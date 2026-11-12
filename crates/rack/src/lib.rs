//! 안디옥 첫 연동: 스토리방화벽 화면 → NetX `rack.handoff(diagnose.target)`.
//! 기준: 통합프로젝트 「안디옥 플랫폼 설계와 에피스틀 규격 (0.15판 초안)」 8.1 "첫 연동", 8.3, 6.3, 6.7 (확정 2026-11-12).
//!
//! 여기에는 운영체제 호출이 없다. 등록부에서 읽은 값·파이프로 받은 응답은 모두 **자료**로만 다룬다:
//! 형식을 글자 그대로 검사하고, 맞지 않으면 쓰지 않는다.

use std::net::IpAddr;

/// 이 프로그램의 모듈 id (HKLM\SOFTWARE\Antioch\Modules\<id>)
pub const MODULE_ID: &str = "storyfirewall";
/// 인계 상대
pub const NETX_ID: &str = "netx";
/// Epistle 판 (메이저, 마이너)
pub const API: (u64, u64) = (1, 0);
/// 등록부 경로 (HKLM / HKCU 아래)
pub const MODULES_KEY: &str = r"SOFTWARE\Antioch\Modules";
pub const RUNNING_KEY: &str = r"SOFTWARE\Antioch\Running";

/// 실행 중인 모듈이 공개한 파이프 이름인가 (5.1: `\\.\pipe\<id>-<128비트 hex>`).
/// HKCU 는 일반 권한 프로그램이 고칠 수 있다 — 이 형식이 아니면 접속하지 않는다(다른 장치·경로로 CreateFile 하지 않게).
pub fn valid_pipe_name(id: &str, name: &str) -> bool {
    let Some(rest) = name.strip_prefix(r"\\.\pipe\") else {
        return false;
    };
    let Some(hex) = rest.strip_prefix(id).and_then(|r| r.strip_prefix('-')) else {
        return false;
    };
    hex.len() == 32 && hex.bytes().all(|c| c.is_ascii_hexdigit())
}

/// 경로 비교용 정규화 (8.3 의 5번): `\\?\` 접두사 제거, `/` → `\`, 끝의 `\` 제거, 소문자.
/// 짧은 이름·링크는 호출하는 쪽이 운영체제의 최종 경로로 바꾼 뒤 넘긴다.
pub fn norm_path(p: &str) -> String {
    let p = p.trim();
    let p = p
        .strip_prefix(r"\\?\UNC\")
        .map(|r| format!(r"\\{r}"))
        .unwrap_or_else(|| p.strip_prefix(r"\\?\").unwrap_or(p).to_string());
    let mut s: String = p.replace('/', r"\").to_lowercase();
    while s.len() > 3 && s.ends_with('\\') {
        s.pop();
    }
    s
}

/// 두 경로가 같은 파일을 가리키는 글자열인가 (정규화 뒤 전체 일치)
pub fn same_path(a: &str, b: &str) -> bool {
    let (a, b) = (norm_path(a), norm_path(b));
    !a.is_empty() && a == b
}

/// 드라이브 문자로 시작하는 절대 경로이고 `..` 조각이 없는가
fn plain_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() > 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && b[2] == b'\\'
        && !p.split('\\').any(|seg| seg == ".." || seg == ".")
}

/// 등록된 Exe 가 관리자만 쓸 수 있는 폴더 아래인가 (8.3 의 4번). `roots` = Program Files 들(운영체제가 알려 준 값).
/// 사용자 폴더에 설치된 실행 파일은 같은 사용자 권한의 프로그램이 바꿔치기할 수 있어 권한을 주지 않는다.
pub fn under_admin_root(exe: &str, roots: &[String]) -> bool {
    let e = norm_path(exe);
    if !plain_absolute(&e) {
        return false;
    }
    roots
        .iter()
        .map(|r| norm_path(r))
        .filter(|r| plain_absolute(r))
        .any(|r| e.len() > r.len() + 1 && e.starts_with(&r) && e.as_bytes()[r.len()] == b'\\')
}

/// rack.hello 요청의 params (6.3)
pub fn hello_params(client_version: &str) -> serde_json::Value {
    serde_json::json!({ "client": MODULE_ID, "client_version": client_version, "api": [API.0, API.1] })
}

/// JSON-RPC 응답에서 result 를 꺼낸다. error 면 그 메시지(자료 — 길이를 자르고 제어 문자를 뺀다)
fn result_of(reply: &serde_json::Value) -> Result<&serde_json::Value, String> {
    if let Some(e) = reply.get("error") {
        let code = e.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        let msg: String = e
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_control())
            .take(120)
            .collect();
        return Err(format!("NetX 가 거절했습니다 ({code}) {msg}"));
    }
    reply
        .get("result")
        .ok_or_else(|| "NetX 응답에 result 가 없습니다".to_string())
}

/// rack.hello 응답 검사 (6.3): 상대가 netx 이고, 메이저 판이 같고, 서버 마이너 ≥ 우리 마이너, operate 를 받았는가.
/// operate 가 없으면 NetX 가 우리를 랙 구성원으로 확인하지 못한 것(8.3 의 2번 — 등록부의 ClientExe 와 실행 경로가 다름)
pub fn check_hello(reply: &serde_json::Value) -> Result<(), String> {
    let r = result_of(reply)?;
    if r.get("module").and_then(|m| m.as_str()) != Some(NETX_ID) {
        return Err("상대가 NetX 가 아닙니다".into());
    }
    let api = r
        .get("api")
        .and_then(|a| a.as_array())
        .ok_or("NetX 응답에 api 판이 없습니다")?;
    let (maj, min) = (
        api.first().and_then(|v| v.as_u64()),
        api.get(1).and_then(|v| v.as_u64()),
    );
    if maj != Some(API.0) || min.is_none_or(|m| m < API.1) {
        return Err("NetX 와 연동 규격 판이 맞지 않습니다".into());
    }
    let operate = r
        .get("granted")
        .and_then(|g| g.as_array())
        .is_some_and(|g| g.iter().any(|x| x.as_str() == Some("operate")));
    if !operate {
        return Err("NetX 가 이 프로그램을 확인하지 못했습니다(설치 등록 정보가 다릅니다)".into());
    }
    Ok(())
}

/// rack.handoff(diagnose.target) 의 params (6.7). **보내는 값은 접속지 주소·포트뿐이다** —
/// 이야기 본문, 프로세스 경로, 파일 이름, 도메인, 사건 번호는 싣지 않는다(8.1 첫 연동).
/// `ip` 는 주소로 해석되는 글자열이어야 한다(해석한 값을 다시 글자로 적어 보낸다 — 받은 글자열을 그대로 싣지 않는다).
pub fn handoff_params(
    request_id: &str,
    ip: &str,
    port: Option<u16>,
) -> Result<serde_json::Value, String> {
    let addr: IpAddr = ip
        .trim()
        .parse()
        .map_err(|_| "접속지 주소가 IP 주소가 아닙니다".to_string())?;
    let mut ep = serde_json::json!({ "type": "endpoint", "ip": addr.to_string() });
    if let Some(p) = port.filter(|p| *p != 0) {
        ep["port"] = serde_json::json!(p);
    }
    Ok(
        serde_json::json!({ "request_id": request_id, "intent": "diagnose.target", "from": MODULE_ID, "entities": [ep] }),
    )
}

/// rack.handoff 응답 (6.7): (받았는가, 창을 띄웠는가)
pub fn check_handoff(reply: &serde_json::Value) -> Result<(bool, bool), String> {
    let r = result_of(reply)?;
    let b = |k: &str| r.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    Ok((b("accepted"), b("opened")))
}

/// 128비트 난수 → UUID v4 글자열 (request_id — 멱등 키, 6.1)
pub fn uuid_v4(mut b: [u8; 16]) -> String {
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn 파이프_이름은_형식이_맞을_때만() {
        let ok = r"\\.\pipe\netx-0123456789abcdefABCDEF0123456789";
        assert!(valid_pipe_name("netx", ok));
        // 다른 모듈 이름, 짧은 값, hex 아님, 다른 장치, 경로 끼워 넣기
        assert!(!valid_pipe_name("storyfirewall", ok));
        assert!(!valid_pipe_name("netx", r"\\.\pipe\netx-0123"));
        assert!(!valid_pipe_name(
            "netx",
            r"\\.\pipe\netx-0123456789abcdefABCDEF012345678z"
        ));
        assert!(!valid_pipe_name(
            "netx",
            r"\\evil\pipe\netx-0123456789abcdefABCDEF0123456789"
        ));
        assert!(!valid_pipe_name(
            "netx",
            r"\\.\pipe\..\netx-0123456789abcdefABCDEF0123456789"
        ));
        assert!(!valid_pipe_name(
            "netx",
            r"C:\x\netx-0123456789abcdefABCDEF0123456789"
        ));
        assert!(!valid_pipe_name("netx", ""));
    }

    #[test]
    fn 경로_비교는_대소문자와_접두사를_무시한다() {
        assert!(same_path(
            r"C:\Program Files\NetX\netx.exe",
            r"\\?\c:\program files\netx\NETX.EXE"
        ));
        assert!(same_path(
            r"C:/Program Files/NetX/netx.exe",
            r"C:\Program Files\NetX\netx.exe"
        ));
        assert!(!same_path(
            r"C:\Program Files\NetX\netx.exe",
            r"C:\Program Files\NetX\netx2.exe"
        ));
        assert!(!same_path(
            r"C:\Program Files\NetX\netx.exe",
            r"C:\Users\a\Program Files\NetX\netx.exe"
        ));
        assert!(!same_path("", ""));
    }

    #[test]
    fn 관리자_폴더_아래만_받는다() {
        let roots = vec![
            r"C:\Program Files".to_string(),
            r"C:\Program Files (x86)".to_string(),
        ];
        assert!(under_admin_root(r"C:\Program Files\NetX\netx.exe", &roots));
        assert!(under_admin_root(
            r"\\?\C:\PROGRAM FILES (X86)\NetX\netx.exe",
            &roots
        ));
        // 사용자 폴더, 이름만 비슷한 폴더, 폴더 자체, 위로 올라가기, 상대 경로, UNC
        assert!(!under_admin_root(
            r"C:\Users\a\AppData\Local\NetX\netx.exe",
            &roots
        ));
        assert!(!under_admin_root(r"C:\Program Files Evil\netx.exe", &roots));
        assert!(!under_admin_root(r"C:\Program Files", &roots));
        assert!(!under_admin_root(
            r"C:\Program Files\..\Users\a\netx.exe",
            &roots
        ));
        assert!(!under_admin_root(r"netx.exe", &roots));
        assert!(!under_admin_root(
            r"\\server\share\Program Files\netx.exe",
            &roots
        ));
        assert!(!under_admin_root(r"C:\Program Files\NetX\netx.exe", &[]));
    }

    #[test]
    fn hello_요청은_규격_6_3_모양() {
        assert_eq!(
            hello_params("0.1.6"),
            json!({"client": "storyfirewall", "client_version": "0.1.6", "api": [1, 0]})
        );
    }

    #[test]
    fn hello_응답_검사() {
        let ok = json!({"jsonrpc": "2.0", "id": 1, "result": {"module": "netx", "module_version": "0.2.0", "api": [1, 3], "granted": ["read", "operate"]}});
        assert!(check_hello(&ok).is_ok());
        let mut v = ok.clone();
        v["result"]["module"] = json!("storyfirewall");
        assert!(check_hello(&v).is_err());
        let mut v = ok.clone();
        v["result"]["api"] = json!([2, 0]);
        assert!(check_hello(&v).is_err());
        // operate 를 못 받음 = 등록부 경로 확인 실패(hello 만 됨)
        let mut v = ok.clone();
        v["result"]["granted"] = json!([]);
        assert!(check_hello(&v).unwrap_err().contains("확인하지 못했습니다"));
        // 오류 응답: 메시지는 자료 — 제어 문자를 빼고 자른다
        let e = json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32006, "message": "version\n_mismatch"}});
        let msg = check_hello(&e).unwrap_err();
        assert!(msg.contains("-32006") && !msg.contains('\n'));
        assert!(check_hello(&json!({})).is_err());
    }

    #[test]
    fn 인계에는_주소와_포트만_싣는다() {
        let p = handoff_params(
            "2f0c0000-0000-4000-8000-000000000000",
            " 203.0.113.9 ",
            Some(443),
        )
        .unwrap();
        assert_eq!(
            p,
            json!({"request_id": "2f0c0000-0000-4000-8000-000000000000", "intent": "diagnose.target", "from": "storyfirewall",
            "entities": [{"type": "endpoint", "ip": "203.0.113.9", "port": 443}]})
        );
        // 포트를 모르면 주소만
        let p = handoff_params("x", "2001:db8::1", None).unwrap();
        assert_eq!(
            p["entities"],
            json!([{"type": "endpoint", "ip": "2001:db8::1"}])
        );
        assert_eq!(
            handoff_params("x", "1.2.3.4", Some(0)).unwrap()["entities"][0].get("port"),
            None
        );
        // 주소가 아닌 글자열(도메인, 명령처럼 보이는 것)은 보내지 않는다
        assert!(handoff_params("x", "example.com", Some(443)).is_err());
        assert!(handoff_params("x", "1.2.3.4; rm -rf", Some(443)).is_err());
        // 싣는 열쇠가 넷뿐인지(본문·경로·note 가 끼지 않는지)
        let keys: Vec<&String> = p.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 4);
    }

    #[test]
    fn 인계_응답() {
        assert_eq!(
            check_handoff(&json!({"result": {"accepted": true, "opened": true}})),
            Ok((true, true))
        );
        assert_eq!(
            check_handoff(&json!({"result": {"accepted": true}})),
            Ok((true, false))
        );
        assert!(check_handoff(
            &json!({"error": {"code": -32010, "message": "unsupported_intent"}})
        )
        .is_err());
    }

    #[test]
    fn uuid_모양() {
        let u = uuid_v4([0xff; 16]);
        assert_eq!(u, "ffffffff-ffff-4fff-bfff-ffffffffffff");
        assert_eq!(uuid_v4([0; 16]), "00000000-0000-4000-8000-000000000000");
    }
}
