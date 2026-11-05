//! 승인 도우미 (A23). 같은 서명 실행 파일을 `--approve <change_id>` 로 UAC 승격해 띄운다. **웹뷰를 만들지 않는다.**
//!
//! 왜: Microsoft 는 WebView2 호스트를 승격(High IL) 프로세스로 돌리지 말고 관리자 작업은 따로 떼라고 권한다(WebView2 보안 문서).
//! UI 는 늘 일반 권한(보기 모드)이고, 변경은 서비스에 맡긴 뒤(change.stage) 이 도우미가 서비스가 계산한 요약을 OS 대화상자로
//! 보여 주고, 사용자가 적용을 누를 때만 실행(change.commit)한다. UI 가 조작돼도 사용자가 보는 것은 실제로 실행될 내용이다.
//!
//! 지키는 것:
//! - 끝점은 파이프 고정(인자로 받지 않는다) — 가짜 TCP 서버로 돌리지 못하게.
//! - 파이프 서버가 session 0(서비스)인지 확인 + SQOS 식별 수준으로 연결 — 같은 이름 파이프를 먼저 만든 일반 권한 악성코드에
//!   승격 토큰을 가장(impersonate)당하지 않게 (client.rs).
//! - 보여 준 요약의 digest 로 실행 — 그사이 바뀌면 서비스가 거부하고, 다시 보여 준다(3번까지).
//! - 60초 확인을 이 창에서 묻는다(예 = 유지, 아니요 = 되돌리기, 답이 없으면 서비스가 기한에 되돌림).
//!
//! - (A24) 적용·유지 단추는 자체 창(approve_win): 앞에 나온 뒤 1.5초 지연, 누르는 순간 덮개 검사.
//!
//! 종료 코드: 0 적용(확인까지) · 1 취소 · 2 오류 · 3 내용이 계속 바뀜 · 4 되돌림 · 5 승격 안 됨 · 6 인자 오류

use std::time::Duration;

use crate::client::Client;

pub const EXIT_OK: i32 = 0;
pub const EXIT_CANCEL: i32 = 1;
pub const EXIT_ERROR: i32 = 2;
pub const EXIT_CHANGED: i32 = 3;
pub const EXIT_ROLLED_BACK: i32 = 4;
pub const EXIT_NOT_ELEVATED: i32 = 5;
pub const EXIT_BAD_ARGS: i32 = 6;

const CAPTION: &str = "Story Firewall - 변경 승인";

pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36 && b.iter().enumerate().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

pub fn new_uuid() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom::getrandom(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// 대화상자·시험 자동 응답
trait Ask {
    /// 적용할까? (확인/취소)
    fn approve(&mut self, text: &str) -> bool;
    /// 유지할까? (예/아니요)
    fn keep(&mut self, text: &str) -> bool;
    fn info(&mut self, text: &str);
}

#[cfg(windows)]
struct Dialogs;
#[cfg(windows)]
impl Dialogs {
    fn show(text: &str, style: u32) -> i32 {
        use windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW;
        let t: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let c: Vec<u16> = CAPTION.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe { MessageBoxW(std::ptr::null_mut(), t.as_ptr(), c.as_ptr(), style) }
    }
}
#[cfg(windows)]
impl Ask for Dialogs {
    // 적용·유지는 자체 창 (A24 클릭재킹 대비: 지연 활성 + 누를 때 덮개 검사). 알림만 MessageBox
    fn approve(&mut self, text: &str) -> bool {
        crate::approve_win::ask(CAPTION, text, "적용", "취소")
    }
    fn keep(&mut self, text: &str) -> bool {
        crate::approve_win::ask(CAPTION, text, "유지", "지금 되돌리기")
    }
    fn info(&mut self, text: &str) {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK, MB_SETFOREGROUND, MB_TOPMOST};
        Self::show(text, MB_OK | MB_ICONINFORMATION | MB_TOPMOST | MB_SETFOREGROUND);
    }
}

/// 시험 빌드(e2e-cdp) 전용 자동 응답: 대화상자 대신 파일에 적고 적용·유지를 고른다
#[cfg(feature = "e2e-cdp")]
struct Auto(std::path::PathBuf);
#[cfg(feature = "e2e-cdp")]
impl Auto {
    fn log(&self, s: &str) {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.0) {
            let _ = writeln!(f, "{s}");
        }
    }
}
#[cfg(feature = "e2e-cdp")]
impl Ask for Auto {
    fn approve(&mut self, text: &str) -> bool {
        self.log(&format!("[approve]\n{text}"));
        true
    }
    fn keep(&mut self, text: &str) -> bool {
        self.log(&format!("[keep]\n{text}"));
        true
    }
    fn info(&mut self, text: &str) {
        self.log(&format!("[info]\n{text}"));
    }
}

/// `args` = 실행 인자 전체. `--approve <id>` 가 있으면 도우미로 돌고 종료 코드를 돌려준다(웹뷰 없음). 없으면 None.
pub fn from_args(args: &[String]) -> Option<i32> {
    // 시험 빌드만: 승인 창 자기 시험 (스크린샷 + 투명 덮개 감지). `--approve-selftest <기록 파일>`
    #[cfg(all(windows, feature = "e2e-cdp"))]
    if let Some(j) = args.iter().position(|a| a == "--approve-selftest") {
        let (log, ok) = crate::approve_win::selftest(4000);
        if let Some(p) = args.get(j + 1) {
            let _ = std::fs::write(p, format!("{}\nok={ok}\n", log.join("\n")));
        }
        return Some(if ok { EXIT_OK } else { EXIT_ERROR });
    }
    let i = args.iter().position(|a| a == "--approve")?;
    let Some(id) = args.get(i + 1).filter(|x| is_uuid(x)) else { return Some(EXIT_BAD_ARGS) };
    // 시험 빌드만: `--e2e-auto <파일>` 이면 대화상자 대신 자동 응답 (배포 빌드에서는 인자를 무시한다)
    #[cfg(feature = "e2e-cdp")]
    if let Some(j) = args.iter().position(|a| a == "--e2e-auto") {
        if let Some(p) = args.get(j + 1) {
            let mut a = Auto(p.into());
            let code = run(id, &mut a);
            #[cfg(windows)]
            {
                use std::sync::atomic::Ordering;
                a.log(&format!("[server] pid={} session={}", crate::client::pipe::SERVER_PID.load(Ordering::SeqCst), crate::client::pipe::SERVER_SESSION.load(Ordering::SeqCst)));
            }
            a.log(&format!("[exit] {code}"));
            return Some(code);
        }
    }
    #[cfg(windows)]
    {
        Some(run(id, &mut Dialogs))
    }
    #[cfg(not(windows))]
    {
        Some(EXIT_ERROR)
    }
}

fn code_of(v: &serde_json::Value) -> Option<i64> {
    v.get("error").and_then(|e| e.get("code")).and_then(|c| c.as_i64())
}
fn msg_of(v: &serde_json::Value) -> String {
    v.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()).unwrap_or("").to_string()
}

fn run(change_id: &str, ask: &mut dyn Ask) -> i32 {
    if !crate::elevate::is_elevated() {
        ask.info("관리자 권한으로 실행되지 않았습니다. 변경은 적용되지 않았습니다.");
        return EXIT_NOT_ELEVATED;
    }
    // 끝점은 파이프 고정. 서버 확인(session 0)은 client 가 연결할 때 한다
    let c = match Client::connect("pipe", Box::new(|_| {})) {
        Ok(c) => c,
        Err(e) => {
            ask.info(&format!("서비스에 연결하지 못했습니다: {e}"));
            return EXIT_ERROR;
        }
    };
    let t = Duration::from_secs(15);
    let hello = c.call("rpc.hello", serde_json::json!({"client_version": env!("CARGO_PKG_VERSION"), "api": [1, 0]}), t);
    if hello.as_ref().map(|v| code_of(v).is_some()).unwrap_or(true) {
        ask.info("서비스 인사(hello)에 실패했습니다.");
        return EXIT_ERROR;
    }
    let mut result = serde_json::Value::Null;
    let mut done = false;
    for round in 0..3 {
        let g = match c.call("change.get", serde_json::json!({"change_id": change_id}), t) {
            Ok(v) => v,
            Err(e) => {
                ask.info(&format!("요약을 받지 못했습니다: {e}"));
                return EXIT_ERROR;
            }
        };
        if code_of(&g).is_some() {
            ask.info(&format!("변경을 찾지 못했습니다(5분이 지나면 만료됩니다): {}", msg_of(&g)));
            return EXIT_ERROR;
        }
        let r = &g["result"];
        let lines: Vec<&str> = r["lines"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
        let digest = r["digest"].as_str().unwrap_or("").to_string();
        let mut text = String::new();
        if round > 0 {
            text.push_str("[내용이 바뀌어 다시 보여 드립니다]\n\n");
        }
        text.push_str("서비스가 계산한 실행 내용입니다. 확인을 누르면 적용합니다.\n\n");
        text.push_str(&lines.join("\n"));
        text.push_str(&format!("\n\n요청한 프로그램: {}", r["staged_by"].as_str().unwrap_or("?")));
        if !ask.approve(&text) {
            return EXIT_CANCEL;
        }
        let v = match c.call("change.commit", serde_json::json!({"request_id": change_id, "change_id": change_id, "digest": digest}), Duration::from_secs(60)) {
            Ok(v) => v,
            Err(e) => {
                ask.info(&format!("적용 요청이 실패했습니다: {e}"));
                return EXIT_ERROR;
            }
        };
        match code_of(&v) {
            None => {
                result = v["result"]["result"].clone();
                done = true;
                break;
            }
            // 보여 준 뒤 내용이 바뀜 → 다시 보여 준다
            Some(-32006) => continue,
            Some(_) => {
                ask.info(&format!("서비스가 거부했습니다: {}", msg_of(&v)));
                return EXIT_ERROR;
            }
        }
    }
    if !done {
        ask.info("내용이 계속 바뀌어 적용하지 않았습니다.");
        return EXIT_CHANGED;
    }
    // 60초 확인: 결과에 든 정책 (policy.apply = 객체 하나, cut.apply = policies 목록)
    let mut pols: Vec<(i64, i64)> = Vec::new();
    let mut push = |x: &serde_json::Value| {
        if let (Some(p), Some(v)) = (x.get("policy_id").and_then(|a| a.as_i64()), x.get("version").and_then(|a| a.as_i64())) {
            pols.push((p, v));
        }
    };
    push(&result);
    for x in result.get("policies").and_then(|a| a.as_array()).into_iter().flatten() {
        push(x);
    }
    if pols.is_empty() {
        return EXIT_OK;
    }
    let list: Vec<String> = pols.iter().map(|(p, v)| format!("정책 #{p} 판 {v}")).collect();
    let keep = ask.keep(&format!(
        "적용했습니다: {}\n\n인터넷·원격 접속 등이 정상인지 확인하세요.\n예 = 유지, 아니요 = 지금 되돌리기\n60초 안에 답하지 않으면 서비스가 자동으로 되돌립니다.",
        list.join(", ")
    ));
    let mut code = EXIT_OK;
    for (p, ver) in pols {
        let (m, params) = if keep {
            ("policy.confirm", serde_json::json!({"request_id": new_uuid(), "policy_id": p, "version": ver}))
        } else {
            ("policy.rollback", serde_json::json!({"request_id": new_uuid(), "policy_id": p}))
        };
        match c.call(m, params, t) {
            Ok(v) if code_of(&v).is_none() => {
                if !keep {
                    code = EXIT_ROLLED_BACK;
                }
            }
            Ok(v) => {
                // 기한이 지나 이미 되돌려졌으면 confirm 이 거부된다
                ask.info(&format!("정책 #{p}: {}", msg_of(&v)));
                code = EXIT_ROLLED_BACK;
            }
            Err(e) => {
                ask.info(&format!("정책 #{p}: {e}"));
                code = EXIT_ERROR;
            }
        }
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uuid_and_args() {
        assert!(is_uuid(&new_uuid()));
        assert_eq!(from_args(&["x".into()]), None);
        assert_eq!(from_args(&["x".into(), "--approve".into(), "nope".into()]), Some(EXIT_BAD_ARGS));
        // 인자에 셸 문자를 끼워 넣어도 UUID 가 아니면 거부
        assert_eq!(from_args(&["x".into(), "--approve".into(), "0f3c2a1e-9b7d-4c6a-8e5f-12345678\" &x".into()]), Some(EXIT_BAD_ARGS));
    }
}
