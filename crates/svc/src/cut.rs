//! "여기서부터 끊기" 계획 (A19, 이야기형 6판 5-5장). 그래프에서 대상을 뽑아 정책 YAML 을 만든다.
//!
//! - 대상: 사건 뿌리(파일 또는 프로세스)로 실행된 프로세스 + 자손 (graph::views::cut_targets).
//! - 시스템 프로세스(svchost·explorer…)는 차단·종료하지 않는다. 대상이 코드를 **주입한** 정상 프로그램도 경로째 막지 않는다
//!   (16차 Q1-c). 대신 시스템·주입당한 프로그램·대상 프로세스가 접속한 곳을 **(IP, 포트, 프로토콜)** 단위로 같은 판에
//!   24시간 주소 차단으로 넣는다(16차 Q2 정정: IP 통째 차단은 CDN 의 다른 서비스까지 끊는다). 대상 프로세스의 접속지까지
//!   막는 까닭: 종료 직전 다른 프로세스로 옮겨 가도(주입 탈출) 같은 곳에는 못 닿게.
//! - 본 정책은 `process:` 명시 목록 + `source: cut`(서비스가 붙임). `descendants_of` 를 쓰지 않는 이유:
//!   그래프에 사건 당시 해시가 없어, 끊는 순간 계산한 해시는 "그 파일이 그때 그 파일"임을 증명하지 못한다.
//!   새 자손은 엔진의 열린 조건(source=cut)이 보충한다.
//! - (A20) 뿌리 파일은 출신 기록의 첫 해시와 지금 해시를 대조해 보여 준다(match|changed|missing|unrecorded).
//!   차단은 경로 기준이라 결과와 상관없이 하고, 격리(2단계)는 match 일 때만 허용할 재료다.
//! - 경로·이름은 외부 문자열 → YAML 은 직렬화기로 만든다(`dsl::emit_yaml`). 정책 이름은 영숫자·`.-_` 만.

use graph::views::{self, CutTargets};
use graph::Store;

pub const MAX_TARGETS: usize = 500;
/// 끊기 때 뿌리 파일을 다시 해시하는 상한. 엔진 스레드에서 읽으므로 작게 둔다(큰 파일로 엔진을 붙잡는 것 방지)
pub const CUT_HASH_MAX: u64 = 64 * 1024 * 1024;

/// 뿌리 파일의 "그때 그 파일인가" (A20)
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RootHash {
    /// 출신 기록 시점의 해시
    pub recorded: Option<String>,
    pub recorded_ft: Option<i64>,
    pub current: Option<String>,
    /// match | changed | missing | unrecorded | too_large | no_root
    pub status: String,
}

pub fn root_hash(graph: &Store, root_image: Option<&str>) -> RootHash {
    let Some(path) = root_image else {
        return RootHash {
            recorded: None,
            recorded_ft: None,
            current: None,
            status: "no_root".into(),
        };
    };
    let rec = views::recorded_sha256(graph, path).ok().flatten();
    let size = std::fs::metadata(path).map(|m| m.len()).ok();
    let (current, missing_or_big) = match size {
        None => (None, Some("missing")),
        Some(n) if n > CUT_HASH_MAX => (None, Some("too_large")),
        Some(_) => match graph::hash::sha256_file(path) {
            graph::hash::HashOutcome::Ok { sha256, .. } => (Some(sha256), None),
            graph::hash::HashOutcome::TooLarge { .. } => (None, Some("too_large")),
            graph::hash::HashOutcome::Unreadable(_) => (None, Some("missing")),
        },
    };
    let status = match (&rec, &current, missing_or_big) {
        (_, _, Some(s)) => s.to_string(),
        (None, _, None) => "unrecorded".into(),
        (Some((r, _)), Some(c), None) if r == c => "match".into(),
        (Some(_), Some(_), None) => "changed".into(),
        _ => "unrecorded".into(),
    };
    RootHash {
        recorded: rec.as_ref().map(|r| r.0.clone()),
        recorded_ft: rec.map(|r| r.1),
        current,
        status,
    }
}
pub const ADDR_BLOCK_EXPIRES: &str = "24h";

#[derive(Debug, Clone, serde::Serialize)]
pub struct CutPlan {
    pub root: i64,
    pub root_label: String,
    pub policy_name: String,
    pub yaml: String,
    /// 경로 차단 대상 (시스템·주입당한 프로그램 제외)
    pub block_images: Vec<String>,
    pub terminate: Vec<views::CutProc>,
    pub excluded_system: Vec<views::CutProc>,
    /// 대상이 코드를 주입한 프로그램(예: 브라우저). 경로를 통째로 막지 않고 접속지만 막는다. 끝내기는 `terminate_injected` 일 때만
    pub injected_hosts: Vec<views::CutProc>,
    pub system_addresses: Vec<(String, u16)>,
    /// 같은 판에 24시간 주소 차단으로 넣을 접속지 (IP·포트·프로토콜) — 16차 Q2 정정, 14~17차 답변 공격 #2
    pub addresses: Vec<views::CutAddress>,
    pub autoruns: Vec<(String, String)>,
    pub written_executables: Vec<String>,
    pub root_hash: RootHash,
    pub warnings: Vec<String>,
}

/// 정책 이름에 쓸 수 있는 문자만 남긴다 (외부 파일명 → 이름)
pub fn safe_name(s: &str) -> String {
    let t: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(40)
        .collect();
    if t.is_empty() {
        "root".into()
    } else {
        t
    }
}

/// 경로에 제어 문자가 있으면 거부 (ETW 이미지 경로에 들어올 수 없지만, 들어오면 위장 시도로 본다)
fn path_ok(p: &str) -> bool {
    !p.is_empty() && !p.chars().any(|c| c.is_control())
}

pub fn plan(graph: &Store, root: i64, also: &[String]) -> Result<CutPlan, String> {
    let t: CutTargets = views::cut_targets(graph, root, MAX_TARGETS).map_err(|e| e.to_string())?;
    let mut warnings = Vec::new();
    if t.root_kind != "file" && t.root_kind != "process" {
        return Err(format!(
            "끊기 뿌리는 파일 또는 프로세스여야 합니다 (받은 것: {})",
            t.root_kind
        ));
    }
    let mut images: Vec<String> = Vec::new();
    let mut push = |img: &str, warnings: &mut Vec<String>| {
        if !path_ok(img) {
            warnings.push("제어 문자가 든 경로를 대상에서 뺐습니다 (표시 위장 의심)".into());
            return;
        }
        if views::is_system_image(img) {
            return;
        }
        let l = img.to_ascii_lowercase();
        if !images.iter().any(|x| x.to_ascii_lowercase() == l) {
            images.push(img.to_string());
        }
    };
    if let Some(r) = &t.root_image {
        push(r, &mut warnings);
    }
    for p in t.procs.iter().filter(|p| !p.injected_host) {
        push(&p.image, &mut warnings);
    }
    let sys: Vec<views::CutProc> = t
        .procs
        .iter()
        .filter(|p| p.system && !p.injected_host)
        .cloned()
        .collect();
    let injected: Vec<views::CutProc> = t
        .procs
        .iter()
        .filter(|p| p.injected_host)
        .cloned()
        .collect();
    let nonsys: Vec<views::CutProc> = t
        .procs
        .iter()
        .filter(|p| !p.system && !p.injected_host)
        .cloned()
        .collect();
    if t.procs.len() >= MAX_TARGETS {
        warnings.push(format!("대상이 {MAX_TARGETS}개를 넘어 잘랐습니다"));
    }
    if !sys.is_empty() {
        warnings.push(format!("시스템 프로세스 {}개는 막거나 종료하지 않고, 접속한 곳만 {ADDR_BLOCK_EXPIRES} 동안 막습니다. 재부팅을 권고합니다", sys.len()));
    }
    if !injected.is_empty() {
        warnings.push(format!("이 사건이 코드를 주입한 정상 프로그램 {}개({})는 통째로 막지 않고, 그 프로그램이 접속한 곳만 막습니다. 주입된 코드는 그 프로그램을 끝내야 사라집니다", injected.len(), injected.iter().map(|p| p.image.rsplit(['\\', '/']).next().unwrap_or(&p.image).to_string()).collect::<Vec<_>>().join(", ")));
    }
    let name = format!("cut-{}-{}", safe_name(&t.root_label), root);
    let mut also_list: Vec<&str> = Vec::new();
    if also.iter().any(|a| a == "terminate") {
        also_list.push("terminate");
    }
    let addresses = t.addresses.clone();
    let yaml = if !images.is_empty() {
        let mut pol = serde_json::json!({
            "name": name, "action": "block",
            "match": { "direction": "both", "process": images },
        });
        if !also_list.is_empty() {
            pol["also"] = serde_json::json!(also_list);
        }
        dsl::emit_yaml(&serde_json::json!([pol]))
    } else if let Some(a) = addresses.first() {
        // 막을 경로가 없고(시스템·주입당한 프로그램뿐) 주소만 있으면: 첫 주소를 정밀 조건(IP·포트·프로토콜)으로 쓴 정책,
        // 나머지는 같은 판의 주소 차단으로. IP 통째 조건은 쓰지 않는다.
        let pol = serde_json::json!([{ "name": name, "action": "block", "match": { "direction": "out", "remote_ip": [a.ip], "remote_port": [a.port], "protocol": if a.proto == 17 { "udp" } else { "tcp" } }, "expires": ADDR_BLOCK_EXPIRES }]);
        dsl::emit_yaml(&pol)
    } else {
        String::new()
    };
    if also
        .iter()
        .any(|a| a == "quarantine" || a == "remove_autorun")
    {
        warnings.push(
            "격리·자리잡기 제거는 1차에서 목록만 보여 줍니다 (실기기 단계에서 백업과 함께 구현)"
                .into(),
        );
    }
    let rh = root_hash(graph, t.root_image.as_deref());
    match rh.status.as_str() {
        "changed" => warnings.push("뿌리 파일의 내용이 사건 당시(처음 본 때)와 다릅니다. 같은 경로에 다른 파일이 놓였을 수 있습니다 — 경로 차단은 그대로 하지만, 격리 전에 확인이 필요합니다".into()),
        "missing" => warnings.push("뿌리 파일이 이미 없습니다(삭제·이동). 경로 차단과 실행 중인 프로세스 종료는 그대로 합니다".into()),
        "unrecorded" => warnings.push("뿌리 파일의 사건 당시 해시가 없습니다(서명된 파일이거나 기록 전). 같은 파일인지 확인할 수 없습니다".into()),
        _ => {}
    }
    let mut terminate: Vec<views::CutProc> = if also.iter().any(|a| a == "terminate") {
        nonsys
            .iter()
            .filter(|p| !p.ended && p.pid != 0)
            .cloned()
            .collect()
    } else {
        vec![]
    };
    if also.iter().any(|a| a == "terminate_injected") {
        terminate.extend(
            injected
                .iter()
                .filter(|p| !p.ended && p.pid != 0 && !p.system)
                .cloned(),
        );
    }
    Ok(CutPlan {
        root,
        root_label: t.root_label.clone(),
        policy_name: name,
        yaml,
        block_images: images,
        terminate,
        excluded_system: sys,
        injected_hosts: injected,
        addresses,
        system_addresses: t.system_addresses.clone(),
        autoruns: t.autoruns.clone(),
        written_executables: t.written_executables.clone(),
        root_hash: rh,
        warnings,
    })
}
