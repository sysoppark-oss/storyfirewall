//! 점수: 장 기본점(사다리) + 가중치(눈금). 8차 의뢰서 4장, 8차 답변 반영.
//!
//! 모든 항목은 근거 선 id(또는 뿌리 노드 id)를 가진다. 언어 모델 없음.

use std::collections::HashSet;

use graph::store::Store;

use crate::baseline::{self, Baseline};
use crate::rules::{
    self, attr_str, is_pe, proc_image_name, sig_of, zone_is_internet, Chain, Chapter, RootKind,
    Sig, LOLBINS,
};
use crate::{Result, View};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Level {
    /// 0~39: 하루 요약에 접힘
    Normal,
    /// 40~69: 오늘의 이야기에 펼침, 알림 없음
    Watch,
    /// 70~: 알림 + 규칙 제안
    Suspicious,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Reason {
    pub points: i32,
    pub what: &'static str,
    /// 근거 선 id (없으면 뿌리 노드)
    pub edge_id: Option<i64>,
    pub node_id: Option<i64>,
}

pub struct Scored {
    pub score: u8,
    pub level: Level,
    pub reasons: Vec<Reason>,
}

/// 가중치 표 — 점수의 단일 출처 (제안 4). 문서의 점수표는 `docs/judge-score-table.md` 로 생성·대조한다.
pub const WEIGHTS: &[(&str, i32)] = &[
    ("서명 없음", 15),
    ("서명 깨짐·신뢰할 수 없음", 25),
    ("신뢰 체인 없는 서명", 10),
    ("Microsoft 서명(카탈로그)", -40),
    // L054: 신뢰하는 회사 서명은 점수 0 — 카드에 서명 줄이 빠지지 않게 사실만 남긴다(할인 여부는 VM 측정 뒤)
    ("신뢰하는 서명(Microsoft 아님)", 0),
    // L054: 서명 확인 결과가 아직 없음(확인 전·실패) — 점수 0, "서명 없음"과 구분해 보인다
    ("서명 확인 결과 없음", 0),
    ("스토어 패키지", -40),
    ("실행 파일이 아닌 뿌리(문서·스크립트·컨테이너)", 15),
    ("인터넷에서 받은 파일(Zone 3·4)", 10),
    ("사용자 쓰기 가능 경로에서 실행", 10),
    (
        "고립 svchost(귀속 없는 접속, 알려진 Microsoft 서비스 없음)",
        30,
    ),
    ("자손에 LOLBin(스크립트·시스템 도구)", 15),
    ("자리잡기 대상이 서명 없는 파일", 10),
    // L052: Program Files 의 서명 없는 설치 프로그램(인터넷에서 받은 표시 없음) — 외부 접속만으로는 "주의"(70+15-20=65)
    ("관리자만 쓰는 설치 위치의 서명 없는 프로그램", -20),
    ("도메인 없이 IP 로 직접 접속", 10),
    ("평소 접속하던 곳", -10),
    ("이 프로그램이 처음 접속한 곳", 10),
    ("평소 없던 포트", 5),
    ("이 PC 에서 처음 보는 곳", 10),
    ("문서 처리기가 LOLBin 을 실행", 15),
    ("복구 수단을 지우는 명령(T1490)", 10),
    // 17판 23-2 ② 브라우저 금고 경비. 뿌리 (사)는 2장 기본점 30 에서 시작하고 Microsoft 서명 감점(−40)을 받지 않는다.
    // 금고 열기 단독 = 30+15 = 45 주의(설치 폴더의 서명 없는 프로그램이면 30+15−20+15 = 40), 외부 접속까지 = 70+15 이상 의심
    ("브라우저가 아닌 프로그램이 브라우저 저장소를 엶", 15),
    // 미끼 단독 = 30+45 = 75 의심(설치 폴더의 서명 없는 프로그램이어도 30+15−20+45 = 70). 스토어 패키지 감점(−40)을 받으면 주의로 내려간다
    ("미끼 파일 접근", 45),
    ("디버깅 모드로 브라우저 실행", 15),
    ("브라우저 디버깅 포트 접속", 15),
    (
        "브라우저가 아닌 프로그램이 브라우저 권한 상승 서비스를 실행",
        15,
    ),
    // 보조 근거(이것만으로 사건을 만들지 않는다)
    ("브라우저 종료 직후 권한 상승 서비스 시작", 10),
];
pub const BASE_POINTS: &[(Chapter, i32)] = &[
    (Chapter::Ingress, 10),
    (Chapter::Execute, 30),
    (Chapter::Persist, 55),
    (Chapter::Egress, 70),
    // 10판 5-9 (1): 신호가 분명해 이 장만으로 의심(알림). 자동 대응은 없다(원칙 22)
    (Chapter::Destroy, 70),
];
pub const LEVEL_BOUNDS: (u8, u8) = (40, 70);

fn w(what: &str) -> i32 {
    WEIGHTS
        .iter()
        .find(|(n, _)| *n == what)
        .map(|(_, p)| *p)
        .unwrap_or_else(|| panic!("가중치 표에 없음: {what}"))
}

/// 문서용 점수표 (markdown)
pub fn score_table_markdown() -> String {
    let mut out = String::from("# judge 점수표 (코드에서 생성 — 수정 금지)\n\n장 기본점: ");
    out.push_str(
        &BASE_POINTS
            .iter()
            .map(|(c, p)| format!("{c:?} {p}"))
            .collect::<Vec<_>>()
            .join(" · "),
    );
    out.push_str(&format!(
        "\n\n등급: 0~{} 평범 · {}~{} 주의 · {}~ 의심\n\n| 항목 | 점 |\n| --- | --- |\n",
        LEVEL_BOUNDS.0 - 1,
        LEVEL_BOUNDS.0,
        LEVEL_BOUNDS.1 - 1,
        LEVEL_BOUNDS.1
    ));
    for (n, p) in WEIGHTS {
        out.push_str(&format!("| {n} | {p:+} |\n"));
    }
    out
}

pub fn base_points(c: Chapter) -> i32 {
    BASE_POINTS
        .iter()
        .find(|(x, _)| *x == c)
        .map(|(_, p)| *p)
        .unwrap()
}

const USER_WRITABLE: &[&str] = &[
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\appdata\\local\\temp\\",
    "\\public\\",
    "\\programdata\\",
    "\\users\\",
];

/// 사용자 쓰기 가능 위치로 보이는가 (경로 이름 기준 근사). Program Files 아래는 이름에 tmp·temp 가 있어도 관리자만 쓰는
/// 위치라 제외한다(노트북 L020: 실행기 임시 폴더 %ProgramFiles%\StoryFirewallDev\tmp 를 "누구나 쓸 수 있는 위치"로 말함).
/// 정확한 판정은 ACL 이지만 판정 시점에 파일 ACL 을 읽지 않으므로 경로로 근사한다(추측 위험: 관리자가 ACL 을 푼 Program Files 하위)
/// 관리자만 쓰는 설치 위치(Program Files·Program Files (x86), 드라이브 문자 무관)
pub fn admin_install_path(path: &str) -> bool {
    let lower = path.replace('/', "\\").to_ascii_lowercase();
    let rest = lower.get(2..).unwrap_or("");
    rest.starts_with("\\program files\\") || rest.starts_with("\\program files (x86)\\")
}

pub fn user_writable_path(path: &str) -> bool {
    let lower = path.replace('/', "\\").to_ascii_lowercase();
    // "c:\program files\", "c:\program files (x86)\" (드라이브 문자 무관)
    let rest = lower.get(2..).unwrap_or("");
    if rest.starts_with("\\program files\\") || rest.starts_with("\\program files (x86)\\") {
        return false;
    }
    USER_WRITABLE.iter().any(|d| lower.contains(d))
}

pub fn level_of(score: u8) -> Level {
    if score < LEVEL_BOUNDS.0 {
        Level::Normal
    } else if score < LEVEL_BOUNDS.1 {
        Level::Watch
    } else {
        Level::Suspicious
    }
}

pub fn score(
    v: &View,
    chain: &Chain,
    kind: RootKind,
    bl: &Baseline,
    store: &Store,
    pc_domains: &HashSet<String>,
    feedback: &HashSet<String>,
) -> Result<Scored> {
    let mut reasons: Vec<Reason> = Vec::new();
    let mut add = |points: i32, what: &'static str, edge_id: Option<i64>, node_id: Option<i64>| {
        reasons.push(Reason {
            points,
            what,
            edge_id,
            node_id,
        });
    };
    let root_id = chain
        .files
        .first()
        .copied()
        .or_else(|| chain.procs.first().copied());
    add(base_points(chain.chapter), "장 기본점", None, root_id);

    // "정상" 피드백(프로세스 뿌리): 부모→도구→띄운 프로그램 조합 키(ChainUnit). 조합이 바뀌면 키가 달라 다시 의심한다
    if matches!(
        kind,
        RootKind::IsolatedSvchost | RootKind::LolbinFromDocApp | RootKind::RecoveryInhibit
    ) {
        if let Some(root) = chain.procs.first().copied() {
            if let Some(u) = v.chain_unit(root) {
                if feedback.contains(&u.key()) {
                    return Ok(Scored {
                        score: 0,
                        level: Level::Normal,
                        reasons: vec![Reason {
                            points: 0,
                            what: "사용자가 정상으로 확인한 실행 조합",
                            edge_id: None,
                            node_id: Some(root),
                        }],
                    });
                }
            }
        }
    }

    // ---- 뿌리 파일 성질 (PE 서명·출신·경로) ----
    let root_file = chain.files.first().map(|id| v.node(*id));
    let mut root_unsigned = false;
    if let Some(f) = root_file {
        // "정상" 피드백: 사건 종료. 금고 경비 사건은 그 사건 전용 키도 본다(L063)
        if feedback.contains(&baseline::root_key(f))
            || (kind == RootKind::VaultAccess && feedback.contains(&baseline::vault_key(f)))
        {
            return Ok(Scored {
                score: 0,
                level: Level::Normal,
                reasons: vec![Reason {
                    points: 0,
                    what: "사용자가 정상으로 확인한 프로그램",
                    edge_id: None,
                    node_id: Some(f.id),
                }],
            });
        }
        if is_pe(&f.key) {
            match sig_of(f) {
                Some(Sig::None_) => {
                    root_unsigned = true;
                    add(w("서명 없음"), "서명 없음", None, Some(f.id));
                    if baseline::admin_installed_unsigned(f) {
                        add(
                            w("관리자만 쓰는 설치 위치의 서명 없는 프로그램"),
                            "관리자만 쓰는 설치 위치의 서명 없는 프로그램",
                            None,
                            Some(f.id),
                        );
                    }
                }
                Some(Sig::Broken) => {
                    root_unsigned = true;
                    add(
                        w("서명 깨짐·신뢰할 수 없음"),
                        "서명 깨짐·신뢰할 수 없음",
                        None,
                        Some(f.id),
                    );
                }
                Some(Sig::Untrusted) => {
                    root_unsigned = true;
                    add(
                        w("신뢰 체인 없는 서명"),
                        "신뢰 체인 없는 서명",
                        None,
                        Some(f.id),
                    );
                }
                Some(Sig::Microsoft)
                    if !matches!(
                        kind,
                        RootKind::IsolatedSvchost
                            | RootKind::LolbinFromDocApp
                            | RootKind::RecoveryInhibit
                            | RootKind::VaultAccess
                    ) =>
                {
                    add(
                        w("Microsoft 서명(카탈로그)"),
                        "Microsoft 서명(카탈로그)",
                        None,
                        Some(f.id),
                    )
                }
                Some(Sig::Valid) if attr_str(f, "store_package").is_some() => {
                    add(w("스토어 패키지"), "스토어 패키지", None, Some(f.id))
                }
                // D035-4: 패키지 앱(파일 서명 확인 미지원) — "서명 없음"으로 세지 않는다
                Some(Sig::Package) => add(w("스토어 패키지"), "스토어 패키지", None, Some(f.id)),
                Some(Sig::Valid) => add(
                    w("신뢰하는 서명(Microsoft 아님)"),
                    "신뢰하는 서명(Microsoft 아님)",
                    None,
                    Some(f.id),
                ),
                None => add(
                    w("서명 확인 결과 없음"),
                    "서명 확인 결과 없음",
                    None,
                    Some(f.id),
                ),
                _ => {}
            }
        } else {
            root_unsigned = true;
            add(
                w("실행 파일이 아닌 뿌리(문서·스크립트·컨테이너)"),
                "실행 파일이 아닌 뿌리(문서·스크립트·컨테이너)",
                None,
                Some(f.id),
            );
        }
        if zone_is_internet(f) {
            add(
                w("인터넷에서 받은 파일(Zone 3·4)"),
                "인터넷에서 받은 파일(Zone 3·4)",
                None,
                Some(f.id),
            );
        }
        if user_writable_path(&f.key) && is_pe(&f.key) {
            add(
                w("사용자 쓰기 가능 경로에서 실행"),
                "사용자 쓰기 가능 경로에서 실행",
                None,
                Some(f.id),
            );
        }
    }
    if kind == RootKind::IsolatedSvchost {
        add(
            w("고립 svchost(귀속 없는 접속, 알려진 Microsoft 서비스 없음)"),
            "고립 svchost(귀속 없는 접속, 알려진 Microsoft 서비스 없음)",
            None,
            chain.procs.first().copied(),
        );
    }

    // ---- 사슬 성질 ----
    let mut lolbin_added = false;
    let mut persist_unsigned_added = false;
    let mut first_seen_added = false;
    let mut ip_direct_added = false;
    let mut known_added = false;
    let mut new_port_added = false;
    let mut t1490_added = false;
    for (eid, ch) in &chain.edges {
        let e = v.edge(*eid).expect("edge in view");
        let dst = v.node(e.dst);
        match e.rel.as_str() {
            "spawned" => {
                let name = proc_image_name(dst);
                if LOLBINS.contains(&name.as_str())
                    && !lolbin_added
                    && !(kind == RootKind::LolbinFromDocApp && chain.procs.first() == Some(&e.dst))
                {
                    lolbin_added = true;
                    add(
                        w("자손에 LOLBin(스크립트·시스템 도구)"),
                        "자손에 LOLBin(스크립트·시스템 도구)",
                        Some(e.id),
                        None,
                    );
                }
                if kind == RootKind::LolbinFromDocApp
                    && !lolbin_added
                    && chain.procs.first() == Some(&e.src)
                {
                    // 뿌리 자체가 LOLBin: 문서 처리기 → LOLBin 쌍이 신호
                }
            }
            "ran" if *ch == Some(Chapter::Destroy) => {
                if !t1490_added {
                    t1490_added = true;
                    add(
                        w("복구 수단을 지우는 명령(T1490)"),
                        "복구 수단을 지우는 명령(T1490)",
                        Some(e.id),
                        Some(e.dst),
                    );
                }
            }
            "registered" => {
                if root_unsigned && !persist_unsigned_added {
                    persist_unsigned_added = true;
                    add(
                        w("자리잡기 대상이 서명 없는 파일"),
                        "자리잡기 대상이 서명 없는 파일",
                        Some(e.id),
                        None,
                    );
                }
            }
            "connected" | "connected_via" if *ch == Some(Chapter::Egress) => {
                let domain = attr_str(dst, "domain");
                let port = dst.attr("port").and_then(|x| x.as_u64()).unwrap_or(0);
                let actor_file = v.image_file(e.src);
                let pkey = actor_file.and_then(baseline::program_key);
                match (&domain, actor_file) {
                    (None, _) => {
                        if !ip_direct_added {
                            ip_direct_added = true;
                            add(
                                w("도메인 없이 IP 로 직접 접속"),
                                "도메인 없이 IP 로 직접 접속",
                                Some(e.id),
                                None,
                            );
                        }
                    }
                    (Some(d), Some(af))
                        if baseline::learnable(af)
                            && pkey
                                .as_deref()
                                .map_or(false, |k| bl.learned(store, k).unwrap_or(false)) =>
                    {
                        let k = pkey.as_deref().unwrap();
                        let known = bl.has(store, k, "domain", &baseline::etld1(d))?;
                        if known && !known_added {
                            known_added = true;
                            add(w("평소 접속하던 곳"), "평소 접속하던 곳", Some(e.id), None);
                        } else if !known && !first_seen_added {
                            first_seen_added = true;
                            add(
                                w("이 프로그램이 처음 접속한 곳"),
                                "이 프로그램이 처음 접속한 곳",
                                Some(e.id),
                                None,
                            );
                        }
                        if !bl.has(store, k, "port", &port.to_string())? && !new_port_added {
                            new_port_added = true;
                            add(w("평소 없던 포트"), "평소 없던 포트", Some(e.id), None);
                        }
                    }
                    (Some(d), _) => {
                        // 학습 제외 프로그램(서명 없음·Zone 3·4) 또는 미학습: PC 전체 기준
                        if bl.pc_learned(store)?
                            && !pc_domains.contains(&baseline::etld1(d))
                            && !first_seen_added
                        {
                            first_seen_added = true;
                            add(
                                w("이 PC 에서 처음 보는 곳"),
                                "이 PC 에서 처음 보는 곳",
                                Some(e.id),
                                None,
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }
    // ---- (사) 브라우저 금고 경비 (17판 23-2 ②): 신호 종류마다 한 번, 근거 = 첫 신호 선 ----
    let mut vault_seen: HashSet<rules::VaultSignal> = HashSet::new();
    let mut vault_actors: Vec<i64> = Vec::new();
    for (eid, _) in &chain.edges {
        let e = v.edge(*eid).expect("edge in view");
        let Some((sig, actor)) = rules::vault_signal(v, e) else {
            continue;
        };
        vault_actors.push(actor);
        if !vault_seen.insert(sig) {
            continue;
        }
        let what: &'static str = match sig {
            rules::VaultSignal::VaultOpen => "브라우저가 아닌 프로그램이 브라우저 저장소를 엶",
            rules::VaultSignal::DecoyOpen => "미끼 파일 접근",
            rules::VaultSignal::DebugLaunch => "디버깅 모드로 브라우저 실행",
            rules::VaultSignal::DebugPortConnect => "브라우저 디버깅 포트 접속",
            rules::VaultSignal::ElevationByNonBrowser => {
                "브라우저가 아닌 프로그램이 브라우저 권한 상승 서비스를 실행"
            }
        };
        add(w(what), what, Some(e.id), Some(actor));
    }
    // 보조 근거: 금고 신호가 있는 사건에서만(이것만으로는 사건이 되지 않는다)
    if !vault_actors.is_empty() && !vault_seen.contains(&rules::VaultSignal::ElevationByNonBrowser)
    {
        if let Some(eid) = rules::elevation_after_browser_end(v, &vault_actors) {
            let what = "브라우저 종료 직후 권한 상승 서비스 시작";
            add(w(what), what, Some(eid), None);
        }
    }
    if kind == RootKind::LolbinFromDocApp {
        let root_proc = chain.procs.first().copied();
        let spawn_edge =
            root_proc.and_then(|r| v.ins(r).find(|e| e.rel == "spawned").map(|e| e.id));
        add(
            w("문서 처리기가 LOLBin 을 실행"),
            "문서 처리기가 LOLBin 을 실행",
            spawn_edge,
            root_proc,
        );
    }

    let total: i32 = reasons.iter().map(|r| r.points).sum();
    let score = total.clamp(0, 100) as u8;
    Ok(Scored {
        score,
        level: level_of(score),
        reasons,
    })
}

#[allow(dead_code)]
fn _keep(_: &rules::Chain) {}

#[cfg(test)]
mod path_tests {
    use super::user_writable_path;

    #[test]
    fn admin_install_path_only_program_files() {
        use super::admin_install_path;
        assert!(admin_install_path(r"C:\Program Files\Git\usr\bin\sh.exe"));
        assert!(admin_install_path(r"D:\Program Files (x86)\Brother\x.exe"));
        assert!(!admin_install_path(
            r"C:\Users\u\AppData\Local\Programs\Git\usr\bin\sh.exe"
        ));
        assert!(!admin_install_path(r"C:\ProgramData\x.exe"));
        assert!(!admin_install_path(r"C:\Program Files Evil\x.exe"));
    }

    #[test]
    fn program_files_tmp_is_not_user_writable() {
        assert!(!user_writable_path(
            r"C:\Program Files\StoryFirewallDev\tmp\devsetup\story-firewall-dev-setup.exe"
        ));
        assert!(!user_writable_path(
            r"D:\Program Files (x86)\Foo\Temp\x.exe"
        ));
        assert!(user_writable_path(
            r"C:\Users\u\AppData\Local\Temp\payload.exe"
        ));
        assert!(user_writable_path(r"C:\Windows\Temp\a.exe"));
        assert!(user_writable_path(r"C:\Users\u\Downloads\setup.exe"));
        assert!(!user_writable_path(r"C:\Windows\System32\curl.exe"));
    }
}
