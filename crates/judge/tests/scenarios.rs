//! A9 통과 기준 (8차 의뢰서 7장 + 8차 답변 Q6 오탐 시나리오)
//! poc3 run-10 시나리오를 정규화 이벤트로 재현해 graph 에 넣고 judge 를 돌린다.

use graph::event::{Direction, Event, EventKind, ProcRef, Proto};
use graph::ingest::Ingester;
use graph::store::Store;
use judge::{Baseline, Chapter, Level, RootKind};

const T0: i64 = 133_800_000_000_000_000; // 임의 FILETIME
const SEC: i64 = 10_000_000;
const DAY: i64 = 24 * 3600 * SEC;

fn ev(ts: i64, source: &str, kind: EventKind) -> Event {
    Event {
        ts,
        source: source.into(),
        kind,
    }
}
fn start(ts: i64, pid: u32, ppid: u32, image: &str) -> Event {
    ev(
        ts,
        "etw:process",
        EventKind::ProcessStart {
            pid,
            ppid,
            image: image.into(),
            create_time: Some(ts),
        },
    )
}
fn snap(ts: i64, pid: u32, ppid: u32, image: &str, services: &[&str]) -> Event {
    ev(
        ts,
        "snapshot",
        EventKind::ProcessSnapshot {
            pid,
            ppid,
            image: image.into(),
            create_time: ts,
            services: services.iter().map(|s| s.to_string()).collect(),
        },
    )
}
fn sig(ts: i64, path: &str, signer: Option<&str>, status: &str, catalog: bool) -> Event {
    ev(
        ts,
        "signature",
        EventKind::Signature {
            path: path.into(),
            signer: signer.map(|s| s.into()),
            issuer: None,
            status: status.into(),
            catalog,
        },
    )
}
fn dns(ts: i64, pid: u32, name: &str, ip: &str) -> Event {
    ev(
        ts,
        "etw:dns",
        EventKind::DnsQuery {
            proc: ProcRef::new(pid, None),
            name: name.into(),
            results: vec![ip.into()],
        },
    )
}
fn conn(ts: i64, pid: u32, ip: &str, port: u16) -> Event {
    ev(
        ts,
        "etw:network",
        EventKind::Connect {
            proc: ProcRef::new(pid, None),
            proto: Proto::Tcp,
            direction: Direction::Out,
            laddr: "10.1.0.4".into(),
            lport: 50000,
            raddr: ip.into(),
            rport: port,
        },
    )
}
fn write(ts: i64, pid: u32, path: &str) -> Event {
    ev(
        ts,
        "etw:file",
        EventKind::FileWrite {
            proc: ProcRef::new(pid, None),
            path: path.into(),
        },
    )
}
fn motw(ts: i64, path: &str, host: &str, zone: u32) -> Event {
    ev(
        ts,
        "motw",
        EventKind::Downloaded {
            path: path.into(),
            host_url: Some(host.into()),
            referrer_url: None,
            zone_id: Some(zone),
        },
    )
}
fn autorun(ts: i64, pid: u32, target: &str) -> Event {
    ev(
        ts,
        "autorun",
        EventKind::AutorunRegistered {
            proc: ProcRef::new(pid, None),
            location: "HKCU\\...\\Run\\Updater".into(),
            target: target.into(),
        },
    )
}

const PWSH: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";
const CURL: &str = r"C:\Windows\System32\curl.exe";
const FIREFOX: &str = r"C:\Program Files\Mozilla Firefox\firefox.exe";
const PAYLOAD: &str = r"C:\Users\runner\AppData\Local\Temp\payload.exe";
const SVCHOST: &str = r"C:\Windows\System32\svchost.exe";
const EXPLORER: &str = r"C:\Windows\explorer.exe";

/// run-10 러너 시나리오: explorer → pwsh → curl(rust-lang.org) / payload.exe(MOTW, 깨진 서명, Run 키, 접속) / firefox
fn runner_scenario(store: &Store) {
    let mut ing = Ingester::new(store);
    let mut t = T0;
    let mut tick = |s: i64| {
        t += s * SEC;
        t
    };
    let evs = vec![
        snap(T0 - 10 * SEC, 4, 0, "System", &[]),
        snap(T0 - 9 * SEC, 800, 4, SVCHOST, &["wuauserv"]),
        snap(T0 - 8 * SEC, 1000, 4, EXPLORER, &[]),
        sig(
            T0 - 7 * SEC,
            SVCHOST,
            Some("Microsoft Windows"),
            "valid",
            true,
        ),
        sig(
            T0 - 7 * SEC,
            EXPLORER,
            Some("Microsoft Windows"),
            "valid",
            true,
        ),
        start(tick(1), 2000, 1000, PWSH),
        sig(tick(0), PWSH, Some("Microsoft Corporation"), "valid", false),
        // curl 사슬 (정상)
        start(tick(1), 2100, 2000, CURL),
        sig(tick(0), CURL, Some("Microsoft Windows"), "valid", true),
        dns(tick(1), 2100, "www.rust-lang.org", "13.227.74.10"),
        conn(tick(1), 2100, "13.227.74.10", 443),
        // payload 사슬 (악성 모의)
        write(
            tick(1),
            2000,
            r"C:\Users\runner\AppData\Local\Temp\payload.tmp",
        ),
        write(tick(1), 2000, PAYLOAD),
        motw(tick(0), PAYLOAD, "https://evil.example/payload.exe", 3),
        sig(tick(1), PAYLOAD, None, "untrusted:bad_digest", false),
        start(tick(1), 2200, 2000, PAYLOAD),
        autorun(tick(1), 2200, PAYLOAD),
        dns(tick(1), 2200, "c2.evil.example", "203.0.113.9"),
        conn(tick(1), 2200, "203.0.113.9", 8443),
        // firefox (정상, 자기 PID)
        start(tick(1), 2300, 1000, FIREFOX),
        sig(
            tick(0),
            FIREFOX,
            Some("Mozilla Corporation"),
            "valid",
            false,
        ),
        dns(tick(1), 2300, "example.com", "93.184.216.34"),
        conn(tick(1), 2300, "93.184.216.34", 443),
        // wuauserv svchost 정상 접속 (귀속 없음이지만 알려진 서비스)
        dns(tick(1), 800, "update.microsoft.com", "20.1.1.1"),
        conn(tick(1), 800, "20.1.1.1", 443),
    ];
    ing.ingest_all(&evs).unwrap();
}

#[test]
fn runner_scenario_only_payload_is_suspicious() {
    let store = Store::open_in_memory().unwrap();
    runner_scenario(&store);
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let sus: Vec<_> = stories
        .iter()
        .filter(|s| s.level.rank() >= Level::Suspicious.rank())
        .collect();
    assert_eq!(sus.len(), 1, "{:#?}", stories);
    let p = sus[0];
    assert_eq!(p.root_label, "payload.exe");
    assert_eq!(p.root_kind, RootKind::IngressFile);
    assert_eq!(p.chapter, Chapter::Egress);
    assert!(p.score >= 90, "score {} reasons {:?}", p.score, p.reasons);
    assert!(!p.ingress_unknown);
    // 근거: 장 기본점·서명 깨짐·Zone 3·Temp 경로·자리잡기 대상 서명 없음
    let whats: Vec<&str> = p.reasons.iter().map(|r| r.what).collect();
    assert!(whats.contains(&"서명 깨짐·신뢰할 수 없음"));
    assert!(whats.contains(&"인터넷에서 받은 파일(Zone 3·4)"));
    assert!(whats.contains(&"사용자 쓰기 가능 경로에서 실행"));
    assert!(whats.contains(&"자리잡기 대상이 서명 없는 파일"));
    // 기준선 미학습: "처음 보는 곳" 가중치는 없어야 한다
    assert!(!whats.iter().any(|w| w.contains("처음")));
    // curl·firefox·svchost(wuauserv) 는 사건이 아니다
    assert!(
        stories
            .iter()
            .all(|s| !["curl.exe", "firefox.exe", "svchost.exe"].contains(&s.root_label.as_str())),
        "{:#?}",
        stories
    );
    // edges.chapter 가 채워졌다: payload 의 접속 선은 4
    let ch: i64 = store
        .conn()
        .query_row(
            "SELECT MAX(chapter) FROM edges WHERE rel = 'connected' AND chapter IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(ch, 4);
    let n_ch: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM edges WHERE chapter IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(n_ch >= 4);
}

#[test]
fn signed_store_app_persisting_is_normal() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let app = r"C:\Program Files\WindowsApps\Vendor.App_1.0\app.exe";
    ing.ingest_all(&[
        snap(T0, 1000, 4, EXPLORER, &[]),
        start(T0 + SEC, 3000, 1000, app),
        sig(T0 + SEC, app, Some("Vendor Inc"), "valid", false),
        autorun(T0 + 2 * SEC, 3000, app),
        dns(T0 + 3 * SEC, 3000, "update.vendor.example", "198.51.100.7"),
        conn(T0 + 4 * SEC, 3000, "198.51.100.7", 443),
    ])
    .unwrap();
    // 스토어 패키지 표식은 수집기가 붙인다 (여기서는 직접)
    let fid = store
        .find_node(graph::NodeKind::File, app)
        .unwrap()
        .unwrap();
    store
        .merge_node_attrs(fid, &serde_json::json!({"store_package": "Vendor.App"}))
        .unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    assert_eq!(stories.len(), 1, "{:#?}", stories);
    let s = &stories[0];
    assert_eq!(s.root_kind, RootKind::SignedPersist);
    assert_eq!(s.chapter, Chapter::Egress);
    assert_eq!(s.score, 30, "{:?}", s.reasons); // 70 − 40
    assert_eq!(s.level, Level::Normal);
}

#[test]
fn unsigned_portable_tool_alerts_once_then_feedback_closes_it() {
    let store = Store::open_in_memory().unwrap();
    let tool = r"C:\Users\pjg\Downloads\rufus-4.5p.exe";
    {
        let mut ing = Ingester::new(&store);
        ing.ingest_all(&[
            snap(T0, 1000, 4, EXPLORER, &[]),
            snap(
                T0,
                1100,
                1000,
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                &[],
            ),
            write(T0 + SEC, 1100, tool),
            motw(T0 + SEC, tool, "https://rufus.ie/", 3),
            sig(T0 + 2 * SEC, tool, None, "nosignature", false),
            start(T0 + 3 * SEC, 4000, 1000, tool),
            write(
                T0 + 4 * SEC,
                4000,
                r"C:\Users\pjg\AppData\Local\Temp\rufus_files\ldlinux.sys",
            ),
            dns(T0 + 5 * SEC, 4000, "rufus.ie", "198.51.100.20"),
            conn(T0 + 6 * SEC, 4000, "198.51.100.20", 443),
        ])
        .unwrap();
    }
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    assert_eq!(stories.len(), 1, "{:#?}", stories);
    let s = &stories[0];
    assert_eq!(s.level, Level::Suspicious, "{:?}", s.reasons); // 70+15+10+10 = 설계상 의심 → 알림 1회
    assert_eq!(s.chapter, Chapter::Egress);
    // 사용자가 "내가 쓰는 도구" 피드백
    let f = store.node(s.root).unwrap();
    bl.mark_normal(&store, &f).unwrap();
    let again = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    assert_eq!(again[0].score, 0);
    assert_eq!(again[0].level, Level::Normal);
}

#[test]
fn word_spawning_powershell_is_a_story_even_though_both_are_signed() {
    let store = Store::open_in_memory().unwrap();
    let word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE";
    let ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let mut ing = Ingester::new(&store);
    ing.ingest_all(&[
        snap(T0, 1000, 4, EXPLORER, &[]),
        start(T0 + SEC, 5000, 1000, word),
        sig(
            T0 + SEC,
            word,
            Some("Microsoft Corporation"),
            "valid",
            false,
        ),
        start(T0 + 2 * SEC, 5100, 5000, ps),
        sig(T0 + 2 * SEC, ps, Some("Microsoft Windows"), "valid", true),
        dns(T0 + 3 * SEC, 5100, "pastebin.example", "203.0.113.50"),
        conn(T0 + 4 * SEC, 5100, "203.0.113.50", 443),
    ])
    .unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let s = stories
        .iter()
        .find(|s| s.root_kind == RootKind::LolbinFromDocApp)
        .expect("(라) 사건");
    assert_eq!(s.root_label, "powershell.exe");
    assert_eq!(s.chapter, Chapter::Egress);
    assert!(s.ingress_unknown);
    assert!(s.score >= 70, "{} {:?}", s.score, s.reasons); // 70 + 15, −40 미적용
    assert_eq!(s.level, Level::Suspicious);
}

#[test]
fn isolated_svchost_is_suspicious_but_known_service_is_not() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    ing.ingest_all(&[
        snap(T0, 4, 0, "System", &[]),
        snap(T0, 800, 4, SVCHOST, &["wuauserv"]),
        snap(T0, 801, 4, SVCHOST, &["EvilUpdateSvc"]),
        sig(T0, SVCHOST, Some("Microsoft Windows"), "valid", true),
        dns(T0 + SEC, 800, "update.microsoft.com", "20.1.1.1"),
        conn(T0 + 2 * SEC, 800, "20.1.1.1", 443),
        dns(T0 + 3 * SEC, 801, "c2.evil.example", "203.0.113.9"),
        conn(T0 + 4 * SEC, 801, "203.0.113.9", 443),
    ])
    .unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    assert_eq!(stories.len(), 1, "{:#?}", stories);
    let s = &stories[0];
    assert_eq!(s.root_kind, RootKind::IsolatedSvchost);
    assert_eq!(s.chapter, Chapter::Egress);
    assert!(
        s.score >= 70 && s.level.rank() >= Level::Suspicious.rank(),
        "{:?}",
        s.reasons
    );
    assert!(
        s.reasons
            .iter()
            .all(|r| r.what != "Microsoft 서명(카탈로그)"),
        "(다) 에는 −40 미적용"
    );
}

#[test]
fn baseline_learns_signed_programs_only_and_flags_first_seen_after_14_days() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    // 1일차: 서명된 앱이 두 곳 접속, 서명 없는 앱이 한 곳 접속
    let app = r"C:\Program Files\Vendor\app.exe";
    let bad = r"C:\Users\pjg\AppData\Local\Temp\bad.exe";
    ing.ingest_all(&[
        snap(T0, 1000, 4, EXPLORER, &[]),
        start(T0 + SEC, 6000, 1000, app),
        sig(T0 + SEC, app, Some("Vendor Inc"), "valid", false),
        dns(T0 + 2 * SEC, 6000, "api.vendor.example", "198.51.100.1"),
        conn(T0 + 3 * SEC, 6000, "198.51.100.1", 443),
        start(T0 + 4 * SEC, 6100, 1000, bad),
        sig(T0 + 4 * SEC, bad, None, "nosignature", false),
        dns(T0 + 5 * SEC, 6100, "c2.evil.example", "203.0.113.9"),
        conn(T0 + 6 * SEC, 6100, "203.0.113.9", 443),
    ])
    .unwrap();
    let bl0 = Baseline::open(&store, T0).unwrap();
    let view = judge::View::load(&store, 0, i64::MAX).unwrap();
    bl0.learn(&store, &view).unwrap();
    // 서명 없는 bad.exe 의 c2 도메인은 학습되지 않았다
    let pc = bl0.pc_domains(&store).unwrap();
    assert!(pc.contains("vendor.example"));
    assert!(!pc.contains("evil.example"), "{pc:?}");
    // 15일 뒤: app 이 새 도메인에 접속 → "처음 접속한 곳"; 기존 도메인은 −10
    let later = T0 + 15 * DAY;
    ing.ingest_all(&[
        start(later, 6200, 1000, app),
        autorun(later + SEC, 6200, app), // 사건이 되도록 (마)
        dns(later + 2 * SEC, 6200, "api.vendor.example", "198.51.100.1"),
        conn(later + 3 * SEC, 6200, "198.51.100.1", 443),
        dns(
            later + 4 * SEC,
            6200,
            "telemetry.other.example",
            "198.51.100.99",
        ),
        conn(later + 5 * SEC, 6200, "198.51.100.99", 8080),
    ])
    .unwrap();
    let bl = Baseline::open(&store, later + SEC).unwrap();
    let stories = judge::run(&store, later - SEC, i64::MAX, &bl).unwrap();
    let s = stories.iter().find(|s| s.root_label == "app.exe").unwrap();
    let whats: Vec<&str> = s.reasons.iter().map(|r| r.what).collect();
    assert!(whats.contains(&"평소 접속하던 곳"), "{whats:?}");
    assert!(whats.contains(&"이 프로그램이 처음 접속한 곳"), "{whats:?}");
    assert!(whats.contains(&"평소 없던 포트"), "{whats:?}");
}

/// 제안 4: 문서 점수표는 코드에서 생성한다. 저장소의 docs/judge-score-table.md 와 다르면 실패 (재생성: JUDGE_WRITE_TABLE=1 cargo test -p judge)
#[test]
fn score_table_doc_matches_code() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/judge-score-table.md"
    );
    let now = judge::score::score_table_markdown();
    if std::env::var("JUDGE_WRITE_TABLE").is_ok() {
        std::fs::write(path, &now).unwrap();
    }
    // Windows 체크아웃(autocrlf)은 CRLF 로 바꾸므로 줄 끝을 정규화해 비교
    let on_disk = std::fs::read_to_string(path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert_eq!(
        on_disk, now,
        "docs/judge-score-table.md 가 코드와 다름 — JUDGE_WRITE_TABLE=1 로 재생성"
    );
}

#[test]
fn svchost_started_after_collection_gets_services_from_scm_poll() {
    // L038(노트북): 필요할 때 켜지는 W32Time 의 svchost 는 수집 시작 뒤 ProcessStart 로 들어와 서비스 목록이 비어 있다.
    // 1초 뒤 SCM 폴링(ServiceMap)이 w32time 을 알려 주는데, 전에는 노드에 반영하지 않아 time.windows.com NTP 접속이 "고립 svchost" 의심이 됐다
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    ing.ingest_all(&[
        snap(T0, 4, 0, "System", &[]),
        snap(T0, 700, 4, r"C:\Windows\System32\services.exe", &[]),
        sig(T0, SVCHOST, Some("Microsoft Windows"), "valid", true),
        start(T0 + 10 * SEC, 900, 700, SVCHOST),
        ev(
            T0 + 11 * SEC,
            "scm",
            EventKind::ServiceMap {
                pid: 900,
                services: vec!["W32Time".into()],
                system_token: Some(false),
                create_time: None,
            },
        ),
        dns(T0 + 12 * SEC, 900, "time.windows.com", "20.2.2.2"),
        conn(T0 + 13 * SEC, 900, "20.2.2.2", 123),
    ])
    .unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    assert!(
        stories
            .iter()
            .all(|s| s.root_kind != RootKind::IsolatedSvchost),
        "W32Time 이 든 svchost 는 고립이 아니다: {:#?}",
        stories
    );
}

/// 구조 개선 B: 조회용 판정(assess)은 run 과 같은 결과를 내되 edges.chapter 를 쓰지 않는다
#[test]
fn assess_matches_run_without_writing() {
    let store = Store::open_in_memory().unwrap();
    runner_scenario(&store);
    let bl = Baseline::open(&store, 0).unwrap();
    let chapters = |s: &Store| -> i64 {
        s.conn()
            .query_row(
                "SELECT COUNT(*) FROM edges WHERE chapter IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(chapters(&store), 0);
    let a = judge::assess(&store, 0, i64::MAX, &bl).unwrap();
    assert_eq!(chapters(&store), 0, "assess 가 DB 에 썼다");
    let r = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    assert!(chapters(&store) > 0);
    let key = |v: &Vec<judge::Story>| {
        v.iter()
            .map(|s| (s.root, s.score, s.chapter as i64, s.edges.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(key(&a), key(&r));
}

/// D035-4(L044 StoreDesktopExtension.exe 의심 오탐): WindowsApps 패키지 파일은 파일 서명이 없다(패키지로 서명) —
/// "서명 없음" 뿌리로 삼지 않는다. 같은 파일이 다른 폴더에 있으면 그대로 서명 없음
#[test]
fn package_app_without_file_signature_is_not_unsigned_root() {
    let run_with = |app: &str| {
        let store = Store::open_in_memory().unwrap();
        let mut ing = Ingester::new(&store);
        ing.ingest_all(&[
            snap(T0, 1000, 4, EXPLORER, &[]),
            start(T0 + SEC, 3000, 1000, app),
            sig(T0 + SEC, app, None, "nosignature", false),
            dns(T0 + 3 * SEC, 3000, "api.example", "198.51.100.7"),
            conn(T0 + 4 * SEC, 3000, "198.51.100.7", 443),
        ])
        .unwrap();
        let bl = Baseline::open(&store, T0 + DAY).unwrap();
        judge::run(&store, 0, i64::MAX, &bl).unwrap()
    };
    let pkg = run_with(
        r"C:\Program Files\WindowsApps\Microsoft.StorePurchaseApp_1.0_x64\StoreDesktopExtension.exe",
    );
    assert!(
        pkg.iter().all(|s| s.root_kind != RootKind::UnsignedProcess),
        "{pkg:#?}"
    );
    let tmp = run_with(r"C:\Users\u\AppData\Local\Temp\StoreDesktopExtension.exe");
    assert!(
        tmp.iter().any(|s| s.root_kind == RootKind::UnsignedProcess),
        "{tmp:#?}"
    );
}

#[test]
fn package_path_only_at_drive_root() {
    use judge::rules::is_package_path;
    assert!(is_package_path(r"C:\Program Files\WindowsApps\A_1.0\a.exe"));
    assert!(is_package_path(
        r"\\?\C:\Program Files\WindowsApps\A_1.0\a.exe"
    ));
    // 28차 Gemini Q1: 다른 드라이브(이동식 매체·ISO)의 같은 이름 폴더는 아님
    assert!(!is_package_path(
        r"D:\Program Files\WindowsApps\A_1.0\a.exe"
    ));
    assert!(!is_package_path(
        r"C:\Users\u\x\Program Files\WindowsApps\a.exe"
    ));
    assert!(!is_package_path(r"C:\Temp\a.exe"));
}

// ---- 이야기형 10판 5-9 (1): 복구 수단 삭제(T1490) ----

fn cmd(ts: i64, pid: u32, line: &str) -> Event {
    ev(
        ts,
        "etw:process",
        EventKind::ProcessCommand {
            proc: ProcRef::new(pid, Some(ts)),
            cmdline: line.into(),
            tool: None,
        },
    )
}
const CMD: &str = r"C:\Windows\System32\cmd.exe";
const VSSADMIN: &str = r"C:\Windows\System32\vssadmin.exe";

#[test]
fn t1490_command_forms() {
    use judge::rules::t1490_kind;
    let yes = [
        (
            r#""C:\Windows\system32\vssadmin.exe" delete shadows /all /quiet"#,
            "그림자 복사본 삭제",
        ),
        (
            "VSSADMIN.EXE Delete Shadows /For=C: /Oldest",
            "그림자 복사본 삭제",
        ),
        (
            "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB",
            "그림자 복사본 저장 공간 변경",
        ),
        (
            "wmic.exe shadowcopy delete /nointeractive",
            "그림자 복사본 삭제",
        ),
        ("wmic SHADOWCOPY DELETE", "그림자 복사본 삭제"),
        ("diskshadow.exe delete shadows all", "그림자 복사본 삭제"),
        ("wbadmin delete catalog -quiet", "백업 기록 삭제"),
        (
            "wbadmin DELETE SYSTEMSTATEBACKUP -keepVersions:0",
            "백업 기록 삭제",
        ),
        (
            "bcdedit /set {default} recoveryenabled No",
            "자동 복구 끄기",
        ),
        (
            "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures",
            "부팅 실패 무시 설정",
        ),
        (
            r"C:\Windows\System32\ReAgentc.exe /disable",
            "복구 환경 끄기",
        ),
        // 29차 Q4: 쉼표·세미콜론 구분, 남은 캐럿, 등호 키값
        ("wmic,shadowcopy,delete", "그림자 복사본 삭제"),
        ("wmic;shadowcopy;delete", "그림자 복사본 삭제"),
        ("vssadmin del^ete shad^ows /all", "그림자 복사본 삭제"),
        (
            "bcdedit /set {default} recoveryenabled=no",
            "자동 복구 끄기",
        ),
    ];
    for (line, want) in yes {
        assert_eq!(t1490_kind(line), Some(want), "{line}");
    }
    // 조회·정상 관리 명령과, 도구 이름이 인자에만 있는 명령은 아니다
    let no = [
        "vssadmin list shadows",
        "vssadmin create shadow /for=C:",
        "wmic shadowcopy list brief",
        "wmic process call create notepad",
        "wbadmin start backup -backupTarget:E:",
        "bcdedit /enum",
        "bcdedit /set {default} recoveryenabled yes",
        "reagentc /info",
        "reagentc /enable",
        "notepad.exe vssadmin delete shadows",
        "cmd.exe /c echo wmic shadowcopy delete",
        "",
    ];
    for line in no {
        assert_eq!(t1490_kind(line), None, "{line}");
    }
}

/// 수집기(collector::cmdline::T1490_TOOLS, Windows 전용이라 여기서 못 부름)가 명령줄을 읽는 도구와 판별 도구가 같아야 한다
#[test]
fn t1490_tools_list_matches_collector() {
    let src = include_str!("../../collector/src/cmdline.rs");
    let line = src
        .lines()
        .find(|l| l.contains("pub const T1490_TOOLS"))
        .expect("T1490_TOOLS");
    let tools: Vec<&str> = line.split('"').skip(1).step_by(2).collect();
    assert_eq!(
        tools,
        [
            "vssadmin.exe",
            "wmic.exe",
            "diskshadow.exe",
            "wbadmin.exe",
            "bcdedit.exe",
            "reagentc.exe"
        ]
    );
    // 각 도구에 판별 규칙이 하나 이상 있다
    let sample = [
        "vssadmin delete shadows",
        "wmic shadowcopy delete",
        "diskshadow delete shadows",
        "wbadmin delete catalog",
        "bcdedit /set recoveryenabled no",
        "reagentc /disable",
    ];
    for (t, s) in tools.iter().zip(sample) {
        assert!(s.starts_with(t.trim_end_matches(".exe")));
        assert!(judge::rules::t1490_kind(s).is_some(), "{t}");
    }
}

#[test]
fn signed_vssadmin_deleting_shadows_is_suspicious_chapter5() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    ing.ingest_all(&[
        snap(T0, 1000, 4, EXPLORER, &[]),
        sig(T0, EXPLORER, Some("Microsoft Windows"), "valid", true),
        start(T0 + SEC, 3000, 1000, CMD),
        sig(T0 + SEC, CMD, Some("Microsoft Windows"), "valid", true),
        start(T0 + 2 * SEC, 3100, 3000, VSSADMIN),
        sig(
            T0 + 2 * SEC,
            VSSADMIN,
            Some("Microsoft Windows"),
            "valid",
            true,
        ),
        cmd(
            T0 + 2 * SEC,
            3100,
            "vssadmin.exe delete shadows /all /quiet",
        ),
        // 같은 도구의 조회 명령은 사건이 아니다
        start(T0 + 3 * SEC, 3200, 3000, VSSADMIN),
        cmd(T0 + 3 * SEC, 3200, "vssadmin list shadows"),
    ])
    .unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let s: Vec<_> = stories
        .iter()
        .filter(|s| s.root_kind == RootKind::RecoveryInhibit)
        .collect();
    assert_eq!(s.len(), 1, "{stories:#?}");
    let s = s[0];
    assert_eq!(s.root_label, "vssadmin.exe");
    assert_eq!(s.chapter, Chapter::Destroy);
    // 개편안 2판 2-2: 5장(파괴 행위)이 높음 점수면 심각
    assert_eq!(s.level, Level::Critical, "{:?}", s.reasons);
    // Microsoft 서명 감점(−40)을 적용하지 않는다: 70 + 10
    assert_eq!(s.score, 80, "{:?}", s.reasons);
    let r = s
        .reasons
        .iter()
        .find(|r| r.what == "복구 수단을 지우는 명령(T1490)")
        .expect("근거 항목");
    let e = store.edge(r.edge_id.unwrap()).unwrap();
    assert_eq!(e.rel, "ran");
    assert_eq!(e.chapter, Some(5));
    assert!(
        !store.evidence_of(e.id).unwrap().is_empty(),
        "근거 원시 이벤트"
    );
    // 3200(list) 은 어떤 사건에도 5장으로 들지 않는다
    assert!(stories
        .iter()
        .all(|x| x.chapter != Chapter::Destroy || x.root == s.root));
}

#[test]
fn unsigned_program_running_vssadmin_is_one_story_reaching_chapter5() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let mal = r"C:\Users\u\AppData\Local\Temp\x.exe";
    ing.ingest_all(&[
        snap(T0, 1000, 4, EXPLORER, &[]),
        start(T0 + SEC, 4000, 1000, mal),
        sig(T0 + SEC, mal, None, "nosignature", false),
        start(T0 + 2 * SEC, 4100, 4000, CMD),
        start(T0 + 3 * SEC, 4200, 4100, VSSADMIN),
        sig(
            T0 + 3 * SEC,
            VSSADMIN,
            Some("Microsoft Windows"),
            "valid",
            true,
        ),
        cmd(
            T0 + 3 * SEC,
            4200,
            r#""C:\Windows\system32\vssadmin.exe" Delete Shadows /All /Quiet"#,
        ),
    ])
    .unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    // 서명 없는 프로그램의 사건 하나가 5장까지 — vssadmin 이 따로 사건이 되지 않는다(같은 사슬)
    assert_eq!(stories.len(), 1, "{stories:#?}");
    let s = &stories[0];
    assert_eq!(s.root_kind, RootKind::UnsignedProcess);
    assert_eq!(s.chapter, Chapter::Destroy);
    assert_eq!(s.level, Level::Critical);
}

/// 10판 구현 중 찾은 결함: 앞 사건의 **선** id 를 모아 두고 다음 뿌리 **노드** id 로 찾아, 번호가 겹치면 사건이 빠졌다
#[test]
fn later_root_is_not_dropped_when_its_node_id_equals_an_earlier_edge_id() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let tool = r"C:\Users\u\Downloads\tool.exe";
    // 노드는 적게, 선은 많이: svchost 노드 번호가 tool 사건의 선 번호 범위 안에 들게(같은 원격지로 여러 번 접속)
    let mut evs = vec![
        snap(T0, 1000, 4, EXPLORER, &[]),
        start(T0 + SEC, 4000, 1000, tool),
        sig(T0 + SEC, tool, None, "nosignature", false),
        snap(T0, 801, 4, SVCHOST, &["EvilUpdateSvc"]),
    ];
    for k in 0..12i64 {
        evs.push(conn(T0 + (3 + k) * SEC, 4000, "203.0.113.20", 443));
    }
    evs.push(conn(T0 + 20 * SEC, 801, "198.51.100.7", 443));
    ing.ingest_all(&evs).unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let svc_node = store
        .find_node(graph::NodeKind::Process, &format!("801@{T0}"))
        .unwrap()
        .expect("svchost 노드");
    let tool_story = stories
        .iter()
        .find(|s| s.root_label == "tool.exe")
        .expect("tool 사건");
    // 시험 전제: 번호 겹침
    assert!(
        tool_story.edges.contains(&svc_node),
        "전제: svchost 노드 {svc_node}, tool 선 {:?}",
        tool_story.edges
    );
    assert!(
        stories
            .iter()
            .any(|s| s.root_kind == RootKind::IsolatedSvchost && s.root == svc_node),
        "{stories:#?}"
    );
}

// ---- L048: SCM 매핑과 시작 이벤트의 순서 ----

fn scm_map(ts: i64, pid: u32, svcs: &[&str], ct: Option<i64>) -> Event {
    ev(
        ts,
        "scm",
        EventKind::ServiceMap {
            pid,
            services: svcs.iter().map(|s| s.to_string()).collect(),
            system_token: Some(true),
            create_time: ct,
        },
    )
}
fn isolated(store: &Store) -> Vec<judge::Story> {
    let bl = Baseline::open(store, T0 + DAY).unwrap();
    judge::run(store, 0, i64::MAX, &bl)
        .unwrap()
        .into_iter()
        .filter(|s| s.root_kind == RootKind::IsolatedSvchost)
        .collect()
}

/// (가) Windows 업데이트 svchost: SCM 폴링이 ETW 시작 이벤트보다 먼저 서비스를 본다 — 전에는 끝까지 "서비스 없음"(오탐)
#[test]
fn scm_map_before_process_start_is_kept_for_that_process() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let t = T0 + 10 * SEC;
    ing.ingest_all(&[
        snap(T0, 700, 4, r"C:\Windows\System32\services.exe", &[]),
        sig(T0, SVCHOST, Some("Microsoft Windows"), "valid", true),
        scm_map(t + SEC / 2, 900, &["wuauserv"], Some(t)),
        start(t, 900, 700, SVCHOST),
        conn(t + 2 * SEC, 900, "20.3.3.3", 443),
    ])
    .unwrap();
    assert!(
        isolated(&store).is_empty(),
        "wuauserv svchost 는 고립이 아니다"
    );
}

/// (나) 같은 PID 를 쓰던 예전 서비스 호스트의 매핑을 새 svchost 가 물려받지 않는다(물려받으면 고립 판정을 피한다)
#[test]
fn new_svchost_does_not_inherit_services_of_old_pid() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let t0 = T0 + 10 * SEC;
    let t1 = T0 + 60 * SEC;
    ing.ingest_all(&[
        snap(T0, 700, 4, r"C:\Windows\System32\services.exe", &[]),
        sig(T0, SVCHOST, Some("Microsoft Windows"), "valid", true),
        start(t0, 900, 700, SVCHOST),
        scm_map(t0 + SEC, 900, &["wuauserv"], Some(t0)),
        ev(
            t0 + 20 * SEC,
            "etw:process",
            EventKind::ProcessStop { pid: 900 },
        ),
        // 사라짐 알림이 늦거나 없어도: 새 프로세스의 생성 시각이 다르면 붙이지 않는다
        start(t1, 900, 700, SVCHOST),
        conn(t1 + SEC, 900, "198.51.100.9", 443),
    ])
    .unwrap();
    let iso = isolated(&store);
    assert_eq!(iso.len(), 1, "새 svchost 는 고립: {iso:#?}");
}

/// (다) 예전 노드의 종료가 아직 안 왔을 때 새 프로세스의 매핑이 먼저 와도 예전 노드에 붙지 않는다
#[test]
fn early_scm_map_does_not_land_on_old_process_with_same_pid() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let t0 = T0 + 10 * SEC;
    let t1 = T0 + 60 * SEC;
    ing.ingest_all(&[
        snap(T0, 700, 4, r"C:\Windows\System32\services.exe", &[]),
        sig(T0, SVCHOST, Some("Microsoft Windows"), "valid", true),
        // 예전 svchost(서비스 없음)가 외부 접속 — 고립 사건
        start(t0, 900, 700, SVCHOST),
        conn(t0 + SEC, 900, "198.51.100.9", 443),
        // 새 svchost(같은 PID)의 매핑이 시작·예전 종료보다 먼저
        scm_map(t1 + SEC / 2, 900, &["wuauserv"], Some(t1)),
        ev(t1 + SEC, "etw:process", EventKind::ProcessStop { pid: 900 }),
        start(t1, 900, 700, SVCHOST),
    ])
    .unwrap();
    let old = store
        .find_node(graph::NodeKind::Process, &format!("900@{t0}"))
        .unwrap()
        .unwrap();
    let new = store
        .find_node(graph::NodeKind::Process, &format!("900@{t1}"))
        .unwrap()
        .unwrap();
    let svcs = |id: i64| {
        store
            .node(id)
            .unwrap()
            .attr("services")
            .and_then(|v| v.as_array().map(|a| a.len()))
            .unwrap_or(0)
    };
    assert_eq!(svcs(old), 0, "예전 노드에 붙지 않음");
    assert_eq!(svcs(new), 1, "새 노드에 붙음");
    assert_eq!(isolated(&store).len(), 1, "예전 고립 사건은 그대로");
}

/// D042-3·L048(sh.exe): 근거가 연결 표뿐인 접속은 4장(외부 접속)을 올리지 않는다 — ETW 실시간 기록이 함께 있으면 올린다
#[test]
fn table_only_connection_does_not_reach_chapter4() {
    let table = |ts: i64, pid: u32, ip: &str| {
        let mut e = conn(ts, pid, ip, 443);
        e.source = "conntable".into();
        e
    };
    let sh = r"C:\Program Files\Git\usr\bin\sh.exe";
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    ing.ingest_all(&[
        snap(T0, 1000, 4, EXPLORER, &[]),
        start(T0 + SEC, 5000, 1000, sh),
        sig(T0 + SEC, sh, None, "nosignature", false),
        table(T0 + 2 * SEC, 5000, "140.82.112.3"),
    ])
    .unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let s = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let s = s
        .iter()
        .find(|x| x.root_label == "sh.exe")
        .expect("sh.exe 사건");
    assert_eq!(s.chapter, Chapter::Execute, "{:?}", s.reasons);
    assert_ne!(s.level, Level::Suspicious);
    // L050: 예전 판이 이 선에 4장을 써 두었어도 지금 판정이 지운다(카드는 DB 의 장을 읽는다)
    store
        .conn()
        .execute("UPDATE edges SET chapter = 4 WHERE rel = 'connected'", [])
        .unwrap();
    judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let stale: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM edges WHERE rel = 'connected' AND chapter IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stale, 0, "연결 표만 근거 접속의 예전 4장이 남음");
    // 같은 접속을 ETW 도 봤으면(같은 선에 근거가 합쳐짐) 4장
    let mut ing = Ingester::new(&store);
    ing.ingest_all(&[conn(T0 + 2 * SEC, 5000, "140.82.112.3", 443)])
        .unwrap();
    let s = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let s = s.iter().find(|x| x.root_label == "sh.exe").unwrap();
    assert_eq!(s.chapter, Chapter::Egress, "ETW 근거가 있는 접속은 4장");
}

/// 29차 Q1: 이름 바꾼 복사본(%TEMP%\x.exe = vssadmin) — 수집기가 OriginalFileName 을 실어 보내면 첫 토큰이 아니라 그 이름으로 판별
#[test]
fn renamed_copy_of_vssadmin_is_judged_by_original_name() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let copy = r"C:\Users\u\AppData\Local\Temp\backup_util.exe";
    let t = T0 + SEC;
    ing.ingest_all(&[
        snap(T0, 1000, 4, EXPLORER, &[]),
        start(t, 3100, 1000, copy),
        sig(t, copy, Some("Microsoft Windows"), "valid", true),
        ev(
            t,
            "etw:kernel-process",
            EventKind::ProcessCommand {
                proc: ProcRef::new(3100, Some(t)),
                cmdline: format!("{copy} delete shadows /all /quiet"),
                tool: Some("vssadmin.exe".into()),
            },
        ),
    ])
    .unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let s = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let s = s
        .iter()
        .find(|x| x.chapter == Chapter::Destroy)
        .unwrap_or_else(|| panic!("5장 사건 없음: {s:#?}"));
    assert_eq!(s.level, Level::Critical);
    // 원래 이름 없이(첫 토큰만)는 판별하지 못한다 — 수집기가 이름을 실어야 하는 이유
    assert_eq!(
        judge::rules::t1490_kind(&format!("{copy} delete shadows /all /quiet")),
        None
    );
}

/// L052(노트북): Program Files 의 서명 없는 설치 프로그램(Git for Windows sh.exe)이 외부 접속만으로 "의심"이 되던 오탐.
/// 관리자만 쓰는 위치 + 인터넷에서 받은 표시 없음 → −20 으로 "주의". 같은 파일이 사용자 폴더에 있으면 그대로 "의심"
#[test]
fn unsigned_program_files_tool_is_watch_but_same_in_user_folder_is_suspicious() {
    for (path, want) in [
        (r"C:\Program Files\Git\usr\bin\sh.exe", Level::Watch),
        (
            r"C:\Users\pjg\AppData\Local\Programs\Git\usr\bin\sh.exe",
            Level::Suspicious,
        ),
    ] {
        let store = Store::open_in_memory().unwrap();
        Ingester::new(&store)
            .ingest_all(&[
                snap(T0, 1000, 4, EXPLORER, &[]),
                start(T0 + SEC, 4100, 1000, path),
                sig(T0 + 2 * SEC, path, None, "nosignature", false),
                dns(T0 + 3 * SEC, 4100, "github.com", "140.82.112.3"),
                conn(T0 + 4 * SEC, 4100, "140.82.112.3", 443),
            ])
            .unwrap();
        let bl = Baseline::open(&store, T0 + DAY).unwrap();
        let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
        let s = stories
            .iter()
            .find(|s| s.root_label == "sh.exe")
            .unwrap_or_else(|| panic!("{path}: {stories:#?}"));
        assert_eq!(s.level, want, "{path}: {:?}", s.reasons);
        let has = s
            .reasons
            .iter()
            .any(|r| r.what == "관리자만 쓰는 설치 위치의 서명 없는 프로그램");
        assert_eq!(has, want == Level::Watch, "{path}");
    }
}

/// 같은 Program Files 위치라도 인터넷에서 받은 표시(Zone 3)가 있으면 감점하지 않는다
#[test]
fn unsigned_program_files_with_motw_gets_no_discount() {
    let store = Store::open_in_memory().unwrap();
    let path = r"C:\Program Files\Tool\tool.exe";
    Ingester::new(&store)
        .ingest_all(&[
            snap(T0, 1000, 4, EXPLORER, &[]),
            start(T0 + SEC, 4200, 1000, path),
            motw(T0 + SEC, path, "https://example.net/tool.exe", 3),
            sig(T0 + 2 * SEC, path, None, "nosignature", false),
            dns(T0 + 3 * SEC, 4200, "example.net", "198.51.100.7"),
            conn(T0 + 4 * SEC, 4200, "198.51.100.7", 443),
        ])
        .unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let s = judge::run(&store, 0, i64::MAX, &bl)
        .unwrap()
        .into_iter()
        .find(|s| s.root_label == "tool.exe")
        .unwrap();
    assert_eq!(s.level, Level::Suspicious, "{:?}", s.reasons);
}

/// 서명 없는 설치 프로그램의 기준선 열쇠는 내용 해시에 묶인다 — 해시가 없으면 배우지 않고, 바뀌면 다른 열쇠
#[test]
fn unsigned_installed_program_key_binds_to_hash() {
    let store = Store::open_in_memory().unwrap();
    let path = r"C:\Program Files\Git\usr\bin\bash.exe";
    let hash = |h: &str| {
        ev(
            T0 + 2 * SEC,
            "hash",
            EventKind::FileHash {
                path: path.into(),
                sha256: Some(h.into()),
                size: 10,
                note: None,
            },
        )
    };
    let mut ing = Ingester::new(&store);
    ing.ingest_all(&[
        snap(T0, 1000, 4, EXPLORER, &[]),
        start(T0 + SEC, 4300, 1000, path),
        sig(T0 + SEC, path, None, "nosignature", false),
    ])
    .unwrap();
    let id = store
        .find_node(graph::NodeKind::File, path)
        .unwrap()
        .unwrap();
    let f = store.node(id).unwrap();
    assert!(judge::baseline::learnable(&f));
    assert_eq!(
        judge::baseline::program_key(&f),
        None,
        "해시 없으면 열쇠 없음(배우지 않음)"
    );
    ing.ingest_all(&[hash("aa11")]).unwrap();
    let k1 = judge::baseline::program_key(&store.node(id).unwrap()).unwrap();
    assert!(k1.ends_with("|unsigned|aa11"), "{k1}");
    ing.ingest_all(&[hash("bb22")]).unwrap();
    let k2 = judge::baseline::program_key(&store.node(id).unwrap()).unwrap();
    assert_ne!(k1, k2);
}

/// 인수인계 2026-11-07 남은 일 2: 프로세스에서 시작한 사건((라))의 "이건 정상입니다"는
/// 부모 → 도구 → 띄운 프로그램 조합에만 — 같은 도구가 다른 프로그램을 띄우면 다시 의심한다
#[test]
fn lolbin_normal_feedback_is_scoped_to_parent_tool_children_combination() {
    let store = Store::open_in_memory().unwrap();
    let word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE";
    let ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let mut ing = Ingester::new(&store);
    ing.ingest_all(&[
        snap(T0, 1000, 4, EXPLORER, &[]),
        start(T0 + SEC, 5000, 1000, word),
        sig(
            T0 + SEC,
            word,
            Some("Microsoft Corporation"),
            "valid",
            false,
        ),
        start(T0 + 2 * SEC, 5100, 5000, ps),
        sig(T0 + 2 * SEC, ps, Some("Microsoft Windows"), "valid", true),
        start(T0 + 3 * SEC, 5200, 5100, CURL),
        sig(T0 + 3 * SEC, CURL, Some("Microsoft Windows"), "valid", true),
        conn(T0 + 4 * SEC, 5200, "203.0.113.50", 443),
    ])
    .unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let find = |ss: &[judge::Story]| {
        ss.iter()
            .find(|s| s.root_kind == RootKind::LolbinFromDocApp)
            .cloned()
            .expect("(라) 사건")
    };
    let s = find(&judge::run(&store, 0, i64::MAX, &bl).unwrap());
    assert_ne!(s.level, Level::Normal);
    // 정상 처리 단위 = winword → powershell → (curl)
    let view = judge::View::load(&store, 0, i64::MAX).unwrap();
    let unit = view.chain_unit(s.root).expect("실행 조합");
    assert_eq!(unit.label(), "winword.exe → powershell.exe → (curl.exe)");
    let key = unit.key();
    assert!(key.starts_with("chain:"), "{key}");
    bl.mark_normal_chain(&store, &key).unwrap();
    let keys = bl.feedback_keys(&store).unwrap();
    let ps_node = store.node(unit.tool.id).unwrap();
    assert!(
        !keys.contains(&judge::baseline::root_key(&ps_node)),
        "powershell 전체를 정상으로 만들지 않는다"
    );
    let s2 = find(&judge::run(&store, 0, i64::MAX, &bl).unwrap());
    assert_eq!(s2.level, Level::Normal, "{:?}", s2.reasons);
    assert_eq!(s2.score, 0);
    // 같은 powershell 이 다른 프로그램(미서명 payload)을 더 띄우면 조합이 달라져 다시 의심
    ing.ingest_all(&[
        start(T0 + 10 * SEC, 5300, 5100, PAYLOAD),
        sig(T0 + 10 * SEC, PAYLOAD, None, "none", false),
    ])
    .unwrap();
    let s3 = find(&judge::run(&store, 0, i64::MAX, &bl).unwrap());
    assert_ne!(s3.level, Level::Normal, "{:?}", s3.reasons);
    let unit3 = judge::View::load(&store, 0, i64::MAX)
        .unwrap()
        .chain_unit(s3.root)
        .unwrap()
        .key();
    assert_ne!(unit3, key);
}

/// (바) 복구 수단 삭제: 정상 조합에는 명령 종류까지 들어간다 — 같은 cmd → vssadmin 이라도 다른 파괴 명령이면 다시 의심
#[test]
fn recovery_inhibit_normal_feedback_includes_command_kind() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    ing.ingest_all(&[
        snap(T0, 1000, 4, EXPLORER, &[]),
        sig(T0, EXPLORER, Some("Microsoft Windows"), "valid", true),
        start(T0 + SEC, 3000, 1000, CMD),
        sig(T0 + SEC, CMD, Some("Microsoft Windows"), "valid", true),
        start(T0 + 2 * SEC, 3100, 3000, VSSADMIN),
        sig(
            T0 + 2 * SEC,
            VSSADMIN,
            Some("Microsoft Windows"),
            "valid",
            true,
        ),
        cmd(
            T0 + 2 * SEC,
            3100,
            "vssadmin.exe delete shadows /all /quiet",
        ),
    ])
    .unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let s = judge::run(&store, 0, i64::MAX, &bl)
        .unwrap()
        .into_iter()
        .find(|s| s.root_kind == RootKind::RecoveryInhibit)
        .expect("(바) 사건");
    let view = judge::View::load(&store, 0, i64::MAX).unwrap();
    let unit = view.chain_unit(s.root).unwrap();
    assert_eq!(
        unit.label(),
        "cmd.exe → vssadmin.exe · 명령: 그림자 복사본 삭제"
    );
    bl.mark_normal_chain(&store, &unit.key()).unwrap();
    let s2 = judge::run(&store, 0, i64::MAX, &bl)
        .unwrap()
        .into_iter()
        .find(|s| s.root_kind == RootKind::RecoveryInhibit)
        .unwrap();
    assert_eq!(s2.level, Level::Normal, "{:?}", s2.reasons);
}

/// 개편안 2판 2-2(42차 Q4): 낮음 사건이라도 같은 접속지로 7일 안에 서로 다른 사건 3건이면 중간으로 올린다 —
/// 경로·이름을 바꿔 가며 다시 뜨는 드로퍼는 출처 축을 피해도 접속지 축에 걸린다
#[test]
fn low_events_sharing_a_remote_are_raised_to_watch_after_three() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let mut evs = vec![snap(T0, 1000, 4, EXPLORER, &[])];
    // 서로 다른 경로·이름의 스토어 앱 세 개(각각 낮음 30점)가 같은 서버에 접속
    for (i, app) in [
        r"C:\Program Files\WindowsApps\V1.App_1.0\a.exe",
        r"C:\Program Files\WindowsApps\V2.App_1.0\b.exe",
        r"C:\Program Files\WindowsApps\V3.App_1.0\c.exe",
    ]
    .iter()
    .enumerate()
    {
        let pid = 3000 + i as u32;
        let t = T0 + (i as i64) * DAY; // 하루 간격(7일 안)
        evs.extend([
            start(t + SEC, pid, 1000, app),
            sig(t + SEC, app, Some("Vendor Inc"), "valid", false),
            autorun(t + 2 * SEC, pid, app),
            dns(t + 3 * SEC, pid, "c2.example", "198.51.100.9"),
            conn(t + 4 * SEC, pid, "198.51.100.9", 443),
        ]);
    }
    ing.ingest_all(&evs).unwrap();
    for app in [r"C:\Program Files\WindowsApps\V1.App_1.0\a.exe", r"C:\Program Files\WindowsApps\V2.App_1.0\b.exe", r"C:\Program Files\WindowsApps\V3.App_1.0\c.exe"] {
        let fid = store.find_node(graph::NodeKind::File, app).unwrap().unwrap();
        store.merge_node_attrs(fid, &serde_json::json!({"store_package": app})).unwrap();
    }
    let bl = Baseline::open(&store, T0 + 3 * DAY).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    assert_eq!(stories.len(), 3, "{:#?}", stories);
    for s in &stories {
        assert_eq!(s.level, Level::Watch, "{:?}", s.reasons);
        assert_eq!(s.score, 40);
        assert!(s.reasons.iter().any(|r| r.what.contains("같은 접속지")), "{:?}", s.reasons);
    }
    // 두 건뿐이면 그대로 낮음
    let store2 = Store::open_in_memory().unwrap();
    let mut ing2 = Ingester::new(&store2);
    ing2.ingest_all(&evs[..1 + 2 * 5]).unwrap();
    for app in [r"C:\Program Files\WindowsApps\V1.App_1.0\a.exe", r"C:\Program Files\WindowsApps\V2.App_1.0\b.exe"] {
        let fid = store2.find_node(graph::NodeKind::File, app).unwrap().unwrap();
        store2.merge_node_attrs(fid, &serde_json::json!({"store_package": app})).unwrap();
    }
    let bl2 = Baseline::open(&store2, T0 + 3 * DAY).unwrap();
    let two = judge::run(&store2, 0, i64::MAX, &bl2).unwrap();
    assert_eq!(two.len(), 2);
    assert!(two.iter().all(|s| s.level == Level::Normal), "{:#?}", two);
}

// ---- 개편안 2판 4-2: 파괴 행위 자동 대응 판정 ----

/// 서명 없는 프로그램 → cmd → vssadmin delete shadows: 세 조건 성립 → 원인 프로그램부터 끊기(Full)
#[test]
fn auto_response_full_for_unsigned_origin_running_t1490() {
    use judge::respond::{self, Mode, Verdict};
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let mal = r"C:\Users\u\AppData\Local\Temp\x.exe";
    ing.ingest_all(&[
        snap(T0, 1000, 4, EXPLORER, &[]),
        sig(T0, EXPLORER, Some("Microsoft Windows"), "valid", true),
        start(T0 + SEC, 4000, 1000, mal),
        sig(T0 + SEC, mal, None, "nosignature", false),
        start(T0 + 2 * SEC, 4100, 4000, CMD),
        sig(T0 + 2 * SEC, CMD, Some("Microsoft Windows"), "valid", true),
        start(T0 + 3 * SEC, 4200, 4100, VSSADMIN),
        sig(T0 + 3 * SEC, VSSADMIN, Some("Microsoft Windows"), "valid", true),
        cmd(T0 + 3 * SEC, 4200, "vssadmin.exe delete shadows /all /quiet"),
    ])
    .unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let view = judge::View::load(&store, 0, i64::MAX).unwrap();
    assert_eq!(stories.len(), 1);
    match respond::judge(&view, &stories[0], &[]) {
        Verdict::Respond(r) => {
            assert_eq!(r.mode, Mode::Full);
            assert_eq!(r.what, "그림자 복사본 삭제");
            assert_eq!(r.story_root, stories[0].root);
            // 명령을 실행한 프로세스는 vssadmin(4200); 서명 미확인 조상은 x.exe 하나(cmd·vssadmin 은 Windows 도구라 제외)
            assert_eq!(r.unsigned_chain.len(), 1, "{r:?}");
            // 끊기 대상은 원인 프로그램 x.exe
            let o = view.node(r.origin);
            assert!(judge::rules::attr_str(o, "image").unwrap_or_default().ends_with("x.exe"), "{o:?}");
            let p = view.node(r.trigger_proc);
            assert!(judge::rules::attr_str(p, "image").unwrap_or_default().ends_with("vssadmin.exe"), "{p:?}");
        }
        v => panic!("{v:?}"),
    }
}

/// 조상이 Microsoft 서명(여기서는 cmd 가 아니라 Windows 밖 경로의 Microsoft 서명 프로그램)이면 대응하지 않는다
#[test]
fn auto_response_skipped_when_ancestor_is_microsoft_or_allowlisted() {
    use judge::respond::{self, Mode, Verdict};
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let tool = r"C:\Program Files\Acme Backup\acmebackup.exe";
    ing.ingest_all(&[
        snap(T0, 1000, 4, EXPLORER, &[]),
        start(T0 + SEC, 4000, 1000, tool),
        sig(T0 + SEC, tool, Some("Acme Software Inc."), "valid", false),
        start(T0 + 2 * SEC, 4100, 4000, CMD),
        start(T0 + 3 * SEC, 4200, 4100, VSSADMIN),
        cmd(T0 + 3 * SEC, 4200, "vssadmin delete shadows /all /quiet"),
    ])
    .unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let view = judge::View::load(&store, 0, i64::MAX).unwrap();
    let s = stories.iter().find(|s| s.chapter == Chapter::Destroy).expect("5장 사건");
    // 허용 목록 없음: 유효 서명이라도 Microsoft 가 아니면 대응한다(2판 4-2) — 끊기 대상은 사건 뿌리(vssadmin)가 아니라 Acme
    match respond::judge(&view, s, &[]) {
        Verdict::Respond(r) => {
            assert_eq!(r.mode, Mode::Full);
            assert!(judge::rules::attr_str(view.node(r.origin), "image").unwrap_or_default().ends_with("acmebackup.exe"), "{r:?}");
        }
        v => panic!("{v:?}"),
    }
    // 허용 목록에 서명자(앞부분, 대소문자 무시)가 있으면 대응하지 않는다
    match respond::judge(&view, s, &["acme software".into()]) {
        Verdict::TrustedAncestor { signer, .. } => assert_eq!(signer, "Acme Software Inc."),
        v => panic!("{v:?}"),
    }
    // Microsoft 서명 조상은 목록 없이도 예외
    let store2 = Store::open_in_memory().unwrap();
    let mut ing2 = Ingester::new(&store2);
    let ms = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE";
    ing2.ingest_all(&[
        snap(T0, 1000, 4, EXPLORER, &[]),
        start(T0 + SEC, 4000, 1000, ms),
        sig(T0 + SEC, ms, Some("Microsoft Corporation"), "valid", false),
        start(T0 + 2 * SEC, 4100, 4000, CMD),
        start(T0 + 3 * SEC, 4200, 4100, VSSADMIN),
        cmd(T0 + 3 * SEC, 4200, "vssadmin delete shadows /all /quiet"),
    ])
    .unwrap();
    let bl2 = Baseline::open(&store2, T0 + DAY).unwrap();
    let st2 = judge::run(&store2, 0, i64::MAX, &bl2).unwrap();
    let view2 = judge::View::load(&store2, 0, i64::MAX).unwrap();
    let s2 = st2.iter().find(|s| s.chapter == Chapter::Destroy).expect("5장 사건");
    assert!(matches!(respond::judge(&view2, s2, &[]), Verdict::TrustedAncestor { .. }), "{s2:#?}");
}

/// 부모가 핵심 프로세스·Windows 도구뿐(explorer → cmd → vssadmin)이면 자식만 종료(ChildOnly)
#[test]
fn auto_response_child_only_when_parent_is_core_process() {
    use judge::respond::{self, Mode, Verdict};
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    ing.ingest_all(&[
        snap(T0, 1000, 4, EXPLORER, &[]),
        sig(T0, EXPLORER, Some("Microsoft Windows"), "valid", true),
        start(T0 + SEC, 3000, 1000, CMD),
        sig(T0 + SEC, CMD, Some("Microsoft Windows"), "valid", true),
        start(T0 + 2 * SEC, 3100, 3000, VSSADMIN),
        sig(T0 + 2 * SEC, VSSADMIN, Some("Microsoft Windows"), "valid", true),
        cmd(T0 + 2 * SEC, 3100, "vssadmin.exe delete shadows /all /quiet"),
    ])
    .unwrap();
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    let stories = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    let view = judge::View::load(&store, 0, i64::MAX).unwrap();
    let s = stories.iter().find(|s| s.root_kind == RootKind::RecoveryInhibit).expect("5장 사건");
    match respond::judge(&view, s, &[]) {
        Verdict::Respond(r) => {
            assert_eq!(r.mode, Mode::ChildOnly);
            assert!(r.unsigned_chain.is_empty());
        }
        v => panic!("{v:?}"),
    }
    // 5장이 아닌 사건은 NoDestroy
    let st = judge::run(&store, 0, i64::MAX, &bl).unwrap();
    for s in st.iter().filter(|s| s.chapter != Chapter::Destroy) {
        assert_eq!(respond::judge(&view, s, &[]), Verdict::NoDestroy);
    }
}
