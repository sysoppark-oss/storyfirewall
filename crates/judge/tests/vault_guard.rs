//! 17판 23-2 ② 브라우저 금고 경비 — 시나리오 시험
//! (별도 시험 바이너리: set_decoy_dirs 는 프로세스 전역)

use graph::event::{Direction, Event, EventKind, ProcRef, Proto};
use graph::ingest::Ingester;
use graph::store::Store;
use judge::{Baseline, Chapter, Level, RootKind, Story};

const T0: i64 = 133_800_000_000_000_000;
const SEC: i64 = 10_000_000;
const DAY: i64 = 24 * 3600 * SEC;

const EXPLORER: &str = r"C:\Windows\explorer.exe";
const SERVICES: &str = r"C:\Windows\System32\services.exe";
const CHROME: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
const CHROME_ELEV: &str =
    r"C:\Program Files\Google\Chrome\Application\131.0.6778.86\elevation_service.exe";
const EDGE: &str = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
const PWSH: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
const DEFENDER: &str =
    r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe";
const LOGIN: &str = r"C:\Users\pjg\AppData\Local\Google\Chrome\User Data\Default\Login Data";
const LOCAL_STATE: &str = r"C:\Users\pjg\AppData\Local\Google\Chrome\User Data\Local State";
const SETUP: &str = r"C:\Users\pjg\Downloads\setup.exe";

const VAULT_OPEN: &str = "브라우저가 아닌 프로그램이 브라우저 저장소를 엶";

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
fn stop(ts: i64, pid: u32) -> Event {
    ev(ts, "etw:process", EventKind::ProcessStop { pid })
}
fn snap(ts: i64, pid: u32, ppid: u32, image: &str) -> Event {
    ev(
        ts,
        "snapshot",
        EventKind::ProcessSnapshot {
            pid,
            ppid,
            image: image.into(),
            create_time: ts,
            services: vec![],
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
fn open(ts: i64, pid: u32, path: &str) -> Event {
    ev(
        ts,
        "etw:file:open",
        EventKind::FileOpen {
            proc: ProcRef::new(pid, None),
            path: path.into(),
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
fn motw(ts: i64, path: &str) -> Event {
    ev(
        ts,
        "motw",
        EventKind::Downloaded {
            path: path.into(),
            host_url: Some("https://files.example/setup.exe".into()),
            referrer_url: None,
            zone_id: Some(3),
        },
    )
}
/// 수집기가 디버깅 스위치만 남겨 보내는 명령줄
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

/// 공통 바탕: explorer·services(Microsoft 서명), Chrome 실행 파일 서명
fn base() -> Vec<Event> {
    vec![
        snap(T0, 600, 4, SERVICES),
        snap(T0, 1000, 4, EXPLORER),
        sig(T0, EXPLORER, Some("Microsoft Windows"), "valid", true),
        sig(T0, SERVICES, Some("Microsoft Windows"), "valid", true),
        sig(T0, CHROME, Some("Google LLC"), "valid", false),
        sig(T0, CHROME_ELEV, Some("Google LLC"), "valid", false),
    ]
}

fn judge_all(store: &Store) -> Vec<Story> {
    let bl = Baseline::open(store, T0 + DAY).unwrap();
    judge::run(store, 0, i64::MAX, &bl).unwrap()
}

fn whats(s: &Story) -> Vec<&'static str> {
    s.reasons.iter().map(|r| r.what).collect()
}

#[test]
fn downloaded_setup_opening_chrome_logins_then_egress_is_suspicious() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let mut evs = base();
    evs.extend([
        start(T0 + SEC, 3000, 1000, CHROME),
        write(T0 + 2 * SEC, 3000, SETUP),
        motw(T0 + 2 * SEC, SETUP),
        sig(T0 + 3 * SEC, SETUP, None, "nosignature", false),
        start(T0 + 4 * SEC, 5000, 1000, SETUP),
        open(T0 + 5 * SEC, 5000, LOGIN),
        open(T0 + 5 * SEC, 5000, LOCAL_STATE),
        // 같은 파일 다시 열기: 선 하나로 합쳐진다
        open(T0 + 6 * SEC, 5000, LOGIN),
        conn(T0 + 7 * SEC, 5000, "203.0.113.9", 443),
    ]);
    ing.ingest_all(&evs).unwrap();
    let stories = judge_all(&store);
    let s: Vec<_> = stories
        .iter()
        .filter(|s| s.root_label == "setup.exe")
        .collect();
    assert_eq!(s.len(), 1, "{stories:#?}");
    let s = s[0];
    assert_eq!(s.root_kind, RootKind::IngressFile);
    assert_eq!(s.chapter, Chapter::Egress);
    assert_eq!(s.level, Level::Suspicious, "{:?}", s.reasons);
    let w = whats(s);
    assert!(w.contains(&VAULT_OPEN), "{w:?}");
    // 신호 종류마다 한 번
    assert_eq!(w.iter().filter(|x| **x == VAULT_OPEN).count(), 1);
    let r = s.reasons.iter().find(|r| r.what == VAULT_OPEN).unwrap();
    let e = store.edge(r.edge_id.unwrap()).unwrap();
    assert_eq!(e.rel, "opened");
    assert_eq!(e.chapter, Some(Chapter::Execute as i64));
    assert!(
        !store.evidence_of(e.id).unwrap().is_empty(),
        "근거 원시 이벤트"
    );
    // Login Data 선은 하나(같은 프로세스·파일 60초 안 = 합침), 근거는 둘
    let n: i64 = store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM edges e JOIN nodes n ON n.id = e.dst WHERE e.rel='opened' AND n.key = ?1",
            [LOGIN],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
    // chrome 은 사건이 아니다
    assert!(
        stories.iter().all(|s| s.root_label != "chrome.exe"),
        "{stories:#?}"
    );
}

#[test]
fn browsers_and_system_readers_opening_vaults_are_not_evidence() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let mut evs = base();
    evs.extend([
        // Chrome 이 자기 금고를 엶
        start(T0 + SEC, 3000, 1000, CHROME),
        open(T0 + 2 * SEC, 3000, LOGIN),
        open(T0 + 2 * SEC, 3000, LOCAL_STATE),
        conn(T0 + 3 * SEC, 3000, "142.250.1.1", 443),
        // Edge 가 Chrome 금고를 엶(가져오기 기능)
        start(T0 + 4 * SEC, 3100, 1000, EDGE),
        sig(
            T0 + 4 * SEC,
            EDGE,
            Some("Microsoft Corporation"),
            "valid",
            false,
        ),
        open(T0 + 5 * SEC, 3100, LOGIN),
        // Defender 검사
        snap(T0, 700, 600, DEFENDER),
        sig(T0, DEFENDER, Some("Microsoft Corporation"), "valid", false),
        open(T0 + 6 * SEC, 700, LOGIN),
        // 금고가 아닌 파일(History)
        start(T0 + 7 * SEC, 3200, 1000, PWSH),
        sig(T0 + 7 * SEC, PWSH, Some("Microsoft Windows"), "valid", true),
        open(
            T0 + 8 * SEC,
            3200,
            r"C:\Users\pjg\AppData\Local\Google\Chrome\User Data\Default\History",
        ),
    ]);
    ing.ingest_all(&evs).unwrap();
    let stories = judge_all(&store);
    assert!(stories.is_empty(), "{stories:#?}");
}

#[test]
fn renamed_chrome_copy_in_temp_is_not_a_browser() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let fake = r"C:\Users\pjg\AppData\Local\Temp\chrome.exe";
    let mut evs = base();
    evs.extend([
        // 서명은 Google 그대로(복사본) — 위치가 설치 폴더가 아니다
        start(T0 + SEC, 5100, 1000, fake),
        sig(T0 + SEC, fake, Some("Google LLC"), "valid", false),
        open(T0 + 2 * SEC, 5100, LOGIN),
    ]);
    ing.ingest_all(&evs).unwrap();
    let stories = judge_all(&store);
    let s = stories
        .iter()
        .find(|s| s.root_kind == RootKind::VaultAccess)
        .unwrap_or_else(|| panic!("{stories:#?}"));
    assert_eq!(s.root_label, "chrome.exe");
    assert_eq!(s.chapter, Chapter::Execute);
    // 2장 30 + 신뢰하는 서명 0 + Temp 10 + 금고 15 = 55
    assert_eq!(s.score, 55, "{:?}", s.reasons);
    assert_eq!(s.level, Level::Watch);
    assert!(whats(s).contains(&VAULT_OPEN));

    // 설치 위치의 chrome.exe 라도 서명이 깨졌으면 브라우저가 아니다
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let mut evs: Vec<Event> = base()
        .into_iter()
        .filter(|e| !matches!(&e.kind, EventKind::Signature { path, .. } if path == CHROME))
        .collect();
    evs.extend([
        start(T0 + SEC, 5300, 1000, CHROME),
        sig(T0 + SEC, CHROME, None, "untrusted:bad_digest", false),
        open(T0 + 2 * SEC, 5300, LOGIN),
    ]);
    ing.ingest_all(&evs).unwrap();
    let stories = judge_all(&store);
    assert_eq!(stories.len(), 1, "{stories:#?}");
    assert_eq!(stories[0].root_kind, RootKind::UnsignedProcess);
    assert!(whats(&stories[0]).contains(&VAULT_OPEN));
}

#[test]
fn signed_program_opening_vault_alone_is_watch_and_with_egress_suspicious() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let tool = r"C:\Program Files\Vendor\PassImport\import.exe";
    let mut evs = base();
    evs.extend([
        start(T0 + SEC, 5400, 1000, tool),
        sig(T0 + SEC, tool, Some("Vendor Inc"), "valid", false),
        open(T0 + 2 * SEC, 5400, LOGIN),
    ]);
    ing.ingest_all(&evs).unwrap();
    let stories = judge_all(&store);
    assert_eq!(stories.len(), 1, "{stories:#?}");
    assert_eq!(stories[0].root_kind, RootKind::VaultAccess);
    assert_eq!(stories[0].score, 45, "{:?}", stories[0].reasons);
    assert_eq!(stories[0].level, Level::Watch);
    // 외부 접속까지
    ing.ingest_all(&[conn(T0 + 3 * SEC, 5400, "203.0.113.20", 443)])
        .unwrap();
    let stories = judge_all(&store);
    assert_eq!(stories[0].chapter, Chapter::Egress);
    assert_eq!(
        stories[0].level,
        Level::Suspicious,
        "{:?}",
        stories[0].reasons
    );
    // Microsoft 서명 도구(esentutl)로 복사해도 −40 감점 없이 주의
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let esent = r"C:\Windows\System32\esentutl.exe";
    let mut evs = base();
    evs.extend([
        start(T0 + SEC, 5500, 1000, esent),
        sig(T0 + SEC, esent, Some("Microsoft Windows"), "valid", true),
        open(T0 + 2 * SEC, 5500, LOGIN),
    ]);
    ing.ingest_all(&evs).unwrap();
    let stories = judge_all(&store);
    assert_eq!(stories.len(), 1, "{stories:#?}");
    assert!(stories[0].score >= 40, "{:?}", stories[0].reasons);
    assert!(whats(&stories[0])
        .iter()
        .all(|w| *w != "Microsoft 서명(카탈로그)"));
}

#[test]
fn debugging_port_launch_by_unusual_parent_is_evidence() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let mut evs = base();
    evs.extend([
        sig(T0, PWSH, Some("Microsoft Windows"), "valid", true),
        start(T0 + SEC, 6000, 1000, PWSH),
        start(T0 + 2 * SEC, 6100, 6000, CHROME),
        cmd(
            T0 + 2 * SEC,
            6100,
            "chrome.exe --remote-debugging-port=9333 --headless=new",
        ),
        // 디버깅 포트(명령줄의 9333)에 PowerShell 이 접속
        conn(T0 + 3 * SEC, 6000, "127.0.0.1", 9333),
        // 사용자가 바로가기로 연 디버깅 모드(부모 = 탐색기)는 근거가 아니다
        start(T0 + 4 * SEC, 6200, 1000, CHROME),
        cmd(
            T0 + 4 * SEC,
            6200,
            "chrome.exe --remote-debugging-port=9444",
        ),
        // 브라우저가 이 PC 안 디버깅 포트로 접속하는 것도 근거가 아니다
        conn(T0 + 5 * SEC, 6200, "::1", 9222),
    ]);
    ing.ingest_all(&evs).unwrap();
    let stories = judge_all(&store);
    assert_eq!(stories.len(), 1, "{stories:#?}");
    let s = &stories[0];
    assert_eq!(s.root_kind, RootKind::VaultAccess);
    assert_eq!(s.root_label, "powershell.exe");
    let w = whats(s);
    assert!(w.contains(&"디버깅 모드로 브라우저 실행"), "{w:?}");
    assert!(w.contains(&"브라우저 디버깅 포트 접속"), "{w:?}");
    // 2장 30 + 15 + 15 (Microsoft 서명 감점 없음)
    assert_eq!(s.score, 60, "{:?}", s.reasons);
    assert_eq!(s.level, Level::Watch);
    let r = s
        .reasons
        .iter()
        .find(|r| r.what == "디버깅 모드로 브라우저 실행")
        .unwrap();
    assert_eq!(store.edge(r.edge_id.unwrap()).unwrap().rel, "ran");
    // 디버깅 모드로 띄운 브라우저가 외부에 접속하면 의심
    ing.ingest_all(&[conn(T0 + 6 * SEC, 6100, "142.250.1.1", 443)])
        .unwrap();
    let stories = judge_all(&store);
    let s = stories
        .iter()
        .find(|s| s.root_label == "powershell.exe")
        .unwrap();
    assert_eq!(s.level, Level::Suspicious, "{:?}", s.reasons);

    // 기본 포트(9222)는 디버깅 실행을 못 봤어도 감시한다
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let py = r"C:\Users\pjg\AppData\Local\Programs\Python\Python312\python.exe";
    let mut evs = base();
    evs.extend([
        start(T0 + SEC, 6300, 1000, py),
        sig(
            T0 + SEC,
            py,
            Some("Python Software Foundation"),
            "valid",
            false,
        ),
        conn(T0 + 2 * SEC, 6300, "127.0.0.1", 9222),
        conn(T0 + 2 * SEC, 6300, "127.0.0.1", 8080),
    ]);
    ing.ingest_all(&evs).unwrap();
    let stories = judge_all(&store);
    assert_eq!(stories.len(), 1, "{stories:#?}");
    assert_eq!(
        whats(&stories[0])
            .iter()
            .filter(|w| w.contains("디버깅"))
            .count(),
        1
    );
}

#[test]
fn decoy_open_alone_is_suspicious_only_when_registered() {
    judge::set_decoy_dirs(vec![
        r"C:\Users\pjg\AppData\Roaming\Exodus\exodus.wallet".into(),
        // 후보 밖(실제 Chrome 프로필)은 등록되지 않는다
        r"C:\Users\pjg\AppData\Local\Google\Chrome\User Data".into(),
    ]);
    assert!(judge::rules::is_decoy(
        r"C:\Users\pjg\AppData\Roaming\Exodus\exodus.wallet\seed.seco"
    ));
    assert!(!judge::rules::is_decoy(LOGIN));
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let tool = r"C:\Program Files\Vendor\Sync\sync.exe";
    let mut evs = base();
    evs.extend([
        start(T0 + SEC, 7000, 1000, tool),
        sig(T0 + SEC, tool, Some("Vendor Inc"), "valid", false),
        open(
            T0 + 2 * SEC,
            7000,
            r"C:\Users\pjg\AppData\Roaming\Exodus\exodus.wallet\seed.seco",
        ),
        // 등록되지 않은 후보(Electrum)는 근거가 아니다
        start(T0 + 3 * SEC, 7100, 1000, tool),
        open(
            T0 + 4 * SEC,
            7100,
            r"C:\Users\pjg\AppData\Roaming\Electrum\wallets\default_wallet",
        ),
    ]);
    ing.ingest_all(&evs).unwrap();
    let stories = judge_all(&store);
    assert_eq!(stories.len(), 1, "{stories:#?}");
    let s = &stories[0];
    assert_eq!(s.root_kind, RootKind::VaultAccess);
    assert_eq!(s.level, Level::Suspicious, "{:?}", s.reasons);
    assert!(whats(s).contains(&"미끼 파일 접근"));
    // 근거 선은 7000 의 열기
    let r = s
        .reasons
        .iter()
        .find(|r| r.what == "미끼 파일 접근")
        .unwrap();
    let e = store.edge(r.edge_id.unwrap()).unwrap();
    assert!(store.node(e.dst).unwrap().key.contains("Exodus"));
}

#[test]
fn elevation_service_signals() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let stealer = r"C:\Users\pjg\AppData\Local\Temp\x.exe";
    let mut evs = base();
    evs.extend([
        start(T0 + SEC, 3000, 1000, CHROME),
        start(T0 + 2 * SEC, 8000, 1000, stealer),
        sig(T0 + 2 * SEC, stealer, None, "nosignature", false),
        open(T0 + 3 * SEC, 8000, LOCAL_STATE),
        // 브라우저가 끝나고 3초 뒤 서비스 관리자가 권한 상승 서비스를 띄움
        stop(T0 + 4 * SEC, 3000),
        start(T0 + 7 * SEC, 8100, 600, CHROME_ELEV),
    ]);
    ing.ingest_all(&evs).unwrap();
    let stories = judge_all(&store);
    assert_eq!(stories.len(), 1, "{stories:#?}");
    let w = whats(&stories[0]);
    assert!(w.contains(&VAULT_OPEN), "{w:?}");
    assert!(
        w.contains(&"브라우저 종료 직후 권한 상승 서비스 시작"),
        "{w:?}"
    );

    // 브라우저가 아닌 프로그램이 직접 실행
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let mut evs = base();
    evs.extend([
        start(T0 + 2 * SEC, 8000, 1000, stealer),
        sig(T0 + 2 * SEC, stealer, None, "nosignature", false),
        start(T0 + 3 * SEC, 8200, 8000, CHROME_ELEV),
    ]);
    ing.ingest_all(&evs).unwrap();
    let stories = judge_all(&store);
    assert_eq!(stories.len(), 1, "{stories:#?}");
    assert!(
        whats(&stories[0]).contains(&"브라우저가 아닌 프로그램이 브라우저 권한 상승 서비스를 실행")
    );

    // 브라우저가 실행 중일 때 서비스 관리자가 띄운 것(평소 모습)은 아무것도 아니다
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let mut evs = base();
    evs.extend([
        start(T0 + SEC, 3000, 1000, CHROME),
        start(T0 + 2 * SEC, 8100, 600, CHROME_ELEV),
    ]);
    ing.ingest_all(&evs).unwrap();
    assert!(judge_all(&store).is_empty());
}

/// L062(30차 Q3-c): 다른 프로세스가 코드를 주입한 브라우저가 금고를 열면 근거다(주입 코드가 연 것일 수 있다)
#[test]
fn injected_browser_opening_its_vault_is_evidence() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let bad = r"C:\Users\pjg\Downloads\x.exe";
    let mut evs = base();
    evs.extend([
        start(T0 + SEC, 5000, 1000, bad),
        start(T0 + SEC, 5200, 1000, CHROME),
        ev(
            T0 + 2 * SEC,
            "sysmon",
            EventKind::Injected {
                from: ProcRef::new(5000, None),
                into: ProcRef::new(5200, None),
                method: "remote_thread".into(),
            },
        ),
        open(T0 + 3 * SEC, 5200, LOGIN),
    ]);
    ing.ingest_all(&evs).unwrap();
    let stories = judge_all(&store);
    assert!(
        stories.iter().any(|s| whats(s).contains(&VAULT_OPEN)),
        "{stories:#?}"
    );
}

/// L063(사용자 결정 "정상 버튼으로"): 금고 경비 사건의 "정상"은 그 판정에만 — 같은 프로그램의 다른 판정 키는 남기지 않는다
#[test]
fn vault_normal_feedback_is_scoped_to_vault_stories() {
    let store = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&store);
    let tool = r"C:\Program Files\Vendor\tool.exe";
    let mut evs = base();
    evs.extend([
        start(T0 + SEC, 5400, 1000, tool),
        sig(T0 + SEC, tool, Some("Vendor Inc."), "valid", false),
        open(T0 + 2 * SEC, 5400, LOGIN),
    ]);
    ing.ingest_all(&evs).unwrap();
    let s = judge_all(&store);
    let st = s
        .iter()
        .find(|s| s.root_kind == RootKind::VaultAccess)
        .unwrap_or_else(|| panic!("{s:#?}"));
    assert_ne!(st.level, Level::Normal);
    let f = graph::views::image_file_of(&store, st.root).expect("실행 파일 노드");
    let bl = Baseline::open(&store, T0 + DAY).unwrap();
    bl.mark_normal_vault(&store, &f).unwrap();
    let keys = bl.feedback_keys(&store).unwrap();
    assert!(keys.contains(&judge::baseline::vault_key(&f)));
    assert!(
        !keys.contains(&judge::baseline::root_key(&f)),
        "프로그램 전체를 정상으로 만들지 않는다"
    );
    let s = judge_all(&store);
    let st = s
        .iter()
        .find(|s| s.root_kind == RootKind::VaultAccess)
        .unwrap();
    assert_eq!(st.level, Level::Normal, "{:?}", st.reasons);
}
