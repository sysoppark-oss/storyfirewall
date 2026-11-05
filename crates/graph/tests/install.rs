//! 설치 엑스레이 (기획서 14판 20-3)

use graph::event::{Direction, Event, EventKind, ProcRef, Proto};
use graph::ingest::Ingester;
use graph::install::{install_xray, installer_roots};
use graph::Store;

const T: i64 = 133_800_000_000_000_000;
const S: i64 = 10_000_000;
const SETUP: &str = r"C:\Users\u\Downloads\WhaleSetup.exe";

fn ev(ts: i64, source: &str, kind: EventKind) -> Event {
    Event {
        ts,
        source: source.into(),
        kind,
    }
}

fn scenario() -> Store {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    let events = vec![
        ev(
            T,
            "snapshot",
            EventKind::ProcessSnapshot {
                pid: 1000,
                ppid: 4,
                image: r"C:\Windows\explorer.exe".into(),
                create_time: T,
                services: vec![],
            },
        ),
        ev(
            T + S,
            "motw",
            EventKind::Downloaded {
                path: SETUP.into(),
                host_url: Some("https://installer.whale.example/WhaleSetup.exe".into()),
                referrer_url: None,
                zone_id: Some(3),
            },
        ),
        ev(
            T + 2 * S,
            "etw:process",
            EventKind::ProcessStart {
                pid: 3000,
                ppid: 1000,
                image: SETUP.into(),
                create_time: Some(T + 2 * S),
            },
        ),
        // 설치 프로그램이 띄운 설치 프로그램(같은 묶음) → 바깥쪽만 뿌리
        ev(
            T + 3 * S,
            "etw:process",
            EventKind::ProcessStart {
                pid: 3100,
                ppid: 3000,
                image: r"C:\Users\u\AppData\Local\Temp\x\whale_installer.exe".into(),
                create_time: Some(T + 3 * S),
            },
        ),
        ev(
            T + 4 * S,
            "etw:process",
            EventKind::ProcessStart {
                pid: 3200,
                ppid: 3100,
                image: r"C:\Windows\System32\cmd.exe".into(),
                create_time: Some(T + 4 * S),
            },
        ),
        ev(
            T + 5 * S,
            "etw:file",
            EventKind::FileWrite {
                proc: ProcRef::new(3100, None),
                path: r"C:\Users\u\AppData\Local\Naver\Whale\whale_update.exe".into(),
            },
        ),
        ev(
            T + 6 * S,
            "autorun",
            EventKind::AutorunRegistered {
                proc: ProcRef::new(3100, None),
                location: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WhaleUpdate".into(),
                target: r"C:\Users\u\AppData\Local\Naver\Whale\whale_update.exe".into(),
            },
        ),
        ev(
            T + 7 * S,
            "etw:dns",
            EventKind::DnsQuery {
                proc: ProcRef::new(3000, None),
                name: "installer.whale.example".into(),
                results: vec!["203.0.113.20".into()],
            },
        ),
        ev(
            T + 8 * S,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(3000, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50000,
                raddr: "203.0.113.20".into(),
                rport: 443,
            },
        ),
        ev(
            T + 9 * S,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(3000, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50001,
                raddr: "203.0.113.20".into(),
                rport: 443,
            },
        ),
        // 설치와 상관없는 프로그램
        ev(
            T + 9 * S,
            "etw:process",
            EventKind::ProcessStart {
                pid: 4000,
                ppid: 1000,
                image: r"C:\Program Files\Google\Chrome\chrome.exe".into(),
                create_time: Some(T + 9 * S),
            },
        ),
    ];
    ing.ingest_all(&events).unwrap();
    st
}

#[test]
fn finds_outer_installer_only() {
    let st = scenario();
    let roots = installer_roots(&st, T, 10).unwrap();
    assert_eq!(
        roots.len(),
        1,
        "설치 프로그램이 띄운 설치 프로그램은 같은 묶음"
    );
    let x = install_xray(&st, roots[0], 100).unwrap();
    assert!(x.image.ends_with("WhaleSetup.exe"));
    assert_eq!(x.pid, Some(3000));
}

#[test]
fn xray_collects_files_autoruns_remotes_origin() {
    let st = scenario();
    let root = installer_roots(&st, T, 10).unwrap()[0];
    let x = install_xray(&st, root, 100).unwrap();
    assert_eq!(x.procs.len(), 3, "설치 프로그램 + 내부 설치 프로그램 + cmd");
    assert!(x.files.iter().any(|f| f.ends_with("whale_update.exe")));
    assert_eq!(x.autoruns.len(), 1);
    assert!(x.autoruns[0].0.ends_with(r"Run\WhaleUpdate"));
    assert_eq!(
        x.remotes.first().map(|r| (r.0.as_str(), r.1)),
        Some(("installer.whale.example", 2)),
        "도메인으로, 접속 2번"
    );
    assert!(
        x.origin.as_deref().unwrap_or("").contains("whale.example"),
        "내려받은 곳: {:?}",
        x.origin
    );
    assert!(!x.truncated);
    assert!(x.last_ts >= T + 8 * S);
}

/// L060 (install-28 실측): 받은 설치 파일 뒤에 업데이트 서비스가 진짜 설치 과정을 띄우면 부모 연결이 끊긴다 → 시간으로 한 설치에 묶는다
#[test]
fn detached_setup_started_soon_after_is_grouped_by_time() {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    let svc = r"C:\Program Files\Naver\Naver Whale\Application\wusvc.exe";
    let inner = r"C:\Program Files (x86)\Naver\Whale\{GUID}\CR_04D08.tmp\setup.exe";
    let events = vec![
        ev(
            T,
            "snapshot",
            EventKind::ProcessSnapshot {
                pid: 1000,
                ppid: 4,
                image: r"C:\Windows\explorer.exe".into(),
                create_time: T,
                services: vec![],
            },
        ),
        ev(
            T,
            "snapshot",
            EventKind::ProcessSnapshot {
                pid: 700,
                ppid: 4,
                image: r"C:\Windows\System32\services.exe".into(),
                create_time: T,
                services: vec![],
            },
        ),
        ev(
            T + S,
            "etw:process",
            EventKind::ProcessStart {
                pid: 3000,
                ppid: 1000,
                image: SETUP.into(),
                create_time: Some(T + S),
            },
        ),
        // 업데이트 서비스(설치 프로그램 아님)가 진짜 설치 과정을 띄움 — 부모가 WhaleSetup 이 아님
        ev(
            T + 20 * S,
            "etw:process",
            EventKind::ProcessStart {
                pid: 3300,
                ppid: 700,
                image: svc.into(),
                create_time: Some(T + 20 * S),
            },
        ),
        ev(
            T + 30 * S,
            "etw:process",
            EventKind::ProcessStart {
                pid: 3400,
                ppid: 3300,
                image: inner.into(),
                create_time: Some(T + 30 * S),
            },
        ),
        ev(
            T + 40 * S,
            "etw:process",
            EventKind::ProcessStart {
                pid: 3500,
                ppid: 3400,
                image: r"C:\Windows\SysWOW64\schtasks.exe".into(),
                create_time: Some(T + 40 * S),
            },
        ),
        // 두 설치 파일 모두 같은 회사의 유효 서명(L062: 시간 묶기 조건)
        ev(
            T + 31 * S,
            "signature",
            EventKind::Signature {
                path: SETUP.into(),
                signer: Some("NAVER Corp.".into()),
                issuer: None,
                status: "valid".into(),
                catalog: false,
            },
        ),
        ev(
            T + 31 * S,
            "signature",
            EventKind::Signature {
                path: inner.into(),
                signer: Some("NAVER Corp.".into()),
                issuer: None,
                status: "valid".into(),
                catalog: false,
            },
        ),
        // 같은 2분 안에 끼어든 서명 없는 "setup" — 묶이지 않는다(30차 Q1)
        ev(
            T + 50 * S,
            "etw:process",
            EventKind::ProcessStart {
                pid: 3600,
                ppid: 1000,
                image: r"C:\Users\u\AppData\Local\Temp\setup_hidden.exe".into(),
                create_time: Some(T + 50 * S),
            },
        ),
        // 10분 뒤 다른 설치 → 따로
        ev(
            T + 900 * S,
            "etw:process",
            EventKind::ProcessStart {
                pid: 5000,
                ppid: 1000,
                image: r"C:\Users\u\Downloads\OtherSetup.exe".into(),
                create_time: Some(T + 900 * S),
            },
        ),
    ];
    ing.ingest_all(&events).unwrap();
    let xs = graph::install::installs(&st, T, 10, 100, |_| true).unwrap();
    assert_eq!(xs.len(), 3, "{xs:#?}");
    assert!(xs[0].image.ends_with("OtherSetup.exe"), "최신 먼저");
    assert!(
        xs[1].image.ends_with("setup_hidden.exe"),
        "서명 없는 끼어든 설치는 따로"
    );
    assert!(xs[1].grouped.is_empty());
    let w = &xs[2];
    assert!(w.image.ends_with("WhaleSetup.exe"));
    assert_eq!(w.grouped.len(), 1);
    assert!(w.grouped[0].ends_with(r"CR_04D08.tmp\setup.exe"));
    assert!(w.procs.iter().any(|p| p.ends_with("schtasks.exe")));
    assert_eq!(
        w.persistence,
        vec!["schtasks.exe 실행 (명령줄을 받지 못해 무엇을 바꿨는지 모름)".to_string()]
    );
}
