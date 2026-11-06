//! 첫 실행 관찰실 (기획서 17판 23-2 ①): 대상 고르기와 자동 차단 계획

use std::collections::HashSet;

use dsl::expand::Resolver;
use engine::backend::{FakeWfp, NoGraph};
use engine::clock::FakeClock;
use engine::{Engine, State};
use graph::event::{Event, EventKind};
use graph::ingest::Ingester;
use graph::Store;
use svc::first_run::{
    assess, assess_at_expiry, sync_umbrella, try_block, umbrella, Assess, Mode, SigFact, Target,
};

const T: i64 = 133_800_000_000_000_000;

fn ev(ts: i64, kind: EventKind) -> Event {
    Event {
        ts,
        source: "test".into(),
        kind,
    }
}
fn start(pid: u32, image: &str, ts: i64) -> Event {
    ev(
        ts,
        EventKind::ProcessStart {
            pid,
            ppid: 10,
            image: image.into(),
            create_time: Some(ts),
        },
    )
}
fn sig(path: &str, status: &str, signer: Option<&str>) -> Event {
    ev(
        T + 5,
        EventKind::Signature {
            path: path.into(),
            signer: signer.map(|s| s.into()),
            issuer: None,
            status: status.into(),
            catalog: false,
        },
    )
}
fn motw(path: &str, zone: u32) -> Event {
    ev(
        T + 5,
        EventKind::Downloaded {
            path: path.into(),
            host_url: Some("https://dl.example.com/files/tool.exe".into()),
            referrer_url: None,
            zone_id: Some(zone),
        },
    )
}
fn store() -> Store {
    let st = Store::open_in_memory().unwrap();
    Ingester::new(&st)
        .ingest(&ev(
            T,
            EventKind::ProcessSnapshot {
                pid: 10,
                ppid: 4,
                image: r"C:\Windows\explorer.exe".into(),
                create_time: T,
                services: vec![],
            },
        ))
        .unwrap();
    st
}
fn proc_node(st: &Store, pid: u32, ts: i64) -> i64 {
    st.find_node(graph::NodeKind::Process, &format!("{pid}@{ts}"))
        .unwrap()
        .unwrap()
}
fn target(a: Assess) -> Target {
    match a {
        Assess::Target(t) => *t,
        other => panic!("대상이어야 한다: {other:?}"),
    }
}

#[test]
fn downloaded_unsigned_first_run_is_target_second_run_is_not() {
    let st = store();
    let mut ing = Ingester::new(&st);
    let exe = r"C:\Users\u\Downloads\tool.exe";
    ing.ingest(&start(20, exe, T + 1)).unwrap();
    let p = proc_node(&st, 20, T + 1);
    let none = HashSet::new();
    // 서명·출신이 아직 오지 않았다 → 기다린다
    assert_eq!(assess(&st, &none, p), Assess::Pending);
    ing.ingest(&sig(exe, "nosignature", None)).unwrap();
    assert_eq!(
        assess(&st, &none, p),
        Assess::Pending,
        "출신 표시를 기다린다"
    );
    ing.ingest(&motw(exe, 3)).unwrap();
    let t = target(assess(&st, &none, p));
    assert_eq!(t.path, exe);
    assert_eq!(t.pid, 20);
    assert_eq!(
        t.create_ft,
        T + 1,
        "서비스 사건 대상이 그래프 프로세스 키와 같은 형식"
    );
    assert_eq!(t.host.as_deref(), Some("dl.example.com"));
    assert_eq!(t.sig, SigFact::None);
    assert!(!t.installer);
    // 두 번째 실행 → 대상 아님. 첫 실행은 다시 봐도 대상(같은 파일 한 번만은 기록 표가 막는다)
    ing.ingest(&start(21, exe, T + 100)).unwrap();
    let p2 = proc_node(&st, 21, T + 100);
    assert_eq!(assess(&st, &none, p2), Assess::Skip("전에 실행된 적 있음"));
    assert!(matches!(assess(&st, &none, p), Assess::Target(_)));
}

#[test]
fn signed_local_installer_and_user_normal_are_handled() {
    let st = store();
    let mut ing = Ingester::new(&st);
    let none = HashSet::new();
    // 유효 서명 → 아님
    let signed = r"C:\Users\u\Downloads\signed.exe";
    ing.ingest_all(&[
        start(30, signed, T + 1),
        sig(signed, "valid", Some("Contoso Ltd")),
        motw(signed, 3),
    ])
    .unwrap();
    assert_eq!(
        assess(&st, &none, proc_node(&st, 30, T + 1)),
        Assess::Skip("서명 유효")
    );
    // 인터넷 표시 없음(로컬 Zone 0... 여기서는 인트라넷 1) → 아님
    let local = r"C:\Users\u\Desktop\local.exe";
    ing.ingest_all(&[
        start(31, local, T + 1),
        sig(local, "nosignature", None),
        motw(local, 1),
    ])
    .unwrap();
    assert_eq!(
        assess(&st, &none, proc_node(&st, 31, T + 1)),
        Assess::Skip("인터넷에서 받은 표시 없음")
    );
    // 깨진 서명 + Zone 4 → 대상(서명 사실 말이 다르다)
    let broken = r"C:\Users\u\Downloads\patched.exe";
    ing.ingest_all(&[
        start(32, broken, T + 1),
        sig(broken, "untrusted:bad_digest", Some("Contoso Ltd")),
        motw(broken, 4),
    ])
    .unwrap();
    assert_eq!(
        target(assess(&st, &none, proc_node(&st, 32, T + 1))).sig,
        SigFact::Broken
    );
    // 설치 프로그램 → 관찰 대상이지만 막지 않는다
    let setup = r"C:\Users\u\Downloads\FooSetup.exe";
    ing.ingest_all(&[
        start(33, setup, T + 1),
        sig(setup, "nosignature", None),
        motw(setup, 3),
    ])
    .unwrap();
    let t = target(assess(&st, &none, proc_node(&st, 33, T + 1)));
    assert!(
        t.installer,
        "설치 프로그램은 관찰 대상(막지는 않음 — 아래 우산 시험)"
    );
    // 사용자가 "정상"으로 표시한 파일 → 아님 (기준선 feedback_normal 키)
    let normal = r"C:\Users\u\Downloads\mytool.exe";
    ing.ingest_all(&[
        start(34, normal, T + 1),
        sig(normal, "nosignature", None),
        motw(normal, 3),
    ])
    .unwrap();
    let base = judge::Baseline::open(&st, T).unwrap();
    let f = st
        .find_node(graph::NodeKind::File, normal)
        .unwrap()
        .unwrap();
    base.mark_normal(&st, &st.node(f).unwrap()).unwrap();
    let fb = base.feedback_keys(&st).unwrap();
    assert_eq!(
        assess(&st, &fb, proc_node(&st, 34, T + 1)),
        Assess::Skip("사용자가 정상으로 표시")
    );
}

#[test]
fn preexisting_snapshot_process_is_not_a_first_run() {
    let st = store();
    let exe = r"C:\Users\u\Downloads\old.exe";
    Ingester::new(&st)
        .ingest_all(&[
            ev(
                T,
                EventKind::ProcessSnapshot {
                    pid: 40,
                    ppid: 10,
                    image: exe.into(),
                    create_time: T - 100,
                    services: vec![],
                },
            ),
            sig(exe, "nosignature", None),
            motw(exe, 3),
        ])
        .unwrap();
    assert_eq!(
        assess(&st, &HashSet::new(), proc_node(&st, 40, T - 100)),
        Assess::Skip("수집 전부터 실행 중")
    );
}

// ---- 막기(방식 나): 관리자 요청으로 만든 우산 정책이 확인된 뒤에만 그 아래 기한부 차단 ----

struct R;
impl Resolver for R {
    fn list_exes(&self, _: &str) -> Vec<String> {
        vec![]
    }
    fn descendants(&self, f: &str, _: &str) -> Result<Vec<String>, String> {
        Ok(vec![f.to_string()])
    }
    fn exists(&self, _: &str) -> bool {
        true
    }
}

const NOW: i64 = 1_700_000_000;
const RID: &str = "0f3c2a1e-9b7d-4c6a-8e5f-123456789abc";
const ADMIN: &str = "pid 100 ui.exe";

fn t_for(path: &str) -> Target {
    Target {
        proc_node: 2,
        file_node: 3,
        path: path.into(),
        pid: 20,
        create_ft: T,
        start_ts: NOW,
        host: None,
        installer: graph::install::is_installer_image(path),
        sig: SigFact::None,
        session: None,
        content_ts: 0,
        sha256: None,
        hash_unverified: false,
    }
}

fn new_engine<'a>(wfp: &'a mut FakeWfp, clock: &'a FakeClock) -> Engine<'a> {
    Engine::new(
        rusqlite::Connection::open_in_memory().unwrap(),
        wfp,
        &NoGraph,
        clock,
        &R,
        &["story-firewall-svc.exe"],
    )
    .unwrap()
}

#[test]
fn umbrella_must_be_confirmed_before_child_blocks_and_children_expire() {
    let exe = r"C:\Users\u\Downloads\to'ol: {x} #.exe";
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(NOW);
    {
        let mut eng = new_engine(&mut wfp, &clock);
        // 우산 없음 → 알림만
        let e = try_block(&mut eng, &t_for(exe), NOW + 600).unwrap_err();
        assert!(e.contains("확인된 상태가 아니어서"), "{e}");
        // 관리자 요청으로 우산 적용 → 확인 대기(Applied): 아직 막지 않는다
        let r = sync_umbrella(&mut eng, Mode::Block, RID, ADMIN)
            .unwrap()
            .expect("우산 적용");
        assert_eq!(r.filters, 0, "우산 자체는 필터 없음");
        assert_eq!(umbrella(&eng.store).unwrap().state, State::Applied);
        assert!(try_block(&mut eng, &t_for(exe), NOW + 600).is_err());
        // 같은 block 을 다시 골라도 새 우산을 만들지 않는다
        assert!(sync_umbrella(
            &mut eng,
            Mode::Block,
            "1f3c2a1e-9b7d-4c6a-8e5f-123456789abc",
            ADMIN
        )
        .unwrap()
        .is_none());
        // 사람이 확인 → 대상 실행 시 기한부 경로 차단
        eng.confirm(r.policy_id, r.version, ADMIN).unwrap();
        let (uid, ids) = try_block(&mut eng, &t_for(exe), NOW + 600).unwrap();
        assert_eq!(uid, r.policy_id);
        assert!(!ids.is_empty());
        let rows = eng.store.filters_of(uid).unwrap();
        assert!(rows.iter().all(|f| f.expires_at == Some(NOW + 600)));
        assert!(rows.iter().all(|f| f.spec.app_path.as_deref() == Some(exe)
            && f.spec.direction == policy::spec::Direction::Out));
        // 정책 기록: 우산 정책 번호 아래 행위자 system:first_run_watch
        let h = eng.store.history_of(uid).unwrap();
        assert!(
            h.iter().any(|x| x.1 == "child_block"
                && x.3 == svc::first_run::ACTOR
                && x.2.contains("to'ol")),
            "{h:?}"
        );
        assert_eq!(h[0].3, ADMIN, "우산은 관리자 요청으로 생긴다");
        // 주소 차단 목록·일괄 해제에는 섞이지 않는다
        assert_eq!(eng.address_blocks().unwrap().len(), 0);
        // 시간이 지나면 만료 → 필터 제거, 우산은 그대로
        clock.advance(601);
        eng.tick().unwrap();
        assert!(eng.store.filters_of(uid).unwrap().is_empty());
        assert_eq!(umbrella(&eng.store).unwrap().state, State::Confirmed);
        assert!(eng
            .store
            .history_of(uid)
            .unwrap()
            .iter()
            .any(|x| x.1 == "child_expired"));
        // 지난 기한은 거부
        assert!(try_block(&mut eng, &t_for(exe), NOW).is_err());
    }
    assert!(wfp.filters.is_empty(), "만료 뒤 WFP 필터도 없다");
}

#[test]
fn umbrella_auto_rollback_pause_and_off_stop_blocking() {
    let exe = r"C:\Users\u\Downloads\a.exe";
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(NOW);
    {
        let mut eng = new_engine(&mut wfp, &clock);
        // F19: 확인 없이 60초 → 자동 롤백 → 막지 않음
        sync_umbrella(&mut eng, Mode::Block, RID, ADMIN)
            .unwrap()
            .unwrap();
        clock.advance(61);
        eng.tick().unwrap();
        assert_eq!(umbrella(&eng.store).unwrap().state, State::RolledBack);
        assert!(try_block(&mut eng, &t_for(exe), NOW + 600).is_err());
        // 다시 block → 새 판으로 확인 대기
        let r = sync_umbrella(
            &mut eng,
            Mode::Block,
            "2f3c2a1e-9b7d-4c6a-8e5f-123456789abc",
            ADMIN,
        )
        .unwrap()
        .expect("되돌린 뒤 다시 적용");
        assert_eq!(r.version, 2);
        eng.confirm(r.policy_id, r.version, ADMIN).unwrap();
        try_block(&mut eng, &t_for(exe), NOW + 600).unwrap();
        // 일시 정지 → 그 아래 필터도 내려가고 새 차단 없음
        eng.pause(r.policy_id, ADMIN).unwrap();
        assert!(eng.store.filters_of(r.policy_id).unwrap().is_empty());
        assert!(try_block(&mut eng, &t_for(r"C:\Users\u\Downloads\b.exe"), NOW + 600).is_err());
        // 다시 block 을 고르면 새 판(확인 필요)
        let r = sync_umbrella(
            &mut eng,
            Mode::Block,
            "3f3c2a1e-9b7d-4c6a-8e5f-123456789abc",
            ADMIN,
        )
        .unwrap()
        .unwrap();
        eng.confirm(r.policy_id, r.version, ADMIN).unwrap();
        try_block(&mut eng, &t_for(exe), NOW + 600).unwrap();
        // block → off: 우산과 그 아래 필터 정리
        assert!(sync_umbrella(
            &mut eng,
            Mode::Off,
            "4f3c2a1e-9b7d-4c6a-8e5f-123456789abc",
            ADMIN
        )
        .unwrap()
        .is_none());
        assert!(umbrella(&eng.store).is_none(), "지운 우산은 남지 않는다");
        assert!(eng.store.filters_of(r.policy_id).unwrap().is_empty());
        let h = eng.store.history_of(r.policy_id).unwrap();
        assert!(h.iter().any(|x| x.1 == "remove" && x.3 == ADMIN), "{h:?}");
    }
    assert!(wfp.filters.is_empty());
}

#[test]
fn unsigned_installer_is_blocked_but_system_image_and_our_service_are_not() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(NOW);
    {
        let mut eng = new_engine(&mut wfp, &clock);
        let r = sync_umbrella(&mut eng, Mode::Block, RID, ADMIN)
            .unwrap()
            .unwrap();
        eng.confirm(r.policy_id, r.version, ADMIN).unwrap();
        // L062(30차 Q2): 서명 없는 "설치 프로그램" 이름은 막기 면제가 아니다
        let ok = try_block(
            &mut eng,
            &t_for(r"C:\Users\u\Downloads\FooSetup.exe"),
            NOW + 600,
        );
        assert!(ok.is_ok(), "{ok:?}");
        // 이 설치 프로그램 차단 필터(주소 체계별) — 아래 거부들은 이 수를 늘리지 않는다
        let foo_filters = eng.store.filters_of(r.policy_id).unwrap().len();
        assert!(foo_filters > 0);
        let e = try_block(
            &mut eng,
            &t_for(r"C:\Windows\System32\svchost.exe"),
            NOW + 600,
        )
        .unwrap_err();
        assert!(e.contains("시스템 핵심"), "{e}");
        let e = try_block(
            &mut eng,
            &t_for(r"C:\Users\u\Downloads\story-firewall-svc.exe"),
            NOW + 600,
        )
        .unwrap_err();
        assert!(e.contains("보호 규칙"), "{e}");
        // 엔진도 따로 막는다: 경로 없는 명세·시스템 이미지
        let wide = policy::spec::BlockSpec {
            app_path: None,
            ..policy::spec::BlockSpec::app("x", r"C:\a.exe", policy::spec::Direction::Out)
        };
        assert!(eng
            .add_child_blocks(r.policy_id, &[wide], NOW + 600, "t", "")
            .is_err());
        let sys = policy::spec::BlockSpec::app(
            "x",
            r"C:\Windows\explorer.exe",
            policy::spec::Direction::Out,
        );
        assert!(matches!(
            eng.add_child_blocks(r.policy_id, &[sys], NOW + 600, "t", ""),
            Err(engine::EngineError::Guard(_))
        ));
        assert_eq!(
            eng.store.filters_of(r.policy_id).unwrap().len(),
            foo_filters
        );
    }
    assert_eq!(
        wfp.filters.len(),
        2,
        "서명 없는 설치 프로그램 차단(V4·V6)만 남는다"
    );
}

/// L062(30차 Q5): 인터넷에서 받은 파일인데 서명 확인 결과가 끝내 오지 않으면(실행 직후 파일 삭제 등) 마지막 판단에서 대상으로
#[test]
fn downloaded_with_unknown_signature_becomes_target_at_expiry() {
    let st = store();
    let mut ing = Ingester::new(&st);
    let exe = r"C:\Users\u\Downloads\gone.exe";
    ing.ingest(&start(40, exe, T + 1)).unwrap();
    ing.ingest(&motw(exe, 3)).unwrap();
    let p = proc_node(&st, 40, T + 1);
    let none = HashSet::new();
    assert_eq!(
        assess(&st, &none, p),
        Assess::Pending,
        "보류 중에는 기다린다"
    );
    let t = target(assess_at_expiry(&st, &none, p));
    assert_eq!(t.sig, SigFact::Unknown);
    // 인터넷 표시가 없는 파일은 마지막에도 대상 아님
    let local = r"C:\Tools\local.exe";
    ing.ingest(&start(41, local, T + 2)).unwrap();
    let p2 = proc_node(&st, 41, T + 2);
    assert!(!matches!(
        assess_at_expiry(&st, &none, p2),
        Assess::Target(_)
    ));
}

/// L065(30차 Q7-a): 서명 없는 파일 수백 개를 풀어도 우산 아래 필터는 상한에서 멈추고 알림만 한다
#[test]
fn umbrella_child_filters_are_capped() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(NOW);
    let mut eng = new_engine(&mut wfp, &clock);
    let r = sync_umbrella(&mut eng, Mode::Block, RID, ADMIN)
        .unwrap()
        .expect("우산 적용");
    eng.confirm(r.policy_id, r.version, ADMIN).unwrap();
    let cap = svc::first_run::UMBRELLA_FILTER_CAP;
    let mut blocked = 0;
    for i in 0..cap {
        let p = format!(r"C:\Users\u\Downloads\drop{i}.exe");
        match try_block(&mut eng, &t_for(&p), NOW + 600) {
            Ok(_) => blocked += 1,
            Err(e) => {
                assert!(e.contains("동시에 막을 수 있는 수"), "{e}");
                break;
            }
        }
    }
    assert_eq!(blocked, cap / 2, "실행 파일 하나 = 필터 2개");
    assert_eq!(eng.store.filters_of(r.policy_id).unwrap().len(), cap);
    // 기한이 지나 풀리면 다시 막을 수 있다
    clock.advance(601);
    eng.tick().unwrap();
    assert!(try_block(
        &mut eng,
        &t_for(r"C:\Users\u\Downloads\late.exe"),
        NOW + 1200
    )
    .is_ok());
}

fn write(pid: u32, path: &str, ts: i64) -> Event {
    ev(
        ts,
        EventKind::FileWrite {
            proc: graph::event::ProcRef::new(pid, None),
            path: path.into(),
        },
    )
}
fn hash(path: &str, sha: &str, ts: i64) -> Event {
    ev(
        ts,
        EventKind::FileHash {
            path: path.into(),
            sha256: Some(sha.into()),
            size: 100,
            note: None,
        },
    )
}

/// L068(30차 Q6): 같은 경로를 덮어쓰면 새 내용의 첫 실행으로 다시 본다. 같은 새 내용의 두 번째 실행은 아니다
#[test]
fn overwritten_same_path_is_first_run_again() {
    let st = store();
    let mut ing = Ingester::new(&st);
    let none = HashSet::new();
    let exe = r"C:\Users\u\Downloads\tool.exe";
    ing.ingest_all(&[
        start(20, exe, T + 1),
        sig(exe, "nosignature", None),
        motw(exe, 3),
    ])
    .unwrap();
    assert!(matches!(
        assess(&st, &none, proc_node(&st, 20, T + 1)),
        Assess::Target(_)
    ));
    // 두 번째 실행(내용 그대로) → 아님
    ing.ingest(&start(21, exe, T + 100)).unwrap();
    assert_eq!(
        assess(&st, &none, proc_node(&st, 21, T + 100)),
        Assess::Skip("전에 실행된 적 있음")
    );
    // 다른 프로그램(pid 10 탐색기 아래)이 같은 경로를 덮어씀 → 그 뒤 실행은 다시 처음
    ing.ingest(&write(10, exe, T + 200)).unwrap();
    ing.ingest(&start(22, exe, T + 300)).unwrap();
    let t = target(assess(&st, &none, proc_node(&st, 22, T + 300)));
    assert_eq!(t.content_ts, T + 200, "내용 판 = 마지막 쓰기 시각");
    // 같은 새 내용의 다음 실행 → 아님
    ing.ingest(&start(23, exe, T + 400)).unwrap();
    assert_eq!(
        assess(&st, &none, proc_node(&st, 23, T + 400)),
        Assess::Skip("전에 실행된 적 있음")
    );
}

/// 쓰기 선이 빠져도(수집 손실) 관찰 때 해시와 지금 해시가 다르면 다시 대상이고, 이미 관찰한 것으로 치지 않는다
#[test]
fn hash_change_without_write_edge_is_first_run_again() {
    let st = store();
    svc::first_run::ensure_table(&st);
    let mut ing = Ingester::new(&st);
    let none = HashSet::new();
    let exe = r"C:\Users\u\Downloads\tool2.exe";
    ing.ingest_all(&[
        start(30, exe, T + 1),
        sig(exe, "nosignature", None),
        motw(exe, 3),
        hash(exe, "aaaa", T + 2),
    ])
    .unwrap();
    let t1 = target(assess(&st, &none, proc_node(&st, 30, T + 1)));
    assert_eq!(t1.sha256.as_deref(), Some("aaaa"));
    // 관찰 기록(처음 내용)
    st.conn()
        .execute(
            "INSERT INTO first_run_watch(file_key, file_node, proc_node, start_ts, until_ts, minutes, mode, blocked, installer, sig, host, content_ts, sha256)
             VALUES (lower(?1), ?2, ?3, 0, 600, 10, 'notify', 0, 0, 'none', NULL, 0, 'aaaa')",
            rusqlite::params![exe, t1.file_node, t1.proc_node],
        )
        .unwrap();
    assert!(svc::first_run::already_watched(&st, exe, 0, Some("aaaa")));
    // 내용이 바뀜(해시 다름, 쓰기 선 없음) → 다음 실행은 대상, 이미 관찰한 것 아님
    ing.ingest(&hash(exe, "bbbb", T + 50)).unwrap();
    ing.ingest(&start(31, exe, T + 100)).unwrap();
    let t2 = target(assess(&st, &none, proc_node(&st, 31, T + 100)));
    assert_eq!(t2.sha256.as_deref(), Some("bbbb"));
    assert!(!svc::first_run::already_watched(
        &st,
        exe,
        t2.content_ts,
        Some("bbbb")
    ));
    // 해시를 모르면(계산 실패) 이미 관찰한 것으로 본다(알림 폭주 방지)
    assert!(svc::first_run::already_watched(&st, exe, 0, None));
}

/// 31차 Gemini Q1: 쓰기·이름 바꾸기 선 없이(블록 복제 등) 내용을 바꾼 뒤 실행 — 이번 실행 뒤 해시가 오기 전에는 "전에 실행됨"으로 버리지 않고 기다린다
#[test]
fn rerun_of_watched_path_waits_for_fresh_hash() {
    let st = store();
    svc::first_run::ensure_table(&st);
    let mut ing = Ingester::new(&st);
    let none = HashSet::new();
    let exe = r"C:\Users\u\Downloads\tool3.exe";
    ing.ingest_all(&[
        start(40, exe, T + 1),
        sig(exe, "nosignature", None),
        motw(exe, 3),
        hash(exe, "aaaa", T + 2),
    ])
    .unwrap();
    let t1 = target(assess(&st, &none, proc_node(&st, 40, T + 1)));
    st.conn()
        .execute(
            "INSERT INTO first_run_watch(file_key, file_node, proc_node, start_ts, until_ts, minutes, mode, blocked, installer, sig, host, content_ts, sha256)
             VALUES (lower(?1), ?2, ?3, 0, 600, 10, 'notify', 0, 0, 'none', NULL, 0, 'aaaa')",
            rusqlite::params![exe, t1.file_node, t1.proc_node],
        )
        .unwrap();
    // 다시 실행, 해시는 아직 지난번 것뿐 → 기다림
    ing.ingest(&start(41, exe, T + 100)).unwrap();
    assert_eq!(
        assess(&st, &none, proc_node(&st, 41, T + 100)),
        Assess::Pending
    );
    // 33차 Q5: 대기 시간이 지나도 안 오면 "모르는 내용" — 다시 관찰(이번 실행이 새 내용 판, 이미 관찰한 것으로 치지 않음)
    let tu = target(svc::first_run::assess_at_expiry(
        &st,
        &none,
        proc_node(&st, 41, T + 100),
    ));
    assert!(tu.hash_unverified);
    assert_eq!(tu.sha256, None);
    assert_eq!(tu.content_ts, T + 100);
    assert!(!svc::first_run::already_watched(
        &st,
        exe,
        tu.content_ts,
        None
    ));
    // 같은 해시가 오면 → 전에 실행됨
    ing.ingest(&hash(exe, "aaaa", T + 101)).unwrap();
    assert_eq!(
        assess(&st, &none, proc_node(&st, 41, T + 100)),
        Assess::Skip("전에 실행된 적 있음")
    );
    // 다음 실행에서 다른 해시가 오면 → 대상
    ing.ingest(&start(42, exe, T + 200)).unwrap();
    assert_eq!(
        assess(&st, &none, proc_node(&st, 42, T + 200)),
        Assess::Pending
    );
    ing.ingest(&hash(exe, "bbbb", T + 201)).unwrap();
    assert!(matches!(
        assess(&st, &none, proc_node(&st, 42, T + 200)),
        Assess::Target(_)
    ));
}
