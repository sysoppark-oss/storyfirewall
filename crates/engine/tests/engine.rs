//! A11 통과 기준 (10차 2-7): apply→confirm→rollback, 60초 자동 롤백, 중간 실패, 재시작 대조, 스케줄 경계·자정 넘김,
//! 만료, 틈 메우기(상한), 서킷 브레이커, excluded_system 주소 차단(24시간·즉시 해제), 멱등 키.

use dsl::expand::Resolver;
use engine::backend::{FakeWfp, GraphQuery, NoGraph};
use engine::clock::FakeClock;
use engine::{
    Engine, EngineError, State, BREAKER_MAX, EXCLUDED_ADDR_TTL_SECS, MAX_FILTERS_PER_POLICY,
};

struct R;
impl Resolver for R {
    fn list_exes(&self, dir: &str) -> Vec<String> {
        if dir.to_ascii_lowercase().contains("tools") {
            vec![format!("{dir}\\a.exe"), format!("{dir}\\b.exe")]
        } else {
            vec![]
        }
    }
    fn descendants(&self, file_path: &str, _sha: &str) -> Result<Vec<String>, String> {
        Ok(vec![
            file_path.to_string(),
            r"C:\Users\pjg\AppData\Local\Temp\dropper.exe".into(),
            r"C:\Windows\System32\svchost.exe".into(),
        ])
    }
    fn exists(&self, _: &str) -> bool {
        true
    }
}

struct G;
impl GraphQuery for G {
    fn event_addresses_of(&self, image: &str) -> Vec<(String, u16, u8)> {
        if image.to_ascii_lowercase().ends_with("svchost.exe") {
            vec![
                ("203.0.113.9".into(), 443, 6),
                ("203.0.113.10".into(), 8443, 6),
            ]
        } else {
            vec![]
        }
    }
}

const SIMPLE: &str = "- name: block-b\n  action: block\n  match: { direction: out, process: ['C:/Program Files/B/b.exe'] }\n";
const WILD: &str =
    "- name: tools\n  action: block\n  match: { direction: out, process: ['C:/Tools/*'] }\n";
const CUT: &str = "- name: cut\n  action: block\n  match: { direction: both, descendants_of: 'file:C:/Users/pjg/Downloads/invoice.exe#sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' }\n  also: [terminate]\n";
// 2024-01-01 00:00 (월요일) 로컬. 1970-01-01 목요일 기준 19723일 뒤 → 월요일
const MONDAY_0000: i64 = 19_723 * 86_400;

fn conn() -> rusqlite::Connection {
    rusqlite::Connection::open_in_memory().unwrap()
}

#[test]
fn apply_confirm_rollback_roundtrip_and_idempotency() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000);
    let mut e = Engine::new(
        conn(),
        &mut wfp,
        &NoGraph,
        &clock,
        &R,
        &["story-firewall-svc.exe"],
    )
    .unwrap();
    let r = e.apply(SIMPLE, &[], "req-1", "ui").unwrap();
    // 프로그램 하나(주소 조건 없음) = V4·V6 필터 2개 (A26: 가짜 백엔드도 실제 WFP 처럼 센다)
    assert_eq!((r.policy_id, r.version, r.filters), (1, 1, 2));
    assert_eq!(r.confirm_deadline, MONDAY_0000 + 60);
    // 멱등: 같은 request_id 는 같은 결과, 필터 추가 없음
    let again = e.apply(SIMPLE, &[], "req-1", "ui").unwrap();
    assert_eq!(again.version, 1);
    assert_eq!(e.store.filters_of(1).unwrap().len(), 2);
    e.confirm(1, 1, "ui").unwrap();
    assert_eq!(e.store.policy(1).unwrap().unwrap().state, State::Confirmed);
    // 2판: 다른 조건
    let r2 = e
        .apply(
            SIMPLE.replace("b.exe", "c.exe").as_str(),
            &[],
            "req-2",
            "ui",
        )
        .unwrap();
    assert_eq!((r2.policy_id, r2.version), (1, 2));
    // 2판 적용 시 1판 필터는 내려가야 한다 (판 겹침 금지)
    let f2 = e.store.filters_of(1).unwrap();
    assert_eq!(f2.len(), 2, "{f2:?}");
    assert!(f2
        .iter()
        .all(|f| f.spec.app_path.as_deref().unwrap().ends_with("c.exe")));
    e.confirm(1, 2, "ui").unwrap();
    // 1판으로 롤백
    e.rollback(1, Some(1), "ui").unwrap();
    let f = e.store.filters_of(1).unwrap();
    assert_eq!(f.len(), 2);
    assert!(f
        .iter()
        .all(|f| f.spec.app_path.as_deref().unwrap().ends_with("b.exe")));
    assert_eq!(e.store.policy(1).unwrap().unwrap().version, 1);
    // 제거
    e.rollback(1, None, "ui").unwrap();
    assert!(e.store.filters_of(1).unwrap().is_empty());
    assert_eq!(e.store.policy(1).unwrap().unwrap().state, State::RolledBack);
    let hist: Vec<String> = e
        .store
        .history_of(1)
        .unwrap()
        .into_iter()
        .map(|h| h.1)
        .collect();
    assert_eq!(
        hist,
        vec!["apply", "confirm", "apply", "confirm", "rollback", "rollback"]
    );
}

#[test]
fn unconfirmed_policy_auto_rolls_back_after_60s() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000);
    let mut e = Engine::new(conn(), &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
    e.apply(SIMPLE, &[], "r", "ui").unwrap();
    clock.advance(59);
    e.tick().unwrap();
    assert_eq!(e.store.policy(1).unwrap().unwrap().state, State::Applied);
    clock.advance(1);
    e.tick().unwrap();
    assert_eq!(e.store.policy(1).unwrap().unwrap().state, State::RolledBack);
    assert!(e.store.filters_of(1).unwrap().is_empty());
    assert!(e.events.iter().any(|ev| ev.kind == "policy_auto_rollback"));
    assert!(e.confirm(1, 1, "ui").is_err(), "되돌린 뒤 confirm 불가");
}

#[test]
fn backend_failure_leaves_nothing() {
    let mut wfp = FakeWfp {
        fail_on_call: Some(1),
        ..Default::default()
    };
    let clock = FakeClock::new(MONDAY_0000);
    let mut e = Engine::new(conn(), &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
    let r = e.apply(SIMPLE, &[], "r", "ui");
    assert!(matches!(r, Err(EngineError::Backend(_))), "{r:?}");
    assert!(e.store.all_filters().unwrap().is_empty());
}

#[test]
fn needs_ack_then_ack_and_guard_rejects() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000);
    let mut e = Engine::new(conn(), &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
    let wide = "- name: wide\n  action: block\n  match: { direction: out }\n";
    let r = e.apply(wide, &[], "r1", "ui");
    assert!(matches!(r, Err(EngineError::NeedsAck(_))), "{r:?}");
    let ok = e.apply(wide, &[("wide".into(), dsl::Ack::Wide)], "r2", "ui");
    // 전체 차단은 가드가 마지막에 거부한다 (PoC·제품 모두)
    assert!(matches!(ok, Err(EngineError::Guard(_))), "{ok:?}");
}

#[test]
fn schedule_window_adds_and_removes_filters_with_midnight_wrap() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000 + 12 * 3600); // 월 12:00
    let mut e = Engine::new(conn(), &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
    let night = "- name: night\n  action: block\n  match: { direction: out, process: ['C:/Program Files/B/b.exe'] }\n  when: { time: '22:00-06:00', days: [mon, tue] }\n";
    let r = e.apply(night, &[], "r", "ui").unwrap();
    assert_eq!(r.filters, 0, "구간 밖이면 필터를 넣지 않는다");
    e.confirm(1, 1, "ui").unwrap();
    clock.advance(10 * 3600); // 월 22:00
    e.tick().unwrap();
    assert_eq!(
        e.store.filters_of(1).unwrap().len(),
        2,
        "22:00 에 넣는다 (V4·V6)"
    );
    clock.advance(5 * 3600); // 화 03:00 (자정 넘김)
    e.tick().unwrap();
    assert_eq!(e.store.filters_of(1).unwrap().len(), 2, "자정 넘겨도 유지");
    clock.advance(3 * 3600); // 화 06:00
    e.tick().unwrap();
    assert!(e.store.filters_of(1).unwrap().is_empty(), "06:00 에 뺀다");
    clock.advance(16 * 3600); // 화 22:00
    e.tick().unwrap();
    assert_eq!(e.store.filters_of(1).unwrap().len(), 2);
    clock.advance(24 * 3600); // 수 22:00 — days 에 없음
    e.tick().unwrap();
    assert!(
        e.store.filters_of(1).unwrap().is_empty(),
        "수요일은 구간 아님"
    );
    // 벽시계만 뛰어도(사용자가 시각 변경) 경계 판정은 벽시계 기준으로 다시 맞춘다
    clock.jump_wall(-24 * 3600); // 화 22:00 으로 되돌림
    e.tick().unwrap();
    assert_eq!(e.store.filters_of(1).unwrap().len(), 2);
}

#[test]
fn expiry_removes_and_notifies() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000);
    let mut e = Engine::new(conn(), &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
    let p = "- name: patch\n  action: block\n  match: { direction: in, process: ['C:/Program Files/B/b.exe'], local_port: [445] }\n  expires: 2h\n  on_expire: notify\n";
    e.apply(p, &[], "r", "ui").unwrap();
    e.confirm(1, 1, "ui").unwrap();
    clock.advance(2 * 3600 - 600);
    e.tick().unwrap();
    assert!(
        e.events.iter().any(|ev| ev.kind == "policy_expiring"),
        "10분 전 알림"
    );
    clock.advance(600);
    e.tick().unwrap();
    assert_eq!(e.store.policy(1).unwrap().unwrap().state, State::Expired);
    assert!(e.store.filters_of(1).unwrap().is_empty());
    assert!(e.events.iter().any(|ev| ev.kind == "policy_expired"));
}

#[test]
fn gap_filling_adds_filters_for_new_processes_and_respects_limit() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000);
    let mut e = Engine::new(conn(), &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
    let r = e.apply(WILD, &[], "r", "ui").unwrap();
    assert_eq!(r.filters, 4, "실행 파일 2개 × V4·V6");
    e.confirm(1, 1, "ui").unwrap();
    // 새로 생긴 실행 파일
    let t = e
        .on_process_start(10, r"C:\Tools\new.exe", r"C:\Windows\explorer.exe")
        .unwrap();
    assert!(t.is_empty(), "terminate 없음");
    assert_eq!(
        e.store.filters_of(1).unwrap().len(),
        6,
        "보충 1개 = 필터 2개"
    );
    assert_eq!(
        e.store.policy(1).unwrap().unwrap().version,
        1,
        "버전은 안 올라간다"
    );
    // 같은 파일 다시 → 중복 없음
    e.on_process_start(11, r"C:\Tools\new.exe", r"C:\Windows\explorer.exe")
        .unwrap();
    assert_eq!(e.store.filters_of(1).unwrap().len(), 6);
    // 디렉터리 밖 → 무시
    e.on_process_start(12, r"C:\Other\x.exe", r"C:\Windows\explorer.exe")
        .unwrap();
    assert_eq!(e.store.filters_of(1).unwrap().len(), 6);
    // 롤백하면 보충분도 함께 사라진다
    e.rollback(1, None, "ui").unwrap();
    assert!(e.store.all_filters().unwrap().is_empty());

    // 끊기: 자손의 자손, terminate, 시스템 프로세스 제외, 상한
    let r = e.apply(CUT, &[], "r2", "ui").unwrap();
    assert!(r.warnings.iter().any(|w| w.contains("[4]")));
    e.confirm(r.policy_id, 1, "ui").unwrap();
    let t = e
        .on_process_start(
            20,
            r"C:\Users\pjg\AppData\Local\Temp\child.exe",
            r"C:\Users\pjg\AppData\Local\Temp\dropper.exe",
        )
        .unwrap();
    assert_eq!(t, vec![20], "also: terminate");
    let t = e
        .on_process_start(
            21,
            r"C:\Users\pjg\AppData\Local\Temp\grandchild.exe",
            r"C:\Users\pjg\AppData\Local\Temp\child.exe",
        )
        .unwrap();
    assert_eq!(t, vec![21], "자손의 자손도");
    let t = e
        .on_process_start(
            22,
            r"C:\Windows\explorer.exe",
            r"C:\Users\pjg\AppData\Local\Temp\child.exe",
        )
        .unwrap();
    assert!(t.is_empty(), "시스템 프로세스는 보충·종료하지 않는다");
    let before = e.store.filters_of(r.policy_id).unwrap().len();
    for i in 0..MAX_FILTERS_PER_POLICY {
        e.on_process_start(
            1000 + i as u32,
            &format!(r"C:\Users\pjg\AppData\Local\Temp\c{i}.exe"),
            r"C:\Users\pjg\AppData\Local\Temp\dropper.exe",
        )
        .unwrap();
    }
    let after = e.store.filters_of(r.policy_id).unwrap().len();
    assert!(
        after <= MAX_FILTERS_PER_POLICY && after > MAX_FILTERS_PER_POLICY - 2,
        "상한에서 멈춘다, 넘지 않는다 (before {before}, after {after})"
    );
    assert!(e.events.iter().any(|ev| ev.kind == "policy_fill_limit"));
}

#[test]
fn self_heal_with_circuit_breaker_never_stops() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000);
    let mut e = Engine::new(conn(), &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
    e.apply(SIMPLE, &[], "r", "ui").unwrap();
    e.confirm(1, 1, "ui").unwrap();
    // 외부 삭제 5회: 즉시 재등록
    for _ in 0..BREAKER_MAX {
        let id = e.store.filters_of(1).unwrap()[0].filter_id;
        e.on_filter_deleted(id).unwrap();
        let now = e.store.filters_of(1).unwrap();
        assert_eq!(
            now.len(),
            2,
            "지워진 한 체계만 다시 넣는다 (V4·V6 중 하나 — 중복 없음)"
        );
        assert!(
            !now.iter().any(|f| f.filter_id == id),
            "새 필터 ID 로 재등록"
        );
        clock.advance(1);
    }
    assert!(
        e.events
            .iter()
            .filter(|ev| ev.kind == "policy_tampered")
            .count()
            >= BREAKER_MAX
    );
    // 6회째: 백오프 (즉시 재등록 안 됨)
    let id = e.store.filters_of(1).unwrap()[0].filter_id;
    e.on_filter_deleted(id).unwrap();
    assert_eq!(
        e.store.filters_of(1).unwrap()[0].filter_id,
        id,
        "아직 재등록 전 (DB 행은 남아 있음)"
    );
    assert!(e.events.iter().any(|ev| ev.kind == "policy_tamper_backoff"));
    e.tick().unwrap();
    assert_eq!(
        e.store.filters_of(1).unwrap()[0].filter_id,
        id,
        "1초 전에는 재등록 안 함"
    );
    clock.advance(1);
    e.tick().unwrap();
    assert_ne!(
        e.store.filters_of(1).unwrap()[0].filter_id,
        id,
        "백오프 뒤 재등록 — 멈추지 않는다"
    );
    // 우리가 지우는 중(rollback)은 변조가 아니다
    let n = e.events.len();
    e.rollback(1, None, "ui").unwrap();
    assert_eq!(e.events.len(), n);
    // 일시 중지 뒤에는 재등록하지 않는다
    e.apply(SIMPLE, &[], "r3", "ui").unwrap();
    e.confirm(1, 2, "ui").unwrap();
    e.pause(1, "ui").unwrap();
    assert!(e.store.filters_of(1).unwrap().is_empty());
    assert_eq!(e.store.policy(1).unwrap().unwrap().state, State::Paused);
}

#[test]
fn reconcile_restores_missing_and_removes_orphans() {
    let clock = FakeClock::new(MONDAY_0000);
    let mut wfp = FakeWfp::default();
    let dir = std::env::temp_dir().join(format!("engine-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("engine.db");
    let _ = std::fs::remove_file(&path);
    let ids: Vec<u64> = {
        let mut e = Engine::new(
            rusqlite::Connection::open(&path).unwrap(),
            &mut wfp,
            &NoGraph,
            &clock,
            &R,
            &[],
        )
        .unwrap();
        e.apply(WILD, &[], "r", "ui").unwrap();
        e.confirm(1, 1, "ui").unwrap();
        e.store
            .filters_of(1)
            .unwrap()
            .iter()
            .map(|f| f.filter_id)
            .collect()
    };
    // 서비스가 내려간 사이: 필터 하나 외부 삭제 + 고아 하나 심기
    assert!(wfp.external_delete(ids[0]));
    let orphan = wfp.plant_orphan(policy::spec::BlockSpec::app(
        "orphan",
        r"C:\x\y.exe",
        policy::spec::Direction::Out,
    ));
    // 재시작
    let mut e = Engine::new(
        rusqlite::Connection::open(&path).unwrap(),
        &mut wfp,
        &NoGraph,
        &clock,
        &R,
        &[],
    )
    .unwrap();
    let (restored, orphans) = e.reconcile().unwrap();
    assert_eq!((restored, orphans), (1, 1));
    assert!(e
        .events
        .iter()
        .any(|ev| ev.kind == "orphan_filters_removed"));
    assert!(e.events.iter().any(|ev| ev.kind == "policy_restored"));
    let live: Vec<u64> = e
        .store
        .all_filters()
        .unwrap()
        .iter()
        .map(|f| f.filter_id)
        .collect();
    assert_eq!(live.len(), 4);
    assert!(!live.contains(&ids[0]) && live.contains(&ids[1]));
    assert!(!live.contains(&orphan));
    // 열린 조건도 복원돼 보충이 된다
    e.on_process_start(5, r"C:\Tools\late.exe", r"C:\Windows\explorer.exe")
        .unwrap();
    assert_eq!(e.store.filters_of(1).unwrap().len(), 6);
    drop(e);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn excluded_system_turns_into_address_blocks_with_ttl_and_release() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000);
    let mut e = Engine::new(conn(), &mut wfp, &G, &clock, &R, &[]).unwrap();
    let r = e.apply(CUT, &[], "r", "ui").unwrap();
    assert!(r.address_block_notice.is_some(), "10차 Q4 경고문");
    assert!(r.warnings.iter().any(|w| w.contains("주소 차단")));
    let f = e.store.filters_of(r.policy_id).unwrap();
    let addr: Vec<_> = f.iter().filter(|x| x.spec.app_path.is_none()).collect();
    assert_eq!(addr.len(), 2, "svchost 의 사건 주소 2곳");
    assert!(addr
        .iter()
        .all(|x| x.expires_at == Some(MONDAY_0000 + EXCLUDED_ADDR_TTL_SECS)));
    assert!(addr
        .iter()
        .all(|x| x.spec.remote_ports.len() == 1 && x.spec.protocols == vec![6]));
    e.confirm(r.policy_id, 1, "ui").unwrap();
    // 24시간 뒤 주소 차단만 사라진다
    clock.advance(EXCLUDED_ADDR_TTL_SECS);
    e.tick().unwrap();
    let f = e.store.filters_of(r.policy_id).unwrap();
    assert!(f.iter().all(|x| x.spec.app_path.is_some()));
    assert!(e.events.iter().any(|ev| ev.kind == "address_block_expired"));
    // 1판으로 롤백해도 지난 주소 차단은 되살아나지 않는다 (영구 차단 방지)
    e.rollback(r.policy_id, Some(1), "ui").unwrap();
    let f = e.store.filters_of(r.policy_id).unwrap();
    assert!(
        f.iter().all(|x| x.spec.app_path.is_some()),
        "기한 지난 주소 차단 재설치 금지"
    );
    // 즉시 해제
    let r2 = e
        .apply(CUT.replace("cut", "cut2").as_str(), &[], "r2", "ui")
        .unwrap();
    assert!(
        e.store
            .filters_of(r2.policy_id)
            .unwrap()
            .iter()
            .filter(|x| x.expires_at.is_some())
            .all(|x| x.expires_at
                == Some(MONDAY_0000 + 2 * EXCLUDED_ADDR_TTL_SECS / 2 + EXCLUDED_ADDR_TTL_SECS)),
        "새 판 기한은 그 판 시각 기준"
    );
    assert_eq!(e.release_address_blocks(r2.policy_id, "ui").unwrap(), 2);
    assert!(e
        .store
        .filters_of(r2.policy_id)
        .unwrap()
        .iter()
        .all(|x| x.spec.app_path.is_some()));
    // 27차: policy_id 0 = 모든 정책의 주소 차단(전에는 0건 — UI "주소 차단 모두 해제"가 아무것도 풀지 못했다)
    let r3 = e
        .apply(CUT.replace("cut", "cut3").as_str(), &[], "r3", "ui")
        .unwrap();
    assert_eq!(e.address_block_count().unwrap(), 2);
    assert_eq!(e.release_address_blocks(0, "ui").unwrap(), 2);
    assert_eq!(e.address_block_count().unwrap(), 0);
    assert!(e
        .store
        .filters_of(r3.policy_id)
        .unwrap()
        .iter()
        .all(|x| x.spec.app_path.is_some()));
    // D036: 주소 차단 하나만 해제. 프로그램 차단 필터는 이 경로로 풀 수 없다
    let r4 = e
        .apply(CUT.replace("cut", "cut4").as_str(), &[], "r4", "ui")
        .unwrap();
    let blocks = e.address_blocks().unwrap();
    assert_eq!(blocks.len(), 2);
    assert_eq!(
        e.release_address_block(blocks[0].filter_id, "ui").unwrap(),
        1
    );
    assert_eq!(e.address_block_count().unwrap(), 1);
    let prog = e
        .store
        .filters_of(r4.policy_id)
        .unwrap()
        .into_iter()
        .find(|x| x.expires_at.is_none())
        .unwrap();
    assert!(e.release_address_block(prog.filter_id, "ui").is_err());
}

// ---- 11차 반영 ----

#[test]
fn version_swap_is_one_transaction_and_failure_keeps_previous_version() {
    // 3번째 replace(= 2판 적용) 를 실패시킨다: 1=1판 적용, 2=?, 순서를 아래에서 맞춘다
    let mut wfp = FakeWfp {
        fail_on_call: Some(3),
        ..Default::default()
    };
    let clock = FakeClock::new(MONDAY_0000);
    {
        let mut e = Engine::new(conn(), &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
        e.apply(SIMPLE, &[], "r1", "ui").unwrap(); // replace #1
        e.confirm(1, 1, "ui").unwrap();
        e.apply(SIMPLE.replace("b.exe", "c.exe").as_str(), &[], "r2", "ui")
            .unwrap(); // replace #2: 1판→2판
        e.confirm(1, 2, "ui").unwrap();
        let r = e.apply(SIMPLE.replace("b.exe", "d.exe").as_str(), &[], "r3", "ui"); // replace #3: 실패
        assert!(matches!(r, Err(EngineError::Backend(_))), "{r:?}");
        let f = e.store.filters_of(1).unwrap();
        assert_eq!(f.len(), 2);
        assert!(
            f[0].spec.app_path.as_deref().unwrap().ends_with("c.exe"),
            "실패하면 직전 판(2판)이 그대로"
        );
        assert_eq!(e.store.policy(1).unwrap().unwrap().version, 2);
    }
    assert_eq!(wfp.filters.len(), 2, "BFE 에도 직전 판만 (V4·V6)");
    assert!(wfp
        .filters
        .values()
        .next()
        .unwrap()
        .app_path
        .as_deref()
        .unwrap()
        .ends_with("c.exe"));
    assert_eq!(
        wfp.log[1],
        (2, 2),
        "판 교체 = 지우기 2 + 넣기 2 를 한 번에 (보호 공백 없음)"
    );
}

#[test]
fn confirm_window_uses_monotonic_clock() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000);
    let mut e = Engine::new(conn(), &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
    e.apply(SIMPLE, &[], "r1", "ui").unwrap();
    // 벽시계를 1시간 앞으로 → 확인 창은 그대로(롤백 안 됨)
    clock.jump_wall(3600);
    e.tick().unwrap();
    assert_eq!(e.store.policy(1).unwrap().unwrap().state, State::Applied);
    // 벽시계를 2시간 뒤로 → 그래도 60초가 지나면 롤백 (창이 늘어나지 않음)
    clock.jump_wall(-7200);
    clock.advance(60);
    e.tick().unwrap();
    assert_eq!(e.store.policy(1).unwrap().unwrap().state, State::RolledBack);
    // 시한 지난 confirm 은 거부
    let mut wfp2 = FakeWfp::default();
    let clock2 = FakeClock::new(MONDAY_0000);
    let mut e2 = Engine::new(conn(), &mut wfp2, &NoGraph, &clock2, &R, &[]).unwrap();
    e2.apply(SIMPLE, &[], "r", "ui").unwrap();
    clock2.advance(60);
    assert!(e2.confirm(1, 1, "ui").is_err());
}

#[test]
fn restart_rolls_back_unconfirmed_policies() {
    let clock = FakeClock::new(MONDAY_0000);
    let mut wfp = FakeWfp::default();
    let dir = std::env::temp_dir().join(format!("engine-restart-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("e.db");
    let _ = std::fs::remove_file(&path);
    {
        let mut e = Engine::new(
            rusqlite::Connection::open(&path).unwrap(),
            &mut wfp,
            &NoGraph,
            &clock,
            &R,
            &[],
        )
        .unwrap();
        e.apply(SIMPLE, &[], "r", "ui").unwrap(); // 확인 전에 서비스가 죽음
    }
    assert_eq!(wfp.filters.len(), 2);
    let mut e = Engine::new(
        rusqlite::Connection::open(&path).unwrap(),
        &mut wfp,
        &NoGraph,
        &clock,
        &R,
        &[],
    )
    .unwrap();
    e.reconcile().unwrap();
    assert_eq!(e.store.policy(1).unwrap().unwrap().state, State::RolledBack);
    assert!(e.events.iter().any(|ev| ev.kind == "policy_auto_rollback"));
    drop(e);
    assert!(wfp.filters.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn next_wakeup_targets_the_schedule_boundary_and_events_reevaluate() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000 + 21 * 3600 + 59 * 60 + 20); // 월 21:59:20
    let mut e = Engine::new(conn(), &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
    let night = "- name: night\n  action: block\n  match: { direction: out, process: ['C:/Program Files/B/b.exe'] }\n  when: { time: '22:00-06:00' }\n";
    e.apply(night, &[], "r", "ui").unwrap();
    assert_eq!(
        e.next_wakeup().unwrap(),
        40,
        "확인 시한(60초)보다 경계(40초)가 먼저"
    );
    e.confirm(1, 1, "ui").unwrap();
    assert_eq!(e.next_wakeup().unwrap(), 40, "22:00 경계까지 40초");
    clock.advance(40);
    e.tick().unwrap();
    assert_eq!(
        e.store.filters_of(1).unwrap().len(),
        2,
        "경계 시각에 정확히 걸림"
    );
    assert_eq!(
        e.next_wakeup().unwrap(),
        60,
        "다음 경계(06:00)는 멀다 → 안전망 60초"
    );
    // 절전 중 06:00 을 지나 깨어남: 단조 시계는 멈췄고 벽시계만 감
    clock.jump_wall(9 * 3600);
    e.on_resume().unwrap();
    assert!(
        e.store.filters_of(1).unwrap().is_empty(),
        "깨어나자마자 구간 밖 → 뺌"
    );
    // 사용자가 시각을 22:30 으로 되돌림
    clock.jump_wall(-(8 * 3600 + 30 * 60));
    e.on_time_changed().unwrap();
    assert_eq!(e.store.filters_of(1).unwrap().len(), 2);
    assert!(e.events.iter().any(|ev| ev.kind == "time_changed"));
}

#[test]
fn history_tables_have_physical_caps() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000);
    let mut e = Engine::new(conn(), &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
    // 60판 적용 → policy_versions 는 최근 50판 + 현재 판만
    for i in 0..60 {
        e.apply(
            SIMPLE.replace("b.exe", &format!("b{i}.exe")).as_str(),
            &[],
            &format!("r{i}"),
            "ui",
        )
        .unwrap();
        e.confirm(1, i + 1, "ui").unwrap();
    }
    e.tick().unwrap();
    let versions: i64 = e
        .store
        .conn
        .query_row(
            "SELECT COUNT(*) FROM policy_versions WHERE policy_id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(versions <= 50, "{versions}");
    let cur: i64 = e
        .store
        .conn
        .query_row(
            "SELECT COUNT(*) FROM policy_versions WHERE policy_id = 1 AND version = 60",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(cur, 1, "현재 판은 남는다");
    // events 90일 상한
    for _ in 0..5 {
        e.store
            .insert_event(MONDAY_0000 - 100 * 86_400, "old", 0, "x")
            .unwrap();
    }
    e.tick().unwrap();
    let old: i64 = e
        .store
        .conn
        .query_row("SELECT COUNT(*) FROM events WHERE kind = 'old'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(old, 0);
}

/// 뿌리 파일이 사라진 뒤의 Resolver (격리·삭제). descendants_of 재전개가 실패한다.
struct Gone;
impl Resolver for Gone {
    fn list_exes(&self, _: &str) -> Vec<String> {
        vec![]
    }
    fn descendants(&self, _: &str, _: &str) -> Result<Vec<String>, String> {
        Err("파일 없음".into())
    }
    fn exists(&self, _: &str) -> bool {
        false
    }
}

/// A19 결함 수정: 재시작 때 열린 조건을 다시 전개하면 뿌리 파일이 격리된 경우 조용히 사라졌다.
/// 이제 판별로 저장한 조건을 복원한다.
#[test]
fn open_conds_survive_restart_even_when_root_file_is_gone() {
    let clock = FakeClock::new(MONDAY_0000);
    let mut wfp = FakeWfp::default();
    let dir = std::env::temp_dir().join(format!("engine-oc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("e.db");
    let _ = std::fs::remove_file(&path);
    {
        let mut e = Engine::new(
            rusqlite::Connection::open(&path).unwrap(),
            &mut wfp,
            &NoGraph,
            &clock,
            &R,
            &[],
        )
        .unwrap();
        let r = e.apply(CUT, &[], "r", "ui").unwrap();
        e.confirm(r.policy_id, r.version, "ui").unwrap();
    }
    // 재시작: 뿌리 파일은 격리돼 없음
    let mut e = Engine::new(
        rusqlite::Connection::open(&path).unwrap(),
        &mut wfp,
        &NoGraph,
        &clock,
        &Gone,
        &[],
    )
    .unwrap();
    e.reconcile().unwrap();
    let before = e.store.filters_of(1).unwrap().len();
    // 자손(dropper)이 새 자식을 띄우면 보충 + 종료 대상
    let kill = e
        .on_process_start(
            7777,
            r"C:\Users\pjg\AppData\Local\Temp\stage2.exe",
            r"C:\Users\pjg\AppData\Local\Temp\dropper.exe",
        )
        .unwrap();
    assert_eq!(kill, vec![7777], "재시작 뒤에도 also:terminate 유지");
    assert_eq!(
        e.store.filters_of(1).unwrap().len(),
        before + 2,
        "보충 1개 = V4·V6"
    );
    // 손자의 자식도 (뿌리 확장이 저장돼 다음 재시작에도 남는다)
    drop(e);
    let mut e = Engine::new(
        rusqlite::Connection::open(&path).unwrap(),
        &mut wfp,
        &NoGraph,
        &clock,
        &Gone,
        &[],
    )
    .unwrap();
    e.reconcile().unwrap();
    let kill = e
        .on_process_start(
            7778,
            r"C:\Users\pjg\AppData\Local\Temp\stage3.exe",
            r"C:\Users\pjg\AppData\Local\Temp\stage2.exe",
        )
        .unwrap();
    assert_eq!(kill, vec![7778]);
    drop(e);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 끊기(source=cut)는 descendants_of 없이 명시 목록만으로도 새 자손을 보충한다. 입력 YAML 로는 source 를 줄 수 없다.
#[test]
fn cut_source_with_explicit_list_fills_new_children() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000);
    let mut e = Engine::new(conn(), &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
    let y = "- name: cut-x\n  action: block\n  match: { direction: both, process: ['C:/Users/pjg/AppData/Local/Temp/payload.exe', 'C:/Windows/System32/cmd.exe'] }\n  also: [terminate]\n";
    // 같은 YAML 을 사용자 정책으로 넣으면 보충하지 않는다
    let r = e.apply(y, &[], "u", "ui").unwrap();
    assert!(e
        .on_process_start(
            10,
            r"C:\Temp\child.exe",
            r"C:\Users\pjg\AppData\Local\Temp\payload.exe"
        )
        .unwrap()
        .is_empty());
    e.rollback(r.policy_id, None, "ui").unwrap();
    // 끊기로 넣으면 보충 + 종료
    let r = e
        .apply_with_source(
            &y.replace("cut-x", "cut-y"),
            &[],
            "c",
            "ui",
            Some(dsl::model::Source::Cut),
        )
        .unwrap();
    e.confirm(r.policy_id, r.version, "ui").unwrap();
    assert_eq!(
        e.on_process_start(11, r"C:\Temp\child.exe", r"C:\Windows\System32\cmd.exe")
            .unwrap(),
        vec![11]
    );
    assert!(e.store.has_app(r.policy_id, r"C:\Temp\child.exe").unwrap());
    // 입력 YAML 의 source 는 거부 (서비스 전용)
    assert!(e
        .apply(
            &format!("{y}  source: cut\n").replace("cut-x", "cut-z"),
            &[],
            "z",
            "ui"
        )
        .is_err());
}

/// A19 결함 수정: 판 되돌리기(rollback to v) 뒤 그 판의 틈 메우기가 재시작 전까지 사라졌다.
#[test]
fn rollback_to_version_restores_that_versions_open_cond() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000);
    let mut e = Engine::new(conn(), &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
    let r1 = e.apply(WILD, &[], "1", "ui").unwrap();
    e.confirm(r1.policy_id, r1.version, "ui").unwrap();
    let r2 = e
        .apply(
            &WILD.replace("C:/Tools/*", "C:/Program Files/B/b.exe"),
            &[],
            "2",
            "ui",
        )
        .unwrap();
    e.confirm(r2.policy_id, r2.version, "ui").unwrap();
    // 2판은 와일드카드가 아니라 보충 없음
    let n = e.store.filters_of(r1.policy_id).unwrap().len();
    e.on_process_start(20, r"C:\Tools\new.exe", r"C:\Windows\explorer.exe")
        .unwrap();
    assert_eq!(e.store.filters_of(r1.policy_id).unwrap().len(), n);
    // 1판으로 되돌리면 C:\Tools\* 보충이 다시 동작
    e.rollback(r1.policy_id, Some(1), "ui").unwrap();
    let n = e.store.filters_of(r1.policy_id).unwrap().len();
    e.on_process_start(21, r"C:\Tools\new2.exe", r"C:\Windows\explorer.exe")
        .unwrap();
    assert_eq!(e.store.filters_of(r1.policy_id).unwrap().len(), n + 2);
}

/// A22 접점 결함: 벽시계는 UTC, 스케줄 요일·분만 로컬. 한국(UTC+9) PC 에서도 확인 시한은 UTC + 60초이고,
/// "평일 09:00~18:00" 스케줄은 로컬 09:00 에 켜진다.
#[test]
fn confirm_deadline_is_utc_and_schedule_uses_local_time() {
    let mut wfp = FakeWfp::default();
    // UTC 월요일 00:00 = 한국 월요일 09:00
    let clock = FakeClock::with_offset(MONDAY_0000, 9 * 3600);
    let mut e = Engine::new(conn(), &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
    let r = e.apply(SIMPLE, &[], "a", "ui").unwrap();
    assert_eq!(
        r.confirm_deadline,
        MONDAY_0000 + 60,
        "UI 로 나가는 시한은 UTC"
    );
    e.confirm(r.policy_id, r.version, "ui").unwrap();
    let sched = "- name: work\n  action: block\n  match: { direction: out, process: ['C:/Games/game.exe'] }\n  when: { days: [mon, tue, wed, thu, fri], time: '09:00-18:00' }\n";
    let r = e.apply(sched, &[], "b", "ui").unwrap();
    e.confirm(r.policy_id, r.version, "ui").unwrap();
    assert!(
        !e.store.filters_of(r.policy_id).unwrap().is_empty(),
        "로컬 09:00 → 켜짐 (UTC 로 보면 00:00 이라 꺼져 있어야 했을 것)"
    );
    // 로컬 18:00 (UTC 09:00) 에 꺼짐
    clock.advance(9 * 3600);
    e.tick().unwrap();
    assert!(e.store.filters_of(r.policy_id).unwrap().is_empty());
}

/// 21차 Q4: ip_family 가 없던 예전 형식의 행(명세 1개 = 행 1개 = 필터 1개)이 남아 있어도 재시작 대조가 정규화하고,
/// 이후 자가 치유·판 되돌리기·재대조가 중복·누락·무한 반복 없이 수렴한다.
#[test]
fn legacy_rows_without_ip_family_converge() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000);
    let dir = std::env::temp_dir().join(format!("engine-legacy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("e.db");
    let _ = std::fs::remove_file(&path);
    {
        let mut e = Engine::new(
            rusqlite::Connection::open(&path).unwrap(),
            &mut wfp,
            &NoGraph,
            &clock,
            &R,
            &[],
        )
        .unwrap();
        e.apply(SIMPLE, &[], "r1", "ui").unwrap();
        e.confirm(1, 1, "ui").unwrap();
        e.apply(&SIMPLE.replace("b.exe", "c.exe"), &[], "r2", "ui")
            .unwrap();
        e.confirm(1, 2, "ui").unwrap();
        // 예전 상태 만들기: V6 행과 그 필터를 없애고, V4 행에서 ip_family 를 지운다 → 행 1개(두 체계 원함) = 필터 1개
        let rows = e.store.filters_of(1).unwrap();
        let v6 = rows
            .iter()
            .find(|r| r.spec.ip_family == Some(policy::spec::IpFamily::V6))
            .unwrap()
            .filter_id;
        e.store
            .conn
            .execute("DELETE FROM wfp_filters WHERE filter_id = ?1", [v6 as i64])
            .unwrap();
        e.store
            .conn
            .execute(
                "UPDATE wfp_filters SET spec_json = json_remove(spec_json, '$.ip_family')",
                [],
            )
            .unwrap();
    }
    assert!(wfp.external_delete(rows_v6_id(&wfp)));
    assert_eq!(wfp.filters.len(), 1, "예전 상태: 필터 1개");
    let mut e = Engine::new(
        rusqlite::Connection::open(&path).unwrap(),
        &mut wfp,
        &NoGraph,
        &clock,
        &R,
        &[],
    )
    .unwrap();
    e.reconcile().unwrap();
    let rows = e.store.filters_of(1).unwrap();
    assert_eq!(rows.len(), 2, "정규화: V4·V6 두 행 {rows:?}");
    assert!(rows.iter().all(|r| r.spec.ip_family.is_some()));
    // 판 되돌리기 (저장된 판 명세는 나누기 전 형식 — swap 이 나눈다)
    e.rollback(1, Some(1), "ui").unwrap();
    let rows = e.store.filters_of(1).unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows
        .iter()
        .all(|r| r.spec.ip_family.is_some()
            && r.spec.app_path.as_deref().unwrap().ends_with("b.exe")));
    let first = rows[0].filter_id;
    drop(e);
    // 서비스가 멈춘 사이 필터 하나가 지워짐 → 재시작 대조가 그 체계만 다시 넣는다
    assert!(wfp.external_delete(first));
    let mut e = Engine::new(
        rusqlite::Connection::open(&path).unwrap(),
        &mut wfp,
        &NoGraph,
        &clock,
        &R,
        &[],
    )
    .unwrap();
    assert_eq!(e.reconcile().unwrap(), (1, 0));
    assert_eq!(e.store.filters_of(1).unwrap().len(), 2);
    // 재대조는 아무것도 바꾸지 않는다 (무한 반복 없음)
    assert_eq!(e.reconcile().unwrap(), (0, 0));
    assert_eq!(e.reconcile().unwrap(), (0, 0));
    drop(e);
    assert_eq!(wfp.filters.len(), 2, "DB 와 BFE 일치");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 가짜 BFE 에서 V6 필터 ID
fn rows_v6_id(wfp: &FakeWfp) -> u64 {
    *wfp.filters
        .iter()
        .find(|(_, s)| s.ip_family == Some(policy::spec::IpFamily::V6))
        .unwrap()
        .0
}

/// 28차 Q2 후속: BFE 재시작·재부팅 뒤 영구 필터의 번호가 바뀌어도(문서: "runtime identifier") 키로 같은 필터임을 알아
/// 번호만 고친다 — 전에는 자기 필터 전부를 "기록에 없는 필터(변조 의심)"로 지우고 다시 넣었다
#[test]
fn reconcile_follows_filter_keys_when_bfe_renumbers() {
    let clock = FakeClock::new(MONDAY_0000);
    let mut wfp = FakeWfp::default();
    let dir = std::env::temp_dir().join(format!("engine-renum-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("engine.db");
    let _ = std::fs::remove_file(&path);
    {
        let mut e = Engine::new(
            rusqlite::Connection::open(&path).unwrap(),
            &mut wfp,
            &NoGraph,
            &clock,
            &R,
            &[],
        )
        .unwrap();
        e.apply(WILD, &[], "r", "ui").unwrap();
        e.confirm(1, 1, "ui").unwrap();
    }
    let before: Vec<u64> = wfp.filters.keys().copied().collect();
    let calls = wfp.calls;
    wfp.renumber_all();
    let after: Vec<u64> = wfp.filters.keys().copied().collect();
    assert!(
        before.iter().all(|id| !after.contains(id)),
        "흉내: 번호가 모두 바뀜"
    );
    let mut e = Engine::new(
        rusqlite::Connection::open(&path).unwrap(),
        &mut wfp,
        &NoGraph,
        &clock,
        &R,
        &[],
    )
    .unwrap();
    let (restored, orphans) = e.reconcile().unwrap();
    assert_eq!((restored, orphans), (0, 0), "재등록·고아 제거 없음");
    assert!(!e
        .events
        .iter()
        .any(|ev| ev.kind == "orphan_filters_removed"));
    assert!(e
        .events
        .iter()
        .any(|ev| ev.kind == "policy_filters_renumbered"));
    let mut db: Vec<u64> = e
        .store
        .all_filters()
        .unwrap()
        .iter()
        .map(|f| f.filter_id)
        .collect();
    db.sort();
    let mut live = after.clone();
    live.sort();
    assert_eq!(db, live, "DB 번호 = 지금 BFE 번호");
    drop(e);
    assert_eq!(wfp.calls, calls, "BFE 변경 호출 없음");
    // 번호를 고친 뒤 해제도 새 번호로 된다
    let mut e = Engine::new(
        rusqlite::Connection::open(&path).unwrap(),
        &mut wfp,
        &NoGraph,
        &clock,
        &R,
        &[],
    )
    .unwrap();
    e.reconcile().unwrap();
    e.rollback(1, None, "ui").unwrap();
    drop(e);
    assert!(wfp.filters.is_empty(), "{:?}", wfp.filters.keys());
    let _ = std::fs::remove_dir_all(&dir);
}

/// 키 열이 없던 예전 DB: 열을 더하고, 번호가 같은 필터는 대조 때 키를 채운다
#[test]
fn legacy_db_gets_filter_key_column_and_keys_filled() {
    let clock = FakeClock::new(MONDAY_0000);
    let mut wfp = FakeWfp::default();
    let c = conn();
    c.execute_batch("CREATE TABLE wfp_filters (filter_id INTEGER PRIMARY KEY, policy_id INTEGER NOT NULL, version INTEGER NOT NULL, spec_json TEXT NOT NULL, expires_at INTEGER);").unwrap();
    let mut e = Engine::new(c, &mut wfp, &NoGraph, &clock, &R, &[]).unwrap();
    e.apply(SIMPLE, &[], "r", "ui").unwrap();
    e.confirm(1, 1, "ui").unwrap();
    let n: i64 = e
        .store
        .conn
        .query_row(
            "SELECT COUNT(*) FROM wfp_filters WHERE filter_key IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n as usize, e.store.all_filters().unwrap().len());
    assert!(n > 0);
}

/// ACL 정책 관리(2026-11-06): 번호 붙은 정책 묶음 = "ACL" 기록 하나·한 트랜잭션, 번호 없는 여러 정책 문서는 거부
#[test]
fn acl_set_applies_as_one_record_and_multi_without_numbers_is_rejected() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000);
    let mut e = Engine::new(
        conn(),
        &mut wfp,
        &NoGraph,
        &clock,
        &R,
        &["story-firewall-svc.exe"],
    )
    .unwrap();
    let acl = "- name: acl.1\n  priority: 1\n  action: allow\n  match: { direction: out, remote_ip: [10.0.0.5], protocol: tcp, remote_port: [443] }\n- name: acl.2\n  priority: 2\n  action: block\n  match: { direction: out, remote_ip: [10.0.0.0/24] }\n";
    let r = e.apply(acl, &[], "acl-1", "ui").unwrap();
    // 두 규칙 모두 IPv4 주소 → V4 필터만: 허용 1 + 차단 1(tcp·udp 는 한 필터의 OR 조건)
    assert_eq!(r.filters, 2, "{r:?}");
    let p = e.store.policy(r.policy_id).unwrap().unwrap();
    assert_eq!(p.name, engine::ACL_RECORD_NAME);
    let fs = e.store.filters_of(r.policy_id).unwrap();
    let w = |name: &str| {
        fs.iter()
            .find(|f| f.spec.name == name)
            .and_then(|f| f.spec.weight)
            .unwrap()
    };
    assert!(w("acl.1") > w("acl.2"), "번호 1 이 먼저");
    // 규칙을 바꿔 다시 적용하면 같은 ACL 기록의 2판(통째 교체)
    let r2 = e
        .apply(&acl.replace("10.0.0.5", "10.0.0.6"), &[], "acl-2", "ui")
        .unwrap();
    assert_eq!((r2.policy_id, r2.version), (r.policy_id, 2));
    // 번호 없는 여러 정책: 전에는 첫 정책만 조용히 적용됐다 → 거부
    let multi = "- name: a\n  action: block\n  match: { direction: out, remote_ip: [10.0.1.1] }\n- name: b\n  action: block\n  match: { direction: out, remote_ip: [10.0.1.2] }\n";
    assert!(matches!(
        e.apply(multi, &[], "m-1", "ui"),
        Err(EngineError::Invalid(_))
    ));
    // ACL 규칙에 기한은 안 된다(묶음 전체가 한 판)
    let exp = "- name: acl.1\n  priority: 1\n  action: block\n  match: { direction: out, remote_ip: [10.0.2.1] }\n  expires: 10m\n";
    assert!(matches!(
        e.apply(exp, &[], "x-1", "ui"),
        Err(EngineError::Invalid(_))
    ));
}

/// 접점 시험: 정책 화면(ui/src/screens/acl.ts aclToYaml)이 만든 꼴 그대로 — JSON flow mapping, 따옴표 이름, 문자열 포트
#[test]
fn acl_yaml_from_ui_is_accepted() {
    let mut wfp = FakeWfp::default();
    let clock = FakeClock::new(MONDAY_0000);
    let mut e = Engine::new(
        conn(),
        &mut wfp,
        &NoGraph,
        &clock,
        &R,
        &["story-firewall-svc.exe"],
    )
    .unwrap();
    let ui = r#"- name: "acl.1"
  priority: 1
  action: allow
  match: {"direction":"out","interface":"Wi-Fi","protocol":"tcp","local_ip":["192.168.0.10"],"remote_ip":["10.0.0.5"],"remote_port":["443"]}
- name: "acl.2"
  priority: 2
  action: block
  match: {"direction":"both","remote_ip":["10.0.0.0/24"],"remote_port":["8000-8100"]}
- name: "acl.3"
  priority: 3
  action: block
  match: {"direction":"in","protocol":"icmp","remote_ip":["203.0.113.0/24"]}
"#;
    let r = e.apply(ui, &[], "ui-acl", "ui").unwrap();
    let fs = e.store.filters_of(r.policy_id).unwrap();
    // acl.1 V4 허용 1 · acl.2 나감·들어옴 V4 2 · acl.3 들어옴 ICMP V4 1
    assert_eq!(fs.len(), 4, "{fs:?}");
    let a1 = fs.iter().find(|f| f.spec.name == "acl.1").unwrap();
    assert_eq!(a1.spec.interface.as_deref(), Some("Wi-Fi"));
    assert_eq!(a1.spec.local_v4.len(), 1);
    let a3 = fs.iter().find(|f| f.spec.name == "acl.3").unwrap();
    assert_eq!(a3.spec.protocols, vec![1]);
    // 38차 Q1②: ICMP 는 echo(Type 0·8)만 — 오류 메시지(Type 3 경로 MTU 등)는 막지 않는다
    let types: Vec<(u16, u16)> = a3.spec.local_ports.iter().map(|r| (r.lo, r.hi)).collect();
    assert_eq!(types, vec![(0, 0), (8, 8)]);
    assert!(a3.spec.remote_ports.is_empty());
}

/// 37차 Q2: 어댑터 재설치로 LUID 가 바뀌면 서비스 시작 대조가 인터페이스 조건 필터를 지금 별칭으로 다시 건다.
/// 별칭이 사라졌으면 옛 필터를 남기고(트랜잭션 실패) 경고 사건만 — 시작 대조는 멈추지 않는다
#[test]
fn reconcile_rebinds_interface_filters_to_current_luid() {
    let clock = FakeClock::new(MONDAY_0000);
    let mut wfp = FakeWfp::default();
    wfp.luid.insert("Wi-Fi".into(), 7);
    let dir = std::env::temp_dir().join(format!("engine-rebind-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("engine.db");
    let _ = std::fs::remove_file(&path);
    let acl = "- name: acl.1\n  priority: 1\n  action: block\n  match: { direction: out, interface: Wi-Fi, remote_ip: [10.0.0.5] }\n- name: acl.2\n  priority: 2\n  action: block\n  match: { direction: out, remote_ip: [10.0.0.6] }\n";
    let pid = {
        let mut e = Engine::new(
            rusqlite::Connection::open(&path).unwrap(),
            &mut wfp,
            &NoGraph,
            &clock,
            &R,
            &[],
        )
        .unwrap();
        let r = e.apply(acl, &[], "a", "ui").unwrap();
        e.confirm(r.policy_id, 1, "ui").unwrap();
        r.policy_id
    };
    let iface_id = |w: &FakeWfp| {
        w.filters
            .iter()
            .find(|(_, s)| s.interface.is_some())
            .map(|(id, _)| *id)
            .unwrap()
    };
    assert_eq!(wfp.bound[&iface_id(&wfp)], 7);
    // 서비스가 내려간 사이 어댑터 재설치 → 같은 별칭, 새 LUID
    wfp.luid.insert("Wi-Fi".into(), 9);
    {
        let mut e = Engine::new(
            rusqlite::Connection::open(&path).unwrap(),
            &mut wfp,
            &NoGraph,
            &clock,
            &R,
            &[],
        )
        .unwrap();
        e.reconcile().unwrap();
        assert_eq!(e.store.filters_of(pid).unwrap().len(), 2, "필터 수 그대로");
    }
    assert_eq!(wfp.filters.len(), 2, "옛 필터를 남기지 않는다");
    assert_eq!(wfp.bound[&iface_id(&wfp)], 9, "새 LUID 로 다시 걸림");
    // 별칭이 사라짐 → 옛 필터 유지 + 경고, 대조는 계속
    wfp.missing_ifaces.insert("Wi-Fi".into());
    let before = iface_id(&wfp);
    let mut e = Engine::new(
        rusqlite::Connection::open(&path).unwrap(),
        &mut wfp,
        &NoGraph,
        &clock,
        &R,
        &[],
    )
    .unwrap();
    e.reconcile().unwrap();
    assert!(e
        .events
        .iter()
        .any(|ev| ev.kind == "policy_interface_missing" && ev.detail.contains("Wi-Fi")));
    assert_eq!(e.store.filters_of(pid).unwrap().len(), 2);
    drop(e);
    assert_eq!(iface_id(&wfp), before);
}

/// 대시보드 개편안 3판 1-1: 긴급 차단 필터는 영구가 아니라 재부팅하면 사라진다. 재시작 대조(reconcile)는
/// 그 필터를 되살리지 않고 정책을 만료로 닫아야 한다(자가 치유가 PC 를 다시 가두지 않게).
/// 다른 정책의 사라진 필터는 지금처럼 되살린다.
#[test]
fn emergency_filters_lost_on_reboot_are_not_restored() {
    let clock = FakeClock::new(MONDAY_0000);
    let mut wfp = FakeWfp::default();
    let dir = std::env::temp_dir().join(format!("engine-emg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("engine.db");
    let _ = std::fs::remove_file(&path);
    let specs = policy::emergency::plan(&policy::emergency::Input {
        own_images: vec![r"C:\Program Files\Story Firewall\story-firewall-svc.exe".into()],
        remote_tools: vec![],
        rdp_clients: vec![],
        ..Default::default()
    });
    let (emg_ids, other_ids) = {
        let mut e = Engine::new(
            rusqlite::Connection::open(&path).unwrap(),
            &mut wfp,
            &NoGraph,
            &clock,
            &R,
            &[],
        )
        .unwrap();
        e.apply(SIMPLE, &[], "r1", "ui").unwrap();
        e.confirm(1, 1, "ui").unwrap();
        // 조건 없는 허용이 섞이면 거부
        let mut bad = specs.clone();
        let mut open = bad[0].clone();
        open.action = policy::spec::Action::Permit;
        bad.push(open);
        assert!(matches!(
            e.apply_emergency(&bad, 30, "r0", "ui"),
            Err(EngineError::Guard(_))
        ));
        // 기한 범위 밖 거부
        assert!(e.apply_emergency(&specs, 0, "r9", "ui").is_err());
        let r = e.apply_emergency(&specs, 30, "r2", "ui").unwrap();
        e.confirm(r.policy_id, r.version, "ui").unwrap();
        let (id, _, exp, st) = e.emergency_status().unwrap().unwrap();
        assert_eq!(
            (id, st, exp),
            (r.policy_id, State::Confirmed, MONDAY_0000 + 1800)
        );
        let emg: Vec<u64> = e
            .store
            .filters_of(r.policy_id)
            .unwrap()
            .iter()
            .map(|f| f.filter_id)
            .collect();
        let other: Vec<u64> = e
            .store
            .filters_of(1)
            .unwrap()
            .iter()
            .map(|f| f.filter_id)
            .collect();
        (emg, other)
    };
    // 재부팅: 긴급 차단 필터는 전부 사라짐(비영구), 다른 정책 필터 하나도 외부 삭제
    for id in &emg_ids {
        assert!(wfp.external_delete(*id));
    }
    assert!(wfp.external_delete(other_ids[0]));
    let mut e = Engine::new(
        rusqlite::Connection::open(&path).unwrap(),
        &mut wfp,
        &NoGraph,
        &clock,
        &R,
        &[],
    )
    .unwrap();
    let (restored, _) = e.reconcile().unwrap();
    assert_eq!(restored, 1, "다른 정책 필터만 되살림");
    assert!(
        e.emergency_status().unwrap().is_none(),
        "긴급 차단은 만료로 닫힘"
    );
    assert!(e.events.iter().any(|ev| ev.kind == "emergency_off"));
}

/// UI 명세 4판 3-1 [연장 30분]: 확인된 긴급 차단의 만료만 늦춘다. 필터는 그대로, 확인 전에는 거부, 하루 상한, 같은 요청은 한 번만
#[test]
fn emergency_extend_moves_only_expiry() {
    let clock = FakeClock::new(MONDAY_0000);
    let mut wfp = FakeWfp::default();
    let specs = policy::emergency::plan(&policy::emergency::Input {
        own_images: vec![r"C:\Program Files\Story Firewall\story-firewall-svc.exe".into()],
        remote_tools: vec![],
        rdp_clients: vec![],
        ..Default::default()
    });
    let mut e = Engine::new(
        rusqlite::Connection::open_in_memory().unwrap(),
        &mut wfp,
        &NoGraph,
        &clock,
        &R,
        &[],
    )
    .unwrap();
    // 걸린 것이 없으면 거부
    assert!(e.extend_emergency(30, "x0", "ui").is_err());
    let r = e.apply_emergency(&specs, 30, "a1", "ui").unwrap();
    // 60초 확인 전에는 늘리지 않는다
    assert!(matches!(
        e.extend_emergency(30, "x1", "ui"),
        Err(EngineError::BadState(_))
    ));
    e.confirm(r.policy_id, r.version, "ui").unwrap();
    let before: Vec<u64> = e
        .store
        .filters_of(r.policy_id)
        .unwrap()
        .iter()
        .map(|f| f.filter_id)
        .collect();
    let exp = e.extend_emergency(30, "x2", "ui").unwrap();
    assert_eq!(exp, MONDAY_0000 + 3600);
    // 같은 요청 번호 다시 = 같은 결과, 두 번 늘리지 않음
    assert_eq!(e.extend_emergency(30, "x2", "ui").unwrap(), exp);
    let (_, ver, exp2, st) = e.emergency_status().unwrap().unwrap();
    assert_eq!(
        (exp2, st, ver),
        (exp, State::Confirmed, r.version),
        "판·상태 그대로"
    );
    let after: Vec<u64> = e
        .store
        .filters_of(r.policy_id)
        .unwrap()
        .iter()
        .map(|f| f.filter_id)
        .collect();
    assert_eq!(before, after, "필터는 바꾸지 않는다");
    // 범위 밖 분
    assert!(e.extend_emergency(0, "x3", "ui").is_err());
    assert!(e.extend_emergency(121, "x4", "ui").is_err());
    // 하루 상한: 여러 번 늘려도 지금 + 1440분을 넘지 않는다
    for i in 0..30 {
        let _ = e.extend_emergency(120, &format!("y{i}"), "ui");
    }
    let (_, _, exp3, _) = e.emergency_status().unwrap().unwrap();
    assert_eq!(exp3, MONDAY_0000 + 1440 * 60);
    assert!(e.extend_emergency(30, "z", "ui").is_err(), "이미 최대");
    // 45차 답변 Q5: 시간이 지나도 누적 상한은 "걸린 때부터 하루" — 20시간 뒤에 늘려도 그 너머로 가지 않는다
    clock.advance(20 * 3600);
    assert!(
        e.extend_emergency(120, "z2", "ui").is_err(),
        "걸린 때부터 하루가 상한"
    );
    let (_, _, exp4, _) = e.emergency_status().unwrap().unwrap();
    assert_eq!(exp4, MONDAY_0000 + 1440 * 60);
}
