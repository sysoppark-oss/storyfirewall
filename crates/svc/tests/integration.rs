//! A14 통과 기준 (13차 3-5): 가짜 Transport·Authn·수집기로 전체 흐름.
//! hello 강제 → apply(needs_ack 오류) → ack 재시도 → confirm → 60초 미확인 자동 롤백 알림 → 수집 이벤트 → judge → story.events 페이지 → 구독 알림 → 권한·서명 거부.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use dsl::expand::Resolver;
use engine::backend::{FakeWfp, GraphQuery, NoGraph, WfpBackend};
use engine::Clock;
use graph::event::{Direction, Event, EventKind, ProcRef, Proto};
use svc::runtime::{Command, Parts, Runtime};
use svc::{Authn, Read, Transport};

// ---- 가짜 부품 ----
struct SharedClock(Arc<AtomicI64>, Arc<AtomicI64>);
/// 모든 시험 시계는 한국 시간대(+9h)로 돈다: 로컬 시각이 UTC 자리에 새어 나가면 시험이 깨지게 (A22 접점 결함)
const TZ_OFFSET: i64 = 9 * 3600;
impl Clock for SharedClock {
    fn wall(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
    fn mono(&self) -> i64 {
        self.1.load(Ordering::SeqCst)
    }
    fn local(&self) -> i64 {
        self.wall() + TZ_OFFSET
    }
}
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
struct TestParts {
    wall: Arc<AtomicI64>,
    mono: Arc<AtomicI64>,
}
impl Parts for TestParts {
    fn build(
        self: Box<Self>,
    ) -> (
        Box<dyn WfpBackend>,
        Box<dyn GraphQuery>,
        Box<dyn Clock>,
        Box<dyn Resolver>,
        rusqlite::Connection,
        graph::store::Store,
        Vec<String>,
    ) {
        (
            Box::new(FakeWfp::default()),
            Box::new(NoGraph),
            Box::new(SharedClock(self.wall, self.mono)),
            Box::new(R),
            rusqlite::Connection::open_in_memory().unwrap(),
            graph::store::Store::open_in_memory().unwrap(),
            vec!["story-firewall-svc.exe".into()],
        )
    }
}

/// 채널 쌍 전송: 테스트가 클라이언트, 핸들러가 서버
struct ChanTransport {
    pid: u32,
    /// 클라이언트 로그온 세션 (A30). None = 범위 제한 없음
    session: Option<u32>,
    rx: Receiver<String>,
    tx: Sender<String>,
    /// 파이프에서 한 번이라도 읽었는가 (Impersonate 순서 제약 검사용)
    read_once: Arc<AtomicBool>,
}
impl Transport for ChanTransport {
    fn read_line(&mut self, timeout: Duration) -> Read {
        self.read_once.store(true, Ordering::SeqCst);
        match self.rx.recv_timeout(timeout) {
            Ok(l) => Read::Line(l),
            Err(mpsc::RecvTimeoutError::Timeout) => Read::Timeout,
            Err(mpsc::RecvTimeoutError::Disconnected) => Read::Closed,
        }
    }
    fn write_line(&mut self, line: &str) -> bool {
        self.tx.send(line.to_string()).is_ok()
    }
    fn client_pid(&self) -> u32 {
        self.pid
    }
    fn client_session(&self) -> Option<u32> {
        self.session
    }
}
/// Windows 의 ImpersonateNamedPipeClient 는 파이프 첫 읽기 전엔 실패한다(0x558, A17 러너 실측).
/// 가짜 Authn 도 같은 제약을 강제해 순서 회귀를 Linux CI 에서 잡는다(제안 4).
struct FakeAuth {
    read_once: Arc<AtomicBool>,
}
/// 연결 중 관리자 그룹에서 빠지는 PID (15차 Q2 원래 질문)
static DEMOTED: AtomicBool = AtomicBool::new(false);
impl Authn for FakeAuth {
    fn client_image(&self, pid: u32) -> Option<String> {
        Some(format!(r"C:\Program Files\StoryFirewall\ui.exe#{pid}"))
    }
    fn signature_ok(&self, pid: u32) -> bool {
        pid != 666
    }
    fn is_admin(&self, pid: u32) -> bool {
        assert!(
            self.read_once.load(Ordering::SeqCst),
            "is_admin 이 파이프 첫 읽기 전에 불렸다 (ImpersonateNamedPipeClient 0x558 재현)"
        );
        pid == 100 || (pid == 300 && !DEMOTED.load(Ordering::SeqCst))
    }
}

struct Client {
    to_server: Sender<String>,
    from_server: Receiver<String>,
    next_id: i64,
    reason: Receiver<&'static str>,
}
impl Client {
    fn connect(rt: &Runtime, pid: u32, conn_id: u64) -> Client {
        Self::connect_session(rt, pid, conn_id, None)
    }
    fn connect_session(rt: &Runtime, pid: u32, conn_id: u64, session: Option<u32>) -> Client {
        let (c2s_tx, c2s_rx) = mpsc::channel::<String>();
        let (s2c_tx, s2c_rx) = mpsc::channel::<String>();
        let (reason_tx, reason_rx) = mpsc::channel();
        let engine = rt.tx.clone();
        std::thread::spawn(move || {
            let read_once = Arc::new(AtomicBool::new(false));
            let mut t = ChanTransport {
                pid,
                session,
                rx: c2s_rx,
                tx: s2c_tx,
                read_once: read_once.clone(),
            };
            let why = svc::handler::serve(conn_id, &mut t, &FakeAuth { read_once }, &engine);
            let _ = reason_tx.send(why);
        });
        Client {
            to_server: c2s_tx,
            from_server: s2c_rx,
            next_id: 1,
            reason: reason_rx,
        }
    }
    fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        let id = self.next_id;
        self.next_id += 1;
        let line = serde_json::to_string(&api::Request::new(id, method, params)).unwrap();
        self.to_server.send(line).unwrap();
        loop {
            let resp = self
                .from_server
                .recv_timeout(Duration::from_secs(5))
                .expect("응답");
            let v: serde_json::Value = serde_json::from_str(resp.trim_end()).unwrap();
            if v.get("id").is_some() {
                return v;
            }
            // 알림은 건너뛴다 (별도 메서드로 받음)
        }
    }
    fn hello(&mut self) -> serde_json::Value {
        self.call(
            "rpc.hello",
            serde_json::json!({"client_version": "0.1.0", "api": [1, 0]}),
        )
    }
    fn next_notification(&self, timeout: Duration) -> Option<serde_json::Value> {
        let line = self.from_server.recv_timeout(timeout).ok()?;
        serde_json::from_str(line.trim_end()).ok()
    }
}

const SIMPLE: &str = "- name: block-b\n  action: block\n  match: { direction: out, process: ['C:/Program Files/B/b.exe'] }\n";
const UUID: &str = "0f3c2a1e-9b7d-4c6a-8e5f-123456789abc";
const T0: i64 = 19_723 * 86_400;

fn boot() -> (Runtime, Arc<AtomicI64>, Arc<AtomicI64>) {
    boot_with(None)
}

fn boot_with(host: Option<Box<dyn svc::host::Host>>) -> (Runtime, Arc<AtomicI64>, Arc<AtomicI64>) {
    let wall = Arc::new(AtomicI64::new(T0));
    let mono = Arc::new(AtomicI64::new(0));
    let rt = Runtime::start_with(
        Box::new(TestParts {
            wall: wall.clone(),
            mono: mono.clone(),
        }),
        "0.1.0",
        host,
    );
    (rt, wall, mono)
}

#[test]
fn hello_is_mandatory_and_version_negotiated() {
    let (rt, _, _) = boot();
    // hello 없이 다른 메서드 → 끊김
    let mut c = Client::connect(&rt, 100, 1);
    let v = c.call("policy.list", serde_json::json!({}));
    assert_eq!(v["error"]["code"], serde_json::json!(-32600));
    assert_eq!(
        c.reason.recv_timeout(Duration::from_secs(2)).unwrap(),
        "no_hello"
    );
    // 판 불일치 → 끊김
    let mut c = Client::connect(&rt, 100, 2);
    let v = c.call(
        "rpc.hello",
        serde_json::json!({"client_version": "9", "api": [2, 0]}),
    );
    assert_eq!(v["error"]["code"], serde_json::json!(-32006));
    assert_eq!(
        c.reason.recv_timeout(Duration::from_secs(2)).unwrap(),
        "version_mismatch"
    );
    // 정상
    let mut c = Client::connect(&rt, 100, 3);
    let v = c.hello();
    assert_eq!(v["result"]["api"], serde_json::json!([1, 0]));
    assert_eq!(v["result"]["server_version"], serde_json::json!("0.1.0"));
    rt.shutdown();
}

#[test]
fn signature_failure_rejects_connection_and_non_admin_cannot_mutate() {
    let (rt, _, _) = boot();
    let c = Client::connect(&rt, 666, 1);
    assert_eq!(
        c.reason.recv_timeout(Duration::from_secs(2)).unwrap(),
        "signature_failed"
    );
    let mut u = Client::connect(&rt, 200, 2); // 서명 OK, 비관리자
    u.hello();
    let v = u.call(
        "policy.apply",
        serde_json::json!({"request_id": UUID, "yaml": SIMPLE}),
    );
    assert_eq!(v["error"]["code"], serde_json::json!(-32001));
    let v = u.call("policy.list", serde_json::json!({}));
    assert!(v["result"]["items"].is_array(), "조회는 된다");
    rt.shutdown();
}

#[test]
fn apply_needs_ack_then_ack_confirm_and_auto_rollback_notification() {
    let (rt, _wall, mono) = boot();
    let mut a = Client::connect(&rt, 100, 1);
    a.hello();
    // 구독
    let v = a.call("events.subscribe", serde_json::json!({}));
    assert_eq!(v["result"]["subscribed"], serde_json::json!(true));
    // needs_ack 는 오류 -32003 (12차 Q1)
    let wide = "- name: wide\n  action: block\n  match: { direction: out, remote_port: [53] , process: ['C:/a/b.exe'] }\n";
    let v = a.call(
        "policy.apply",
        serde_json::json!({"request_id": UUID, "yaml": wide}),
    );
    assert_eq!(v["error"]["code"], serde_json::json!(-32003), "{v}");
    // 응답 낱말 = 입력 낱말 (A23 접점 결함: 예전엔 "selfblock" 을 내보내고 "self" 만 받았다)
    assert_eq!(v["error"]["data"]["items"][0][1], serde_json::json!("self"));
    // ack 붙여 재시도 (같은 request_id — 실패했던 요청이라 저장 안 됨)
    let v = a.call(
        "policy.apply",
        serde_json::json!({"request_id": UUID, "yaml": wide, "acknowledge": [["wide", "self"]]}),
    );
    assert!(v["result"]["policy_id"].is_i64(), "{v}");
    let pid = v["result"]["policy_id"].as_i64().unwrap();
    let ver = v["result"]["version"].as_i64().unwrap();
    // 멱등: 같은 request_id 다시 → 같은 결과
    let v2 = a.call(
        "policy.apply",
        serde_json::json!({"request_id": UUID, "yaml": wide, "acknowledge": [["wide", "self"]]}),
    );
    assert_eq!(v2["result"]["version"], serde_json::json!(ver));
    // confirm: 틀린 버전 → version_mismatch
    let v = a.call(
        "policy.confirm",
        serde_json::json!({"request_id": UUID, "policy_id": pid, "version": ver + 5}),
    );
    assert_eq!(v["error"]["code"], serde_json::json!(-32006));
    let v = a.call(
        "policy.confirm",
        serde_json::json!({"request_id": UUID, "policy_id": pid, "version": ver}),
    );
    assert_eq!(v["result"]["ok"], serde_json::json!(true));
    // 두 번째 정책은 확인하지 않고 60초 경과 → 자동 롤백 알림
    let v = a.call(
        "policy.apply",
        serde_json::json!({"request_id": "1f3c2a1e-9b7d-4c6a-8e5f-123456789abc", "yaml": SIMPLE}),
    );
    assert!(v["result"]["policy_id"].is_i64(), "{v}");
    mono.fetch_add(61, Ordering::SeqCst);
    rt.tx.send(Command::Tick).unwrap();
    // 알림이 올 때까지 (다른 응답은 없음)
    let mut got = false;
    for _ in 0..5 {
        if let Some(n) = a.next_notification(Duration::from_secs(2)) {
            if n["method"] == serde_json::json!("events.new")
                && n["params"]["kind"] == serde_json::json!("policy_auto_rollback")
            {
                got = true;
                break;
            }
        }
    }
    assert!(got, "자동 롤백 알림");
    let v = a.call("policy.list", serde_json::json!({}));
    let states: Vec<String> = v["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["state"].as_str().unwrap().to_string())
        .collect();
    assert!(
        states.contains(&"Confirmed".into()) && states.contains(&"RolledBack".into()),
        "{states:?}"
    );
    rt.shutdown();
}

#[test]
fn ingest_judge_story_events_and_suspicious_notification() {
    let (rt, _, _) = boot();
    let mut a = Client::connect(&rt, 100, 1);
    a.hello();
    a.call("events.subscribe", serde_json::json!({}));
    // 수집 이벤트: payload 사건 재현
    let t = 133_800_000_000_000_000i64;
    let s = 10_000_000;
    let payload = r"C:\Users\pjg\AppData\Local\Temp\payload.exe";
    let ev = |ts: i64, source: &str, kind: EventKind| Event {
        ts,
        source: source.into(),
        kind,
    };
    let events = vec![
        ev(
            t,
            "snapshot",
            EventKind::ProcessSnapshot {
                pid: 1000,
                ppid: 4,
                image: r"C:\Windows\explorer.exe".into(),
                create_time: t,
                services: vec![],
            },
        ),
        ev(
            t + s,
            "etw:file",
            EventKind::FileWrite {
                proc: ProcRef::new(1000, None),
                path: payload.into(),
            },
        ),
        ev(
            t + s,
            "motw",
            EventKind::Downloaded {
                path: payload.into(),
                host_url: Some("https://evil.example/p".into()),
                referrer_url: None,
                zone_id: Some(3),
            },
        ),
        ev(
            t + 2 * s,
            "signature",
            EventKind::Signature {
                path: payload.into(),
                signer: None,
                issuer: None,
                status: "untrusted".into(),
                catalog: false,
            },
        ),
        ev(
            t + 3 * s,
            "etw:process",
            EventKind::ProcessStart {
                pid: 2200,
                ppid: 1000,
                image: payload.into(),
                create_time: Some(t + 3 * s),
            },
        ),
        ev(
            t + 4 * s,
            "autorun",
            EventKind::AutorunRegistered {
                proc: ProcRef::new(2200, None),
                location: "HKCU\\...\\Run\\x".into(),
                target: payload.into(),
            },
        ),
        ev(
            t + 5 * s,
            "etw:dns",
            EventKind::DnsQuery {
                proc: ProcRef::new(2200, None),
                name: "c2.evil.example".into(),
                results: vec!["203.0.113.9".into()],
            },
        ),
        ev(
            t + 6 * s,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(2200, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50000,
                raddr: "203.0.113.9".into(),
                rport: 8443,
            },
        ),
    ];
    rt.tx.send(Command::Ingest(events)).unwrap();
    rt.tx.send(Command::Judge).unwrap();
    let mut got = None;
    for _ in 0..5 {
        if let Some(n) = a.next_notification(Duration::from_secs(2)) {
            if n["params"]["kind"] == serde_json::json!("story_suspicious") {
                got = Some(n);
                break;
            }
        }
    }
    let n = got.expect("의심 사건 알림");
    assert_eq!(n["params"]["label"], serde_json::json!("payload.exe"));
    assert_eq!(n["params"]["chapter"], serde_json::json!(4));
    // 같은 사건을 다시 판정해도 장이 안 올라갔으면 알림 없음
    rt.tx.send(Command::Judge).unwrap();
    assert!(
        a.next_notification(Duration::from_millis(800)).is_none(),
        "중복 알림 없음"
    );
    // story.events 페이지 (plain, 기본 level watch)
    let v = a.call("story.events", serde_json::json!({"cursor": {"limit": 1}}));
    let items = v["result"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{v}");
    assert!(items[0]["title"]
        .as_str()
        .unwrap()
        .starts_with("[의심] payload.exe"));
    assert!(v["result"]["next"].is_null(), "사건 1건이라 다음 쪽 없음");
    // L052: 대시보드(since 0)와 이야기 화면(since 지정)을 오가도 두 결과의 문장 캐시가 서로 지우지 않고 같은 문장을 돌려준다
    let first = items[0]["title"].clone();
    let w = a.call(
        "story.events",
        serde_json::json!({"since_ts": 1, "cursor": {"limit": 1}}),
    );
    assert_eq!(w["result"]["items"][0]["title"], first, "{w}");
    let again = a.call("story.events", serde_json::json!({"cursor": {"limit": 1}}));
    assert_eq!(again["result"]["items"][0]["title"], first, "{again}");
    // story.explain: 근거 원시 이벤트
    let edge = items[0]["sentences"][0]["edge_ids"][0].as_i64().unwrap();
    let v = a.call("story.explain", serde_json::json!({"edge_id": edge}));
    assert!(!v["result"]["evidence"].as_array().unwrap().is_empty());
    // 피드백 → 사건 종료 (파일에서 시작한 사건이라 정상 처리 가능)
    assert_eq!(items[0]["feedback_ok"], serde_json::json!(true));
    let root = items[0]["root"].as_i64().unwrap();
    let v = a.call(
        "judge.feedback_normal",
        serde_json::json!({"request_id": UUID, "root": root}),
    );
    assert_eq!(v["result"]["ok"], serde_json::json!(true));
    let v = a.call("story.events", serde_json::json!({"level_min": "normal"}));
    assert_eq!(v["result"]["items"][0]["score"], serde_json::json!(0));
    rt.shutdown();
}

#[test]
fn baseline_uses_filetime_and_learns_daily() {
    // 엔진 시계는 unix 초, judge 는 FILETIME. 14일 뒤 pc_learned 가 true 가 되어야 한다 (단위 불일치 회귀)
    let (rt, wall, _) = boot();
    let mut a = Client::connect(&rt, 100, 1);
    a.hello();
    let t = svc::runtime::unix_to_filetime(T0);
    let app = r"C:\Program Files\Vendor\app.exe";
    let ev = |ts: i64, source: &str, kind: EventKind| Event {
        ts,
        source: source.into(),
        kind,
    };
    rt.tx
        .send(Command::Ingest(vec![
            ev(
                t,
                "snapshot",
                EventKind::ProcessSnapshot {
                    pid: 1000,
                    ppid: 4,
                    image: r"C:\Windows\explorer.exe".into(),
                    create_time: t,
                    services: vec![],
                },
            ),
            ev(
                t + 10_000_000,
                "etw:process",
                EventKind::ProcessStart {
                    pid: 6000,
                    ppid: 1000,
                    image: app.into(),
                    create_time: Some(t + 10_000_000),
                },
            ),
            ev(
                t + 10_000_000,
                "signature",
                EventKind::Signature {
                    path: app.into(),
                    signer: Some("Vendor Inc".into()),
                    issuer: None,
                    status: "valid".into(),
                    catalog: false,
                },
            ),
            ev(
                t + 20_000_000,
                "etw:dns",
                EventKind::DnsQuery {
                    proc: ProcRef::new(6000, None),
                    name: "api.vendor.example".into(),
                    results: vec!["198.51.100.1".into()],
                },
            ),
            ev(
                t + 30_000_000,
                "etw:network",
                EventKind::Connect {
                    proc: ProcRef::new(6000, None),
                    proto: Proto::Tcp,
                    direction: Direction::Out,
                    laddr: "10.0.0.2".into(),
                    lport: 50000,
                    raddr: "198.51.100.1".into(),
                    rport: 443,
                },
            ),
        ]))
        .unwrap();
    // Ingest 뒤 같은 큐로 Learn → 순서 보장 (자동 학습은 하루 1회라 테스트에서는 명시 호출)
    rt.tx.send(Command::Learn).unwrap();
    let v = a.call("judge.baseline_status", serde_json::json!({}));
    assert_eq!(v["result"]["pc_learned"], serde_json::json!(false));
    wall.fetch_add(15 * 86_400, Ordering::SeqCst);
    rt.tx.send(Command::Judge).unwrap();
    let v = a.call("judge.baseline_status", serde_json::json!({}));
    assert_eq!(v["result"]["pc_learned"], serde_json::json!(true), "{v}");
    rt.shutdown();
}

/// A17 러너 실측: SCM 은 시각 변경 1회에 TIMECHANGE 를 2건 보낸다. 엔진은 1초 창 안의 중복을 하나로 합치되,
/// 그 창 안에 끼어든 다른 명령(RPC)을 삼키면 안 된다.
#[test]
fn duplicate_time_changed_is_coalesced_without_swallowing_commands() {
    let (rt, _, _) = boot();
    let mut c = Client::connect(&rt, 100, 1);
    c.hello();
    rt.tx.send(Command::TimeChanged).unwrap();
    rt.tx.send(Command::TimeChanged).unwrap();
    // 합치기 창(1초) 안에 RPC 가 들어온다 → 응답이 와야 한다 (call 은 5초 안에 응답 없으면 panic)
    let v = c.call("policy.list", serde_json::json!({}));
    assert!(v["result"].is_object(), "{v}");
    // 합치기 뒤에도 정상 동작
    rt.tx.send(Command::TimeChanged).unwrap();
    let v = c.call("settings.get", serde_json::json!({}));
    assert!(v["result"].is_object(), "{v}");
    rt.shutdown();
}

// ---------------------------------------------------------------- A19

/// 종료 요청을 기록하는 호스트
struct RecHost(Arc<std::sync::Mutex<Vec<(u32, Option<i64>)>>>);
impl svc::host::Host for RecHost {
    fn listeners(&self) -> Result<Vec<svc::host::Listener>, String> {
        Ok(vec![svc::host::Listener {
            proto: "tcp".into(),
            laddr: "0.0.0.0".into(),
            lport: 4444,
            pid: 2200,
            any_addr: true,
        }])
    }
    fn terminate(&self, pid: u32, create_ft: Option<i64>) -> String {
        self.0.lock().unwrap().push((pid, create_ft));
        "Terminated".into()
    }
}

/// payload 사건 + 자손(cmd) + 시스템 자손(svchost) — 시각은 엔진 벽시계(T0) 근처 FILETIME
fn a19_events() -> (Vec<Event>, i64) {
    let t = svc::runtime::unix_to_filetime(T0) - 600 * 10_000_000;
    let s = 10_000_000;
    let payload = r"C:\Users\pjg\AppData\Local\Temp\payload.exe";
    let ev = |ts: i64, source: &str, kind: EventKind| Event {
        ts,
        source: source.into(),
        kind,
    };
    (
        vec![
            ev(
                t,
                "snapshot",
                EventKind::ProcessSnapshot {
                    pid: 1000,
                    ppid: 4,
                    image: r"C:\Windows\explorer.exe".into(),
                    create_time: t,
                    services: vec![],
                },
            ),
            ev(
                t + s,
                "etw:file",
                EventKind::FileWrite {
                    proc: ProcRef::new(1000, None),
                    path: payload.into(),
                },
            ),
            ev(
                t + s,
                "motw",
                EventKind::Downloaded {
                    path: payload.into(),
                    host_url: Some("https://evil.example/p".into()),
                    referrer_url: None,
                    zone_id: Some(3),
                },
            ),
            ev(
                t + 3 * s,
                "etw:process",
                EventKind::ProcessStart {
                    pid: 2200,
                    ppid: 1000,
                    image: payload.into(),
                    create_time: Some(t + 3 * s),
                },
            ),
            ev(
                t + 4 * s,
                "etw:process",
                EventKind::ProcessStart {
                    pid: 2300,
                    ppid: 2200,
                    image: r"C:\Windows\System32\cmd.exe".into(),
                    create_time: Some(t + 4 * s),
                },
            ),
            ev(
                t + 4 * s,
                "etw:process",
                EventKind::ProcessStart {
                    pid: 2500,
                    ppid: 2200,
                    image: r"C:\Windows\System32\svchost.exe".into(),
                    create_time: Some(t + 4 * s),
                },
            ),
            ev(
                t + 5 * s,
                "autorun",
                EventKind::AutorunRegistered {
                    proc: ProcRef::new(2200, None),
                    location: "HKCU\\Run\\x".into(),
                    target: payload.into(),
                },
            ),
            ev(
                t + 6 * s,
                "etw:dns",
                EventKind::DnsQuery {
                    proc: ProcRef::new(2200, None),
                    name: "c2.evil.example".into(),
                    results: vec!["203.0.113.9".into()],
                },
            ),
            ev(
                t + 7 * s,
                "etw:network",
                EventKind::Connect {
                    proc: ProcRef::new(2200, None),
                    proto: Proto::Tcp,
                    direction: Direction::Out,
                    laddr: "10.0.0.2".into(),
                    lport: 50000,
                    raddr: "203.0.113.9".into(),
                    rport: 8443,
                },
            ),
            ev(
                t + 8 * s,
                "etw:network",
                EventKind::Connect {
                    proc: ProcRef::new(2500, None),
                    proto: Proto::Tcp,
                    direction: Direction::Out,
                    laddr: "10.0.0.2".into(),
                    lport: 50001,
                    raddr: "198.51.100.7".into(),
                    rport: 443,
                },
            ),
        ],
        t,
    )
}

#[test]
fn a19_connections_listeners_and_process_detail() {
    let kills = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (rt, _, _) = boot_with(Some(Box::new(RecHost(kills.clone()))));
    let mut c = Client::connect(&rt, 100, 1);
    c.hello();
    let (events, _) = a19_events();
    rt.tx.send(Command::Ingest(events)).unwrap();
    let v = c.call("connections.list", serde_json::json!({"since_secs": 3600}));
    let items = v["result"]["items"].as_array().expect("items");
    let pay = items
        .iter()
        .find(|i| i["pid"] == 2200)
        .unwrap_or_else(|| panic!("payload 접속 {v}"));
    assert_eq!(pay["domain"], serde_json::json!("c2.evil.example"));
    // 접점: 원격 주소마다 "where"(종류·국가). 시험 환경에는 DB 가 없어 공인 주소는 종류만
    let w = &pay["where"];
    assert!(w["scope"].is_string(), "where 필드 {pay}");
    assert_eq!(v["result"]["geo"]["country_db"], serde_json::json!(false));
    assert!(
        pay["first_ft"].as_i64().unwrap() > 116_444_736_000_000_000,
        "FILETIME 단위"
    );
    // 5분 창 밖(10분 전 사건)은 안 보인다: 기본 since_secs=300
    let v = c.call("connections.list", serde_json::json!({}));
    assert!(v["result"]["items"].as_array().unwrap().is_empty(), "{v}");
    // 리스닝: 호스트 결과 + 그래프 이미지
    let v = c.call("listeners.list", serde_json::json!({}));
    let l = &v["result"]["items"][0];
    assert_eq!(l["lport"], serde_json::json!(4444));
    assert!(l["image"].as_str().unwrap().ends_with("payload.exe"), "{v}");
    // 프로세스 상세
    let pid_node = pay["process_id"].as_i64().unwrap();
    let v = c.call("process.detail", serde_json::json!({"node_id": pid_node}));
    let d = &v["result"];
    assert_eq!(d["pid"], serde_json::json!(2200));
    assert_eq!(d["children"].as_array().unwrap().len(), 2);
    assert_eq!(
        d["origin"]["host_url"],
        serde_json::json!("https://evil.example/p")
    );
    assert!(!d["rewind"].as_array().unwrap().is_empty());
    assert!(d["create_ft"].as_i64().is_some());
    // 프로세스가 아닌 노드는 거부
    let v = c.call(
        "process.detail",
        serde_json::json!({"node_id": pay["remote_id"]}),
    );
    assert_eq!(v["error"]["code"], serde_json::json!(-32602));
    rt.shutdown();
}

#[test]
fn a19_cut_preview_apply_blocks_then_terminates_and_fills_new_children() {
    let kills = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (rt, _, _) = boot_with(Some(Box::new(RecHost(kills.clone()))));
    let mut c = Client::connect(&rt, 100, 1);
    c.hello();
    let (events, t) = a19_events();
    rt.tx.send(Command::Ingest(events)).unwrap();
    // 뿌리 = payload 프로세스
    let v = c.call("connections.list", serde_json::json!({"since_secs": 3600}));
    let root = v["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["pid"] == 2200)
        .unwrap()["process_id"]
        .as_i64()
        .unwrap();
    let v = c.call(
        "cut.preview",
        serde_json::json!({"story_root": root, "also": ["terminate"]}),
    );
    let p = &v["result"];
    let imgs: Vec<String> = p["block_images"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    assert!(
        imgs.iter().any(|i| i.ends_with("payload.exe"))
            && imgs.iter().any(|i| i.ends_with("cmd.exe")),
        "{imgs:?}"
    );
    assert!(
        !imgs
            .iter()
            .any(|i| i.to_ascii_lowercase().ends_with("svchost.exe")),
        "시스템 프로세스는 차단 목록에 없음"
    );
    assert_eq!(p["excluded_system"].as_array().unwrap().len(), 1);
    assert_eq!(
        p["system_addresses"][0][0],
        serde_json::json!("198.51.100.7")
    );
    // 접속지는 (IP·포트·프로토콜) 단위: 시스템 접속지 + 대상 접속지 (16차 Q2 정정, 공격 #2 주입 탈출 대비)
    let addrs: Vec<(String, u64, u64, String)> = p["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["ip"].as_str().unwrap().to_string(),
                a["port"].as_u64().unwrap(),
                a["proto"].as_u64().unwrap(),
                a["why"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(
        addrs.contains(&("198.51.100.7".into(), 443, 6, "system".into())),
        "{addrs:?}"
    );
    assert!(
        addrs.contains(&("203.0.113.9".into(), 8443, 6, "target".into())),
        "{addrs:?}"
    );
    assert!(
        p["validation"]["errors"].as_array().unwrap().is_empty(),
        "{p}"
    );
    let term: Vec<i64> = p["terminate"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["pid"].as_i64().unwrap())
        .collect();
    assert_eq!(
        term.len(),
        2,
        "payload·cmd 만 종료 (svchost 제외): {term:?}"
    );
    assert!(
        kills.lock().unwrap().is_empty(),
        "미리보기는 아무것도 하지 않는다"
    );
    // 비관리자는 적용 불가
    let mut u = Client::connect(&rt, 200, 2);
    u.hello();
    let v = u.call(
        "cut.apply",
        serde_json::json!({"request_id": UUID, "story_root": root, "also": ["terminate"]}),
    );
    assert_eq!(v["error"]["code"], serde_json::json!(-32001));
    c.call("events.subscribe", serde_json::json!({}));
    // 적용: 정책 1건(경로 차단 + 같은 판의 주소 차단, 확인 1번) → 종료 2건 (생성 시각 포함)
    let v = c.call("cut.apply", serde_json::json!({"request_id": UUID, "story_root": root, "also": ["terminate", "remove_autorun"]}));
    let r = &v["result"];
    assert_eq!(r["policies"].as_array().unwrap().len(), 1, "{v}");
    // 실제 WFP 필터 수: 경로 2개 × 방향 2 × 주소 체계 2(V4·V6) + 주소 2곳(IPv4 라 V4 만) (A26 접점)
    assert_eq!(
        r["policies"][0]["filters"].as_u64().unwrap(),
        2 * 2 * 2 + 2,
        "{v}"
    );
    assert!(r["policies"][0]["address_block_notice"].is_string());
    assert_eq!(r["terminated"].as_array().unwrap().len(), 2);
    assert_eq!(r["pending"], serde_json::json!(["remove_autorun"]));
    assert_eq!(r["autoruns"].as_array().unwrap().len(), 1);
    {
        let k = kills.lock().unwrap();
        assert!(k.contains(&(2200, Some(t + 3 * 10_000_000))), "{k:?}");
        assert!(k.iter().all(|(pid, ct)| *pid != 2500 && ct.is_some()));
    }
    // 서비스가 남긴 사건도 알림으로 나가야 한다 (A19 발견: store.insert_event 직접 호출은 알림이 안 갔다)
    let mut kinds = Vec::new();
    while let Some(n) = c.next_notification(Duration::from_millis(500)) {
        kinds.push(n["params"]["kind"].as_str().unwrap_or("").to_string());
    }
    assert!(
        kinds.iter().any(|k| k == "cut_applied") && kinds.iter().any(|k| k == "cut_terminate"),
        "{kinds:?}"
    );
    // 확인
    for pol in r["policies"].as_array().unwrap() {
        let v = c.call("policy.confirm", serde_json::json!({"request_id": "1f3c2a1e-9b7d-4c6a-8e5f-123456789abc", "policy_id": pol["policy_id"], "version": pol["version"]}));
        assert!(v["result"].is_object(), "{v}");
    }
    // 새 자손: cmd 가 띄운 stage2 → 수집 배치(Batch) 로 들어오면 보충 + 종료
    kills.lock().unwrap().clear();
    let st = t + 100 * 10_000_000;
    rt.tx
        .send(Command::Batch(vec![Event {
            ts: st,
            source: "etw:process".into(),
            kind: EventKind::ProcessStart {
                pid: 3000,
                ppid: 2300,
                image: r"C:\Temp\stage2.exe".into(),
                create_time: Some(st),
            },
        }]))
        .unwrap();
    // Batch 는 그래프에 넣지 않으므로 부모 이미지는 그래프의 cmd.exe 로 찾는다
    let v = c.call("policy.list", serde_json::json!({}));
    assert_eq!(
        v["result"]["items"].as_array().unwrap().len(),
        1,
        "끊기는 정책 1건"
    );
    let k = kills.lock().unwrap().clone();
    assert_eq!(k, vec![(3000, Some(st))], "새 자손 종료 (생성 시각 키)");
    rt.shutdown();
}

/// 접점: graph 의 시스템 프로세스 목록 사본이 dsl 원본과 같아야 한다 (끊기 미리보기와 엔진 전개가 다르게 거르면 안 됨)
#[test]
fn system_image_lists_match_between_graph_and_dsl() {
    let mut a: Vec<&str> = graph::views::SYSTEM_IMAGES.to_vec();
    let mut b: Vec<&str> = dsl::validate::SYSTEM_IMAGES.to_vec();
    a.sort();
    b.sort();
    assert_eq!(a, b);
    // 판정 함수도 같은 결과 (graph 는 dsl 에 의존하지 않아 사본이 있다)
    for p in [
        r"C:\Windows\System32\svchost.exe",
        r"C:\Users\x\svchost.exe",
        r"C:\Windows\explorer.exe",
        r"C:\Windows\System32\explorer.exe",
        r"\SystemRoot\System32\csrss.exe",
        "svchost.exe",
        r"C:\Windows\System32\cmd.exe",
        "",
    ] {
        assert_eq!(
            graph::views::is_system_image(p),
            dsl::validate::is_system_image(p),
            "{p}"
        );
    }
}

/// 15차 Q2: 연결 중 관리자 그룹에서 빠지면 다음 변경 요청부터 거부 (캐시하지 않음)
#[test]
fn admin_is_rechecked_per_mutation() {
    let (rt, _, _) = boot();
    let mut c = Client::connect(&rt, 300, 1);
    c.hello();
    let v = c.call(
        "settings.set",
        serde_json::json!({"request_id": UUID, "voice": "plain"}),
    );
    assert!(v["result"].is_object(), "{v}");
    DEMOTED.store(true, Ordering::SeqCst);
    let v = c.call("settings.set", serde_json::json!({"request_id": "2f3c2a1e-9b7d-4c6a-8e5f-123456789abc", "voice": "expert"}));
    assert_eq!(v["error"]["code"], serde_json::json!(-32001), "{v}");
    // 조회는 계속 된다
    let v = c.call("policy.list", serde_json::json!({}));
    assert!(v["result"].is_object());
    rt.shutdown();
}

/// A23 변경 승인: 보기 모드(비관리자) UI 가 맡기고 → 승인 도우미(관리자)가 서비스 요약을 보고 → 실행. 보지 않은 내용은 실행하지 않는다.
#[test]
fn a23_change_stage_get_commit_and_digest_guard() {
    let kills = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (rt, _wall, _) = boot_with(Some(Box::new(RecHost(kills.clone()))));
    let (events, t) = a19_events();
    rt.tx.send(Command::Ingest(events)).unwrap();
    let mut ui = Client::connect(&rt, 200, 1); // 서명 OK, 비관리자 = 보기 모드 UI
    ui.hello();
    let v = ui.call("connections.list", serde_json::json!({"since_secs": 3600}));
    let root = v["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["pid"] == 2200)
        .unwrap()["process_id"]
        .as_i64()
        .unwrap();
    // 맡기기: 비관리자도 된다. 실행은 안 됨
    let v = ui.call("change.stage", serde_json::json!({"method": "cut.apply", "params": {"request_id": UUID, "story_root": root, "also": ["terminate"]}}));
    let cid = v["result"]["change_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{v}"))
        .to_string();
    assert!(kills.lock().unwrap().is_empty());
    assert_eq!(
        ui.call("policy.list", serde_json::json!({}))["result"]["items"]
            .as_array()
            .unwrap()
            .len(),
        0,
        "맡기기만으로는 적용 안 됨"
    );
    // 보기 모드 UI 는 요약을 볼 수도(get), 실행할 수도(commit) 없다
    assert_eq!(
        ui.call("change.get", serde_json::json!({"change_id": cid}))["error"]["code"],
        serde_json::json!(-32001)
    );
    assert_eq!(
        ui.call(
            "change.commit",
            serde_json::json!({"request_id": UUID, "change_id": cid, "digest": "0".repeat(64)})
        )["error"]["code"],
        serde_json::json!(-32001)
    );
    // 맡길 수 없는 것: 확인·중첩
    let v = ui.call("change.stage", serde_json::json!({"method": "policy.confirm", "params": {"request_id": UUID, "policy_id": 1, "version": 1}}));
    assert_eq!(v["error"]["code"], serde_json::json!(-32602));
    // 맡길 때 검증: needs_ack 미확인 → -32003 (UI 가 먼저 묻는다), 낱말은 입력과 같다
    let wide = "- name: wide\n  action: block\n  match: { direction: out, remote_port: [53] , process: ['C:/a/b.exe'] }\n";
    let v = ui.call(
        "change.stage",
        serde_json::json!({"method": "policy.apply", "params": {"request_id": UUID, "yaml": wide}}),
    );
    assert_eq!(v["error"]["code"], serde_json::json!(-32003), "{v}");
    let items = v["error"]["data"]["items"].clone();
    let v = ui.call("change.stage", serde_json::json!({"method": "policy.apply", "params": {"request_id": "2f3c2a1e-9b7d-4c6a-8e5f-123456789abc", "yaml": wide, "acknowledge": items}}));
    assert!(
        v["result"]["change_id"].is_string(),
        "받은 항목을 그대로 돌려보내면 통과해야 한다: {v}"
    );

    // 승인 도우미 (관리자)
    let mut helper = Client::connect(&rt, 100, 2);
    helper.hello();
    let g = helper.call("change.get", serde_json::json!({"change_id": cid}));
    let lines: Vec<String> = g["result"]["lines"]
        .as_array()
        .unwrap_or_else(|| panic!("{g}"))
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    let digest = g["result"]["digest"].as_str().unwrap().to_string();
    assert!(lines.iter().any(|l| l.contains("payload.exe")), "{lines:?}");
    assert!(
        lines.iter().any(|l| l.contains("203.0.113.9:8443/tcp")),
        "접속지 포함: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("PID 2200")),
        "끝낼 프로세스: {lines:?}"
    );
    assert!(
        g["result"]["staged_by"]
            .as_str()
            .unwrap()
            .contains("pid 200"),
        "맡긴 쪽 표시"
    );

    // 그사이 새 자손이 생기면(대상이 늘어남) 보여 준 요약과 달라진다 → 거부
    let st = t + 50 * 10_000_000;
    rt.tx
        .send(Command::Ingest(vec![Event {
            ts: st,
            source: "etw:process".into(),
            kind: EventKind::ProcessStart {
                pid: 2600,
                ppid: 2200,
                image: r"C:\Temp\dropper2.exe".into(),
                create_time: Some(st),
            },
        }]))
        .unwrap();
    let v = helper.call(
        "change.commit",
        serde_json::json!({"request_id": cid, "change_id": cid, "digest": digest}),
    );
    assert_eq!(
        v["error"]["code"],
        serde_json::json!(-32006),
        "보지 않은 내용은 실행하지 않는다: {v}"
    );
    assert!(kills.lock().unwrap().is_empty());
    // 다시 보여 주고 승인
    let g = helper.call("change.get", serde_json::json!({"change_id": cid}));
    assert!(g["result"]["lines"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l.as_str().unwrap().contains("dropper2.exe")));
    let digest = g["result"]["digest"].as_str().unwrap().to_string();
    let v = helper.call(
        "change.commit",
        serde_json::json!({"request_id": cid, "change_id": cid, "digest": digest}),
    );
    let pol = v["result"]["result"]["policies"][0].clone();
    assert!(pol["policy_id"].is_i64(), "{v}");
    assert_eq!(kills.lock().unwrap().len(), 3, "payload·cmd·dropper2 종료");
    // 같은 승인 다시 → 한 번만 실행
    let v2 = helper.call(
        "change.commit",
        serde_json::json!({"request_id": cid, "change_id": cid, "digest": digest}),
    );
    assert_eq!(
        v2["result"]["result"]["policies"][0]["policy_id"],
        pol["policy_id"]
    );
    assert_eq!(kills.lock().unwrap().len(), 3);
    // 도우미가 60초 확인
    let v = helper.call("policy.confirm", serde_json::json!({"request_id": "3f3c2a1e-9b7d-4c6a-8e5f-123456789abc", "policy_id": pol["policy_id"], "version": pol["version"]}));
    assert!(v["result"].is_object(), "{v}");
    // UI 는 결과와 정책 상태를 읽는다
    let r = ui.call("change.result", serde_json::json!({"change_id": cid}));
    assert_eq!(r["result"]["state"], serde_json::json!("done"), "{r}");
    assert_eq!(
        r["result"]["policies"][0]["state"],
        serde_json::json!("Confirmed"),
        "{r}"
    ); // policy.list 과 같은 표기
       // 기록에는 승인한 쪽·맡긴 쪽이 함께
    let h = helper.call(
        "policy.history",
        serde_json::json!({"policy_id": pol["policy_id"]}),
    );
    let hs = h.to_string();
    assert!(hs.contains("승인") && hs.contains("pid 200"), "{hs}");
    // 모르는 id
    let r = ui.call(
        "change.result",
        serde_json::json!({"change_id": "4f3c2a1e-9b7d-4c6a-8e5f-123456789abc"}),
    );
    assert_eq!(r["result"]["state"], serde_json::json!("expired"));
    rt.shutdown();
}

/// A23: 맡긴 변경은 5분 뒤 만료 (도우미를 늦게 띄워도 오래된 요청이 실행되지 않게)
#[test]
fn a23_staged_change_expires() {
    let (rt, wall, _) = boot();
    let mut ui = Client::connect(&rt, 200, 1);
    ui.hello();
    let v = ui.call("change.stage", serde_json::json!({"method": "policy.apply", "params": {"request_id": UUID, "yaml": SIMPLE}}));
    let cid = v["result"]["change_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{v}"))
        .to_string();
    let mut helper = Client::connect(&rt, 100, 2);
    helper.hello();
    let g = helper.call("change.get", serde_json::json!({"change_id": cid}));
    assert!(
        g["result"]["lines"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l.as_str().unwrap().contains("block-b")),
        "{g}"
    );
    let digest = g["result"]["digest"].as_str().unwrap().to_string();
    wall.fetch_add(svc::change::CHANGE_TTL_SECS + 5, Ordering::SeqCst);
    rt.tx.send(Command::Tick).unwrap();
    let v = helper.call(
        "change.commit",
        serde_json::json!({"request_id": cid, "change_id": cid, "digest": digest}),
    );
    assert_eq!(v["error"]["code"], serde_json::json!(-32602), "만료: {v}");
    assert_eq!(
        helper.call("policy.list", serde_json::json!({}))["result"]["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    rt.shutdown();
}

/// A24 (18차 Q1-a): 자손을 부풀려도 승인 창의 뒤 묶음(접속지)이 밀려나지 않는다
#[test]
fn a24_flooded_children_do_not_push_addresses_out_of_approval_summary() {
    let (rt, _, _) = boot();
    let (mut events, t) = a19_events();
    let s = 10_000_000;
    for i in 0..120u32 {
        let ts = t + 20 * s + i as i64;
        events.push(Event {
            ts,
            source: "etw:process".into(),
            kind: EventKind::ProcessStart {
                pid: 5000 + i,
                ppid: 2200,
                image: format!(
                    r"C:\Users\pjg\AppData\Local\Temp\{}\child{i}.exe",
                    "x".repeat(300)
                ),
                create_time: Some(ts),
            },
        });
    }
    rt.tx.send(Command::Ingest(events)).unwrap();
    let mut ui = Client::connect(&rt, 200, 1);
    ui.hello();
    let v = ui.call("connections.list", serde_json::json!({"since_secs": 3600}));
    let root = v["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["pid"] == 2200)
        .unwrap()["process_id"]
        .as_i64()
        .unwrap();
    let v = ui.call("change.stage", serde_json::json!({"method": "cut.apply", "params": {"request_id": UUID, "story_root": root, "also": ["terminate"]}}));
    let cid = v["result"]["change_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{v}"))
        .to_string();
    let mut helper = Client::connect(&rt, 100, 2);
    helper.hello();
    let g = helper.call("change.get", serde_json::json!({"change_id": cid}));
    let lines: Vec<String> = g["result"]["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    assert!(lines.len() <= svc::change::LINES_MAX, "{}", lines.len());
    assert!(
        lines.iter().any(|l| l.contains("203.0.113.9:8443/tcp")),
        "접속지 묶음이 보여야 한다: {lines:#?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("끝낼 프로세스 12")),
        "개수는 머리줄에: {lines:#?}"
    );
    assert!(lines.iter().any(|l| l.contains("외 ")), "나머지는 '외 N개'");
    // 긴 경로도 파일 이름(꼬리)은 남는다
    assert!(
        lines
            .iter()
            .filter(|l| l.contains("child"))
            .all(|l| l.ends_with(".exe") && l.chars().count() <= svc::change::LINE_MAX),
        "{lines:#?}"
    );
    rt.shutdown();
}

#[test]
fn a29_squat_event_links_to_graph_process_node_and_is_listed_for_users() {
    // 접점: 서비스가 남기는 대상 {pid, create_ft} 가 그래프 프로세스 키(PID@생성 시각, ingest 의 add_process)와 같은 형식이어야
    // UI 가 점유자의 프로세스 상세·이야기로 넘어간다
    let (rt, _, _) = boot();
    let (events, t) = a19_events();
    rt.tx.send(Command::Ingest(events)).unwrap();
    // a19_events 의 스냅샷 프로세스(pid 1000, 생성 시각 t)를 점유자로 쓴다 — 실제 서비스도 수집 시작 스냅샷이 같은 키를 만든다
    let squatter_ft = t;
    let pid = 1000u32;
    let mut ui = Client::connect(&rt, 200, 1);
    ui.hello();
    rt.tx
        .send(Command::RecordEventRef {
            kind: "pipe_squat".into(),
            severity: 3,
            detail: "다른 프로그램이 예전 파이프 이름을 차지하고 있습니다: PID 1000".into(),
            target: serde_json::json!({"type": "process", "pid": pid, "create_ft": squatter_ft, "image": "C:\\x\\squat.exe", "session": 1}).to_string(),
        })
        .unwrap();
    rt.tx
        .send(Command::RecordEvent {
            kind: "data_dir_held".into(),
            severity: 3,
            detail: "대체 폴더".into(),
        })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    // 사용자(관리자 아님)도 읽는다
    let v = ui.call("service.events", serde_json::json!({"since_secs": 86400}));
    let items = v["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{v}"));
    assert_eq!(items.len(), 2, "{v}");
    assert_eq!(items[0]["kind"], "data_dir_held", "새것부터");
    let sq = &items[1];
    assert_eq!(sq["kind"], "pipe_squat");
    assert_eq!(sq["target"]["pid"], 1000);
    let node = sq["target"]["node_id"]
        .as_i64()
        .unwrap_or_else(|| panic!("점유자가 그래프 노드로 이어져야 한다: {sq}"));
    let d = ui.call(
        "process.detail",
        serde_json::json!({"node_id": node, "max_depth": 4}),
    );
    assert!(
        d["result"].to_string().contains("explorer.exe"),
        "이어진 노드로 프로세스 상세가 열린다: {d}"
    );
    // 범위 검사
    let bad = ui.call("service.events", serde_json::json!({"since_secs": 0}));
    assert_eq!(bad["error"]["code"], -32602, "{bad}");
    rt.shutdown();
}

#[test]
fn a30_standard_user_sees_only_own_session_and_system() {
    // 22차 Q6: 사용자 A(세션 1) 의 이야기·연결·프로세스를 사용자 B(세션 2) 는 보지 못한다. 관리자·시스템(0)은 그대로
    let (rt, _, _) = boot();
    let (mut events, t) = a19_events();
    let s = 10_000_000;
    // a19_events: explorer 1000(스냅샷 t) → payload 2200 → cmd 2300·svchost 2500. 모두 세션 1 (사용자 A)
    for (pid, ct) in [(1000u32, t), (2200, t + 3 * s), (2300, t + 4 * s)] {
        events.push(Event {
            ts: t + 9 * s,
            source: "etw:process".into(),
            kind: EventKind::ProcessSession {
                pid,
                create_time: ct,
                session: 1,
            },
        });
    }
    events.push(Event {
        ts: t + 9 * s,
        source: "etw:process".into(),
        kind: EventKind::ProcessSession {
            pid: 2500,
            create_time: t + 4 * s,
            session: 0,
        },
    });
    // 사용자 B(세션 2) 의 프로세스 하나와 접속
    events.push(Event {
        ts: t + 10 * s,
        source: "etw:process".into(),
        kind: EventKind::ProcessStart {
            pid: 7000,
            ppid: 4,
            image: r"C:\Users\b\app.exe".into(),
            create_time: Some(t + 10 * s),
        },
    });
    events.push(Event {
        ts: t + 10 * s,
        source: "etw:process".into(),
        kind: EventKind::ProcessSession {
            pid: 7000,
            create_time: t + 10 * s,
            session: 2,
        },
    });
    events.push(Event {
        ts: t + 11 * s,
        source: "etw:network".into(),
        kind: EventKind::Connect {
            proc: ProcRef::new(7000, None),
            proto: Proto::Tcp,
            direction: Direction::Out,
            laddr: "10.0.0.2".into(),
            lport: 50100,
            raddr: "192.0.2.50".into(),
            rport: 443,
        },
    });
    rt.tx.send(Command::Ingest(events)).unwrap();

    let mut admin = Client::connect_session(&rt, 100, 1, Some(2));
    admin.hello();
    let mut b = Client::connect_session(&rt, 200, 2, Some(2));
    b.hello();
    let mut a = Client::connect_session(&rt, 201, 3, Some(1));
    a.hello();

    let pids = |c: &mut Client| -> Vec<i64> {
        let v = c.call("connections.list", serde_json::json!({"since_secs": 3600}));
        let mut p: Vec<i64> = v["result"]["items"]
            .as_array()
            .unwrap_or_else(|| panic!("{v}"))
            .iter()
            .map(|i| i["pid"].as_i64().unwrap())
            .collect();
        p.sort();
        p.dedup();
        p
    };
    assert_eq!(pids(&mut admin), vec![2200, 2500, 7000], "관리자는 전부");
    assert_eq!(
        pids(&mut b),
        vec![2500, 7000],
        "B 는 자기 것 + 시스템(svchost 세션 0)"
    );
    assert_eq!(pids(&mut a), vec![2200, 2500], "A 는 자기 것 + 시스템");

    // 이야기: payload(세션 1) 사건은 B 에게 안 보임
    let n = |c: &mut Client| {
        c.call("story.events", serde_json::json!({"level_min": "normal"}))["result"]["items"]
            .as_array()
            .map(|x| x.len())
            .unwrap_or(0)
    };
    assert!(n(&mut a) >= 1 && n(&mut admin) >= 1);
    assert_eq!(n(&mut b), 0, "다른 사용자 세션의 이야기는 숨김");
    let today_b = b.call("story.today", serde_json::json!({}));
    assert!(
        !today_b["result"].to_string().contains("payload.exe"),
        "오늘의 이야기에도 없음: {today_b}"
    );

    // 프로세스 상세·마인드맵: 다른 사용자 노드는 "없음"과 같은 오류 (있는지도 알리지 않음)
    let v = admin.call("connections.list", serde_json::json!({"since_secs": 3600}));
    let payload_node = v["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["pid"] == 2200)
        .unwrap()["process_id"]
        .clone();
    let d = b.call(
        "process.detail",
        serde_json::json!({"node_id": payload_node, "max_depth": 4}),
    );
    assert_eq!(d["error"]["code"], -32602, "{d}");
    let g = b.call(
        "graph.neighbors",
        serde_json::json!({"node_id": payload_node, "max_depth": 4}),
    );
    assert_eq!(g["error"]["code"], -32602, "{g}");
    let ok = a.call(
        "graph.neighbors",
        serde_json::json!({"node_id": payload_node, "max_depth": 4}),
    );
    assert!(
        ok["result"]["branches"]
            .as_array()
            .is_some_and(|x| !x.is_empty()),
        "주인은 본다: {ok}"
    );
    let c = b.call(
        "cut.preview",
        serde_json::json!({"story_root": payload_node}),
    );
    assert_eq!(c["error"]["code"], -32602, "{c}");

    // 서비스 사건: 다른 세션 점유자는 문장·대상을 감춤
    rt.tx
        .send(Command::RecordEventRef { kind: "pipe_squat".into(), severity: 3, detail: "PID 2200 C:\\Users\\a\\payload.exe".into(), target: serde_json::json!({"type": "process", "pid": 2200, "create_ft": t + 3 * s, "image": "x", "session": 1}).to_string() })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let ev_b = b.call("service.events", serde_json::json!({}));
    let item = &ev_b["result"]["items"][0];
    assert!(
        item["target"].is_null() && !item["detail"].as_str().unwrap().contains("payload"),
        "{ev_b}"
    );
    let ev_a = a.call("service.events", serde_json::json!({}));
    assert!(
        ev_a["result"]["items"][0]["target"]["node_id"].is_i64(),
        "{ev_a}"
    );
    rt.shutdown();
}

/// 구조 개선 A: 엔진이 무거운 조회로 막혀 있어도 hello 는 바로 답한다(L040 설치 직후 "연결되지 않음")
#[test]
fn hello_answers_while_engine_is_busy() {
    let (rt, _, _) = boot();
    rt.tx
        .send(svc::runtime::Command::DevForce("delay".into()))
        .unwrap();
    let mut a = Client::connect(&rt, 100, 1);
    a.hello();
    // a 의 목록 조회가 엔진을 2.5초 붙잡는다
    let line = serde_json::to_string(&api::Request::new(99, "policy.list", serde_json::json!({})))
        .unwrap();
    a.to_server.send(line).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let mut b = Client::connect(&rt, 100, 2);
    let t = std::time::Instant::now();
    let v = b.hello();
    assert_eq!(v["result"]["server_version"], serde_json::json!("0.1.0"));
    assert!(
        t.elapsed() < Duration::from_millis(1500),
        "hello 가 엔진을 기다렸다: {:?}",
        t.elapsed()
    );
    // 27차 Gemini Q1: 엔진이 한 일에 묶여 있으면 hello 가 그 시간을 알려 준다(연결 중 다시 불러도 엔진 밖에서)
    // (값 자체는 전역이라 병렬 시험의 다른 엔진과 섞인다 — 계산은 runtime 단위 시험에서)
    let v = b.hello();
    assert!(v["result"]["engine_busy_ms"].is_u64(), "{v}");
    rt.shutdown();
}

/// 27차: 보관 정리가 실제로 돈다(주기 판정 뒤) — 설정한 정책이 retention.get 에 보이고, 마지막 정리 결과가 남는다
#[test]
fn retention_runs_after_judge_and_uses_settings() {
    let (rt, _, _) = boot();
    let mut c = Client::connect(&rt, 100, 1);
    c.hello();
    let v = c.call("retention.get", serde_json::json!({}));
    assert_eq!(
        v["result"]["raw_days"],
        serde_json::json!(7),
        "기본 정책: {v}"
    );
    assert!(v["result"]["last"].is_null(), "아직 정리 전: {v}");
    let v = c.call(
        "retention.set",
        serde_json::json!({"request_id": UUID, "raw_days": 3}),
    );
    assert!(v["result"].is_object(), "{v}");
    rt.tx.send(Command::Judge).unwrap();
    let v = c.call("retention.get", serde_json::json!({}));
    assert_eq!(v["result"]["raw_days"], serde_json::json!(3), "{v}");
    assert_eq!(v["result"]["last"]["ok"], serde_json::json!(true), "{v}");
    // 이상한 값은 안전 범위로(0 이하 → 기본)
    let v = c.call(
        "retention.set",
        serde_json::json!({"request_id": "2f3c2a1e-9b7d-4c6a-8e5f-123456789abd", "raw_days": -5}),
    );
    assert!(v["result"].is_object(), "{v}");
    let v = c.call("retention.get", serde_json::json!({}));
    assert_eq!(v["result"]["raw_days"], serde_json::json!(7), "{v}");
    rt.shutdown();
}

/// 10판 5-9 (1) + 정상 처리 결함: 프로세스에서 시작한 사건(복구 수단 삭제)은 5장 의심, "이건 정상입니다"는 거부(전에는 효과 없는 성공)
#[test]
fn recovery_inhibit_story_and_process_root_feedback_is_refused() {
    let (rt, _wall, _) = boot();
    let mut a = Client::connect(&rt, 100, 1);
    a.hello();
    let t = svc::runtime::unix_to_filetime(T0);
    let vss = r"C:\Windows\System32\vssadmin.exe";
    let ev = |ts: i64, source: &str, kind: EventKind| Event {
        ts,
        source: source.into(),
        kind,
    };
    rt.tx
        .send(Command::Ingest(vec![
            ev(
                t,
                "snapshot",
                EventKind::ProcessSnapshot {
                    pid: 1000,
                    ppid: 4,
                    image: r"C:\Windows\explorer.exe".into(),
                    create_time: t,
                    services: vec![],
                },
            ),
            ev(
                t + 10_000_000,
                "etw:process",
                EventKind::ProcessStart {
                    pid: 3100,
                    ppid: 1000,
                    image: vss.into(),
                    create_time: Some(t + 10_000_000),
                },
            ),
            ev(
                t + 10_000_000,
                "etw:process",
                EventKind::ProcessCommand {
                    proc: graph::event::ProcRef::new(3100, Some(t + 10_000_000)),
                    cmdline: "vssadmin delete shadows /all /quiet".into(),
                    tool: None,
                },
            ),
        ]))
        .unwrap();
    let v = a.call(
        "story.events",
        serde_json::json!({"level_min": "suspicious"}),
    );
    let items = v["result"]["items"].as_array().unwrap();
    let it = items
        .iter()
        .find(|x| x["title"].as_str().unwrap_or("").contains("vssadmin.exe"))
        .unwrap_or_else(|| panic!("{v}"));
    assert!(
        it["title"].as_str().unwrap().contains("5장 파괴 징후"),
        "{it}"
    );
    assert_eq!(it["feedback_ok"], serde_json::json!(false));
    let v = a.call(
        "judge.feedback_normal",
        serde_json::json!({"request_id": UUID, "root": it["root"]}),
    );
    assert!(v["error"].is_object(), "{v}");
    rt.shutdown();
}

/// 첫 실행 관찰실 (17판 23-2 ①): 설정 왕복(관리자만) → 수집 배치 → 서비스 사건·알림 → 이야기 카드 한 줄. 두 번째 실행·끄기는 조용히
#[test]
fn first_run_watch_settings_notify_and_story_line() {
    let (rt, _, _) = boot();
    let mut a = Client::connect(&rt, 100, 1);
    a.hello();
    // 일반 사용자는 바꿀 수 없다
    let mut u = Client::connect(&rt, 200, 2);
    u.hello();
    let v = u.call(
        "settings.set",
        serde_json::json!({"request_id": UUID, "first_run_watch": "off"}),
    );
    assert!(v["error"].is_object(), "{v}");
    // 이상한 값 거부, 정상 값 왕복
    let v = a.call(
        "settings.set",
        serde_json::json!({"request_id": UUID, "first_run_minutes": 15}),
    );
    assert!(v["error"].is_object(), "{v}");
    let v = a.call(
        "settings.set",
        serde_json::json!({"request_id": "1f3c2a1e-9b7d-4c6a-8e5f-123456789abc", "first_run_watch": "block", "first_run_minutes": 5}),
    );
    // 방식 나: block 을 고르면 이 관리자 요청으로 우산 정책 1건 — 60초 확인 대상으로 돌려준다
    let umb = v["result"]["policies"][0].clone();
    assert!(umb["policy_id"].is_i64(), "{v}");
    assert_eq!(umb["filters"], 0, "{v}");
    let v = a.call("settings.get", serde_json::json!({}));
    assert_eq!(v["result"]["first_run_watch"], "block", "{v}");
    assert_eq!(v["result"]["first_run_minutes"], 5, "{v}");
    assert_eq!(v["result"]["first_run_umbrella"]["state"], "Applied", "{v}");
    a.call("events.subscribe", serde_json::json!({}));

    let t = svc::runtime::unix_to_filetime(T0);
    let exe = r"C:\Users\pjg\Downloads\tool.exe";
    let ev = |ts: i64, kind: EventKind| Event {
        ts,
        source: "test".into(),
        kind,
    };
    let start = |pid: u32, ts: i64| {
        ev(
            ts,
            EventKind::ProcessStart {
                pid,
                ppid: 10,
                image: exe.into(),
                create_time: Some(ts),
            },
        )
    };
    let first = vec![
        ev(
            t - 100,
            EventKind::ProcessSnapshot {
                pid: 10,
                ppid: 4,
                image: r"C:\Windows\explorer.exe".into(),
                create_time: t - 100,
                services: vec![],
            },
        ),
        start(20, t),
    ];
    // 실제 서비스 순서: 저장 스레드가 그래프에 넣고(Ingest 역할) 복사본을 엔진에 Batch 로
    rt.tx.send(Command::Ingest(first.clone())).unwrap();
    rt.tx.send(Command::Batch(first)).unwrap();
    // 서명·출신은 나중 배치로 온다 → 그때 판단
    let later = vec![
        ev(
            t + 1,
            EventKind::Signature {
                path: exe.into(),
                signer: None,
                issuer: None,
                status: "nosignature".into(),
                catalog: false,
            },
        ),
        ev(
            t + 1,
            EventKind::Downloaded {
                path: exe.into(),
                host_url: Some("https://dl.example.com/tool.exe".into()),
                referrer_url: None,
                zone_id: Some(3),
            },
        ),
    ];
    rt.tx.send(Command::Ingest(later.clone())).unwrap();
    rt.tx.send(Command::Batch(later)).unwrap();
    let mut got = None;
    for _ in 0..5 {
        if let Some(n) = a.next_notification(Duration::from_secs(2)) {
            if n["params"]["kind"] == "first_run_watch" {
                got = Some(n);
                break;
            }
        }
    }
    let n = got.expect("첫 실행 알림");
    let d = n["params"]["detail"].as_str().unwrap();
    assert!(
        d.starts_with("인터넷에서 받은 서명 없는 프로그램이 처음 실행됐습니다 · 5분 동안 관찰: "),
        "{d}"
    );
    assert!(
        !d.contains("(나가는 연결 차단)"),
        "막지 않았으면 차단이라고 쓰지 않는다: {d}"
    );
    assert!(
        d.contains("관찰실 차단 정책이 확인된 상태가 아니어서"),
        "확인 전에는 막지 않는다: {d}"
    );
    assert!(d.contains("dl.example.com"), "{d}");
    // 서비스 사건: 대상 프로세스로 이어지고 관찰 끝 시각을 가진다
    let v = a.call("service.events", serde_json::json!({"since_secs": 86400}));
    let items: Vec<&serde_json::Value> = v["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "first_run_watch")
        .collect();
    assert_eq!(items.len(), 1, "{v}");
    let tg = &items[0]["target"];
    assert_eq!(tg["origin_host"], "dl.example.com", "{tg}");
    assert_eq!(tg["until_ts"], serde_json::json!(T0 + 300), "{tg}");
    assert_eq!(tg["blocked"], false);
    assert!(tg["node_id"].is_i64(), "프로세스 노드로 이어진다: {tg}");
    // 17판 23-2 ③ 변경 장부: 관찰 대상이면 열리고(자손 트리 사실), 아무 프로세스나 열리지는 않는다
    let v = a.call("ledger.get", serde_json::json!({"node_id": tg["node_id"]}));
    assert!(v["result"]["run"]["procs"].is_array(), "{v}");
    let v = a.call("ledger.get", serde_json::json!({"node_id": 1}));
    assert!(v["error"].is_object(), "{v}");
    // 정책 화면: 우산 1건(확인 대기, 그 아래 차단 없음)
    let v = a.call("policy.list", serde_json::json!({}));
    let items = v["result"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{v}");
    assert_eq!(items[0]["origin"]["kind"], "first_run_watch", "{v}");
    assert_eq!(items[0]["child_blocks"].as_array().unwrap().len(), 0);
    // 사람이 확인 → 다음 대상부터 막는다
    let v = a.call(
        "policy.confirm",
        serde_json::json!({"request_id": "5f3c2a1e-9b7d-4c6a-8e5f-123456789abc", "policy_id": umb["policy_id"], "version": umb["version"]}),
    );
    assert!(v["result"].is_object(), "{v}");
    let blk = r"C:\Users\pjg\Downloads\blk.exe";
    let evs = vec![
        ev(
            t + 10,
            EventKind::ProcessStart {
                pid: 25,
                ppid: 10,
                image: blk.into(),
                create_time: Some(t + 10),
            },
        ),
        ev(
            t + 11,
            EventKind::Signature {
                path: blk.into(),
                signer: None,
                issuer: None,
                status: "nosignature".into(),
                catalog: false,
            },
        ),
        ev(
            t + 11,
            EventKind::Downloaded {
                path: blk.into(),
                host_url: None,
                referrer_url: None,
                zone_id: Some(3),
            },
        ),
    ];
    rt.tx.send(Command::Ingest(evs.clone())).unwrap();
    rt.tx.send(Command::Batch(evs)).unwrap();
    let mut got = None;
    for _ in 0..5 {
        if let Some(n) = a.next_notification(Duration::from_secs(2)) {
            if n["params"]["kind"] == "first_run_watch" {
                got = Some(n);
                break;
            }
        }
    }
    let d = got.expect("막은 알림")["params"]["detail"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(d.contains("5분 동안 관찰(나가는 연결 차단): "), "{d}");
    let v = a.call("policy.list", serde_json::json!({}));
    let kids = v["result"]["items"][0]["child_blocks"].as_array().unwrap();
    assert!(!kids.is_empty(), "{v}");
    assert!(kids.iter().all(|k| k["path"] == blk), "{v}");
    assert_eq!(
        v["result"]["address_blocks"], 0,
        "주소 차단과 섞이지 않는다: {v}"
    );
    let v = a.call("service.events", serde_json::json!({"since_secs": 86400}));
    let ev_b = v["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "first_run_watch" && e["target"]["image"] == blk)
        .unwrap_or_else(|| panic!("{v}"))
        .clone();
    assert_eq!(ev_b["target"]["blocked"], true);
    assert_eq!(ev_b["target"]["umbrella_policy_id"], umb["policy_id"]);
    let h = a.call(
        "policy.history",
        serde_json::json!({"policy_id": umb["policy_id"]}),
    );
    assert!(
        h["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["action"] == "child_block" && x["actor"] == "system:first_run_watch"),
        "{h}"
    );
    // 두 번째 실행 → 사건 없음
    let second = vec![start(21, t + 50)];
    rt.tx.send(Command::Ingest(second.clone())).unwrap();
    rt.tx.send(Command::Batch(second)).unwrap();
    // 이야기 카드: 뿌리 파일의 관찰 한 줄
    rt.tx.send(Command::Judge).unwrap();
    let v = a.call("story.events", serde_json::json!({"level_min": "normal"}));
    let card = v["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["root_image"] == exe)
        .unwrap_or_else(|| panic!("{v}"))
        .clone();
    assert_eq!(
        card["first_run_watch"]["text"],
        "인터넷에서 받은 서명 없는 프로그램이 처음 실행됐습니다 · 5분 동안 관찰",
        "{card}"
    );
    let v = a.call("service.events", serde_json::json!({"since_secs": 86400}));
    let n_watch = v["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "first_run_watch")
        .count();
    assert_eq!(n_watch, 2, "두 번째 실행은 알리지 않는다: {v}");
    // 끄면 새 프로그램도 조용하다
    let v = a.call(
        "settings.set",
        serde_json::json!({"request_id": "3f3c2a1e-9b7d-4c6a-8e5f-123456789abc", "first_run_watch": "off"}),
    );
    assert!(v["result"].is_object(), "{v}");
    // block → off: 우산과 그 아래 차단을 걷는다
    let v = a.call("policy.list", serde_json::json!({}));
    assert_eq!(v["result"]["items"].as_array().unwrap().len(), 0, "{v}");
    let v = a.call("settings.get", serde_json::json!({}));
    assert!(v["result"]["first_run_umbrella"].is_null(), "{v}");
    let other = r"C:\Users\pjg\Downloads\other.exe";
    let evs = vec![
        ev(
            t + 60,
            EventKind::ProcessStart {
                pid: 30,
                ppid: 10,
                image: other.into(),
                create_time: Some(t + 60),
            },
        ),
        ev(
            t + 61,
            EventKind::Signature {
                path: other.into(),
                signer: None,
                issuer: None,
                status: "nosignature".into(),
                catalog: false,
            },
        ),
        ev(
            t + 61,
            EventKind::Downloaded {
                path: other.into(),
                host_url: None,
                referrer_url: None,
                zone_id: Some(3),
            },
        ),
    ];
    rt.tx.send(Command::Ingest(evs.clone())).unwrap();
    rt.tx.send(Command::Batch(evs)).unwrap();
    let v = a.call("service.events", serde_json::json!({"since_secs": 86400}));
    let n_watch = v["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "first_run_watch")
        .count();
    assert_eq!(n_watch, 2, "끄기: {v}");
    rt.shutdown();
}

/// AI 에이전트 감시 (14판 20-5): 미리 계산 전에는 ready=false(조회 때 계산하지 않음), 주기 판정 뒤에는 도구별 목록. 범위 검사
#[test]
fn agents_list_reads_precomputed_cache() {
    let (rt, _, _) = boot();
    let mut a = Client::connect(&rt, 100, 1);
    a.hello();
    let v = a.call("agents.list", serde_json::json!({}));
    assert_eq!(v["result"]["ready"], false, "{v}");
    let v = a.call("agents.list", serde_json::json!({"days": 8}));
    assert!(v["error"].is_object(), "{v}");
    let t = svc::runtime::unix_to_filetime(T0) - 3600 * 10_000_000;
    let evs = vec![
        Event {
            ts: t,
            source: "etw:process".into(),
            kind: EventKind::ProcessStart {
                pid: 7000,
                ppid: 4,
                image: r"C:\Users\pjg\AppData\Local\AnthropicClaude\claude.exe".into(),
                create_time: Some(t),
            },
        },
        Event {
            ts: t + 10_000_000,
            source: "etw:network".into(),
            kind: EventKind::Connect {
                proc: ProcRef::new(7000, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50000,
                raddr: "203.0.113.40".into(),
                rport: 443,
            },
        },
    ];
    rt.tx.send(Command::Ingest(evs)).unwrap();
    rt.tx.send(Command::Judge).unwrap();
    let v = a.call("agents.list", serde_json::json!({"days": 1}));
    assert_eq!(v["result"]["ready"], true, "{v}");
    let items = v["result"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{v}");
    assert_eq!(items[0]["key"], "claude");
    assert_eq!(items[0]["found_by"], "image");
    assert!(
        items[0]["run"]["remotes"]
            .to_string()
            .contains("203.0.113.40"),
        "{v}"
    );
    rt.shutdown();
}
