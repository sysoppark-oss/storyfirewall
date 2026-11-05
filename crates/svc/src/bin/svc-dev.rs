//! 개발용 가짜 서비스 (A15). UI 를 Linux/Windows 어디서든 실제 서비스 없이 개발·시연한다.
//!
//! svc-dev [--listen 127.0.0.1:7878] [--non-admin] [--admin-listen 127.0.0.1:7879] [--no-demo]
//! `--admin-listen`: 관리자로 치는 두 번째 포트 — 승인 도우미 흉내(A23, UI 종단 시험의 보기 모드 경로)
//! 프로토콜은 파이프와 같다(한 줄 JSON). 가짜 WFP, 메모리 DB, 재현 이벤트(payload 사건 + 브라우저 활동).

use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dsl::expand::Resolver;
use engine::backend::{FakeWfp, GraphQuery, NoGraph, WfpBackend};
use engine::Clock;
use svc::dev::{DevAuthn, TcpTransport};
use svc::runtime::{Parts, Runtime};
use svc::Command;

struct SysClock;
impl Clock for SysClock {
    fn wall(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }
    fn mono(&self) -> i64 {
        static T0: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        T0.get_or_init(std::time::Instant::now).elapsed().as_secs() as i64
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
struct P;
impl Parts for P {
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
            Box::new(SysClock),
            Box::new(R),
            rusqlite::Connection::open_in_memory().unwrap(),
            // 구조 개선 C: 실제 서비스처럼 파일 DB — 읽기 작업자 경로(읽기 전용 연결)를 UI 시험이 거치게 한다. 매번 새로
            {
                let dir = std::env::temp_dir().join(format!("svc-dev-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                graph::store::Store::open(dir.join("graph.db")).unwrap()
            },
            vec!["story-firewall-ui.exe".into()],
        )
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut listen = "127.0.0.1:7878".to_string();
    let mut admin = true;
    let mut demo = true;
    let mut admin_listen: Option<String> = None;
    let mut health: Option<String> = Some("normal".into());
    let mut force: Option<String> = None;
    let mut live = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                listen = args.get(i + 1).cloned().unwrap_or(listen);
                i += 1;
            }
            "--non-admin" => admin = false,
            "--admin-listen" => {
                admin_listen = args.get(i + 1).cloned();
                i += 1;
            }
            "--no-demo" => demo = false,
            // C1 시연: --health normal|lost
            "--health" => {
                i += 1;
                health = args.get(i).cloned();
            }
            // D013 시연: --force empty|error|delay|busy (목록 조회를 빈 응답·오류·2.5초 지연·busy 로)
            // D030-3 캡처: 3초마다 새 접속 하나(연결 표 "새 접속 N건" 알약)
            "--live" => live = true,
            "--force" => {
                i += 1;
                force = args.get(i).cloned();
            }
            _ => {}
        }
        i += 1;
    }
    let rt = Runtime::start_with(Box::new(P), "0.1.0-dev", Some(Box::new(svc::dev::DevHost)));
    if demo {
        // SF_GEO_DIR 이 있으면 실제 DB-IP 파일 위에 시연값(설정 화면 기준일 캡처용)
        let base = std::env::var("SF_GEO_DIR")
            .ok()
            .map(|d| geo::Geo::open_dir(std::path::Path::new(&d)).0)
            .unwrap_or_default();
        geo::init_global(svc::demo::demo_geo_on(base));
        let now_ft = SysClock.wall() * 10_000_000 + 116_444_736_000_000_000;
        for hb in svc::demo::demo_heartbeats(now_ft) {
            rt.tx.send(Command::DevHeartbeat(hb)).unwrap();
        }
        rt.tx
            .send(Command::Ingest(svc::demo::demo_events(now_ft)))
            .unwrap();
        rt.tx.send(Command::Judge).unwrap();
        if let Some(h) = &health {
            let now = SysClock.wall();
            let ft = |u: i64| u * 10_000_000 + 116_444_736_000_000_000;
            let v = if h == "stalled" {
                serde_json::json!({ "stalled": true, "lost_24h": 0, "gaps_24h": [], "clock_changes_24h": [] })
            } else if h == "lost" {
                serde_json::json!({ "lost_24h": 214, "gaps_24h": [{ "from_ts": ft(now - 3600), "to_ts": ft(now - 3540), "events": 214, "reason": "channel_full" }], "clock_changes_24h": [now - 7200] })
            } else {
                // 25차 Q1: 시연 데이터의 기록 없는 구간(서비스 중지·절전)과 같은 값
                let [hf, ht] = svc::demo::demo_heartbeats(now_ft);
                serde_json::json!({ "lost_24h": 0, "gaps_24h": [{ "from_ts": hf, "to_ts": ht, "events": 0, "reason": "no_record" }], "clock_changes_24h": [now - 5400] })
            };
            rt.tx.send(Command::DevHealth(v)).unwrap();
        }
    }
    if let Some(f) = force {
        rt.tx.send(Command::DevForce(f)).unwrap();
    }
    if live {
        let tx = rt.tx.clone();
        std::thread::spawn(move || {
            for n in 0u32.. {
                std::thread::sleep(std::time::Duration::from_secs(3));
                let now_ft = SysClock.wall() * 10_000_000 + 116_444_736_000_000_000;
                if tx
                    .send(Command::Ingest(svc::demo::demo_live_connect(now_ft, n)))
                    .is_err()
                {
                    break;
                }
            }
        });
    }
    let conn_id = Arc::new(AtomicU64::new(0));
    if let Some(al) = admin_listen {
        let l = TcpListener::bind(&al).expect("bind admin");
        eprintln!("svc-dev: admin (approve helper) on {al}");
        let tx = rt.tx.clone();
        let ids = conn_id.clone();
        std::thread::spawn(move || accept(l, tx, ids, true));
    }
    let listener = TcpListener::bind(&listen).expect("bind");
    eprintln!("svc-dev: listening on {listen} (admin={admin}, demo={demo})");
    accept(listener, rt.tx.clone(), conn_id, admin);
}

fn accept(
    listener: TcpListener,
    tx0: std::sync::mpsc::Sender<Command>,
    conn_id: Arc<AtomicU64>,
    admin: bool,
) {
    for stream in listener.incoming().flatten() {
        let id = conn_id.fetch_add(1, Ordering::SeqCst) + 1;
        let tx = tx0.clone();
        std::thread::spawn(move || {
            let Ok(mut t) = TcpTransport::new(stream) else {
                return;
            };
            let why = svc::handler::serve(id, &mut t, &DevAuthn { admin }, &tx);
            eprintln!("svc-dev: connection {id} closed: {why}");
        });
    }
}
