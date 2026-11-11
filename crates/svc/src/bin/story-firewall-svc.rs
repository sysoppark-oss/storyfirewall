//! 제품 서비스 본체 (A26). svc-poc 의 시험 모드에 흩어져 있던 것을 하나로 묶는다.
//!
//! story-firewall-svc install [--test-signer CN]   : SCM 등록(자동 시작, 실패 시 재시작). 명령줄 = 이 exe run [...]
//! story-firewall-svc uninstall                      : 중지 → 등록 해제 → 우리 WFP 필터·Sublayer·Provider 삭제 → 공개 이름 삭제
//! story-firewall-svc start | stop | status
//! story-firewall-svc run [--test-signer CN]         : SCM 이 띄우는 본체
//! story-firewall-svc console <secs> [--test-signer CN] [--data-base DIR] : 같은 본체를 앞에서 N 초 (개발·시험)
//!
//! 본체 = 데이터 폴더(%ProgramData%\StoryFirewall, 소유자 검사·보호 DACL) → 고정 파이프 이름 점유자 점검 →
//! 엔진(실제 WFP, 그래프 기반 조회기, 재시작 대조) → 수집 세션(ETW, 배치 복사본 → 엔진) → 1분마다 판정 →
//! 파이프(무작위 이름 → HKLM 공개, 연결마다 스레드) → SCM 이벤트(중지·절전 복귀·시각 변경).
//! `--test-signer` 는 test-signer feature 빌드에서만 받는다(배포 빌드는 제품 서명자만).

#[cfg(any(windows, feature = "host-check"))]
fn main() {
    real::main()
}

#[cfg(not(any(windows, feature = "host-check")))]
fn main() {
    eprintln!("story-firewall-svc 는 Windows 전용입니다");
}

#[cfg(any(windows, feature = "host-check"))]
mod real {
    /// 화면 상태 줄·service.log 에 보이는 판 번호. 릴리스 빌드는 태그(v0.1.3 → 0.1.3)를 SF_VERSION 으로 넘긴다 —
    /// 전에는 크레이트 판(0.1.0)이 그대로 보여 v0.1.3 으로 업데이트해도 "0.1.0판"이었다(사용자 제보 2026-11-07)
    const SVC_VERSION: &str = match option_env!("SF_VERSION") {
        Some(v) => v,
        None => env!("CARGO_PKG_VERSION"),
    };

    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc::{self, Receiver};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use dsl::expand::Resolver;
    use engine::backend::{GraphQuery, WfpBackend};
    use engine::Clock;
    use svc::resolver::{GraphAddresses, GraphResolver};
    use svc::runtime::{Command, Parts, Runtime};
    use svc::win::service::ServiceEvent;
    use svc::win::wfp_backend::{NoWfp, WinWfp};
    use svc::win::{authn, data_dir, pipe, pipe_name, process, service, time};

    pub const SERVICE_NAME: &str = "StoryFirewall";
    const DISPLAY: &str = "Story Firewall";
    const DESCRIPTION: &str =
        "이야기형 연결 분석 방화벽: 연결 수집·판정·정책 적용 (로컬 처리, 외부 전송 없음)";
    /// 자기 보호: 이 이미지들은 정책으로 막을 수 없다 (가드)
    const PROTECTED: &[&str] = &["story-firewall-svc.exe", "story-firewall-ui.exe"];
    /// 판정 주기
    const JUDGE_EVERY: Duration = Duration::from_secs(svc::runtime::JUDGE_EVERY_SECS);
    /// 28차 Gemini Q5: 파이프 동시 연결 상한(UI·승인 도우미·노트북 시험 도구를 합쳐도 넉넉한 수)
    const MAX_PIPE_CONNECTIONS: usize = 16;

    #[derive(Clone, Default)]
    struct Opts {
        test_signer: Option<String>,
        /// 시험 빌드 전용: 시험 인증서 잎 SHA-256 지문 고정(신뢰할 루트에 넣지 않는 개발 PC 설치용, authn::WinAuthn::with_test_pin)
        test_pin: Option<String>,
        /// 시험 빌드 전용: 데이터 폴더 기준 경로 대체(HKLM 기록 안 함) — 핸들 쥐기 공격 시험용
        data_base: Option<PathBuf>,
    }

    fn parse_opts(args: &[String]) -> Result<Opts, String> {
        let mut o = Opts::default();
        if let Some(i) = args.iter().position(|a| a == "--test-signer") {
            if !cfg!(feature = "test-signer") {
                return Err("--test-signer 는 시험 빌드에서만".into());
            }
            o.test_signer = Some(args.get(i + 1).cloned().ok_or("--test-signer CN")?);
        }
        if let Some(i) = args.iter().position(|a| a == "--test-signer-sha256") {
            if !cfg!(feature = "test-signer") {
                return Err("--test-signer-sha256 는 시험 빌드에서만".into());
            }
            let v = args
                .get(i + 1)
                .cloned()
                .ok_or("--test-signer-sha256 HEX64")?
                .to_ascii_lowercase();
            if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("--test-signer-sha256 는 16진 64자".into());
            }
            o.test_pin = Some(v);
        }
        if let Some(i) = args.iter().position(|a| a == "--data-base") {
            if !cfg!(feature = "test-signer") {
                return Err("--data-base 는 시험 빌드에서만".into());
            }
            o.data_base = Some(PathBuf::from(
                args.get(i + 1).cloned().ok_or("--data-base 경로")?,
            ));
        }
        Ok(o)
    }

    /// 서비스 기록 (데이터 폴더의 service.log, UTC unix 초)
    #[derive(Clone)]
    struct Log(Arc<Mutex<Option<std::fs::File>>>);
    impl Log {
        fn open(path: &Path) -> Self {
            Log(Arc::new(Mutex::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .ok(),
            )))
        }
        fn w(&self, s: impl AsRef<str>) {
            if let Ok(mut g) = self.0.lock() {
                if let Some(f) = g.as_mut() {
                    let _ = writeln!(f, "{} {}", time::WinClock::default().wall(), s.as_ref());
                    let _ = f.flush();
                }
            }
        }
    }

    struct Product {
        dir: PathBuf,
        log: Log,
    }
    impl Parts for Product {
        #[allow(clippy::type_complexity)]
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
            let g = self.dir.join("graph.db").to_string_lossy().into_owned();
            let backend: Box<dyn WfpBackend> = match WinWfp::open() {
                Ok(w) => Box::new(w),
                Err(e) => {
                    self.log
                        .w(format!("wfp: open failed ({e}) — 보기 전용으로 동작"));
                    Box::new(NoWfp(e))
                }
            };
            let gq: Box<dyn GraphQuery> =
                Box::new(GraphAddresses::open(&g).expect("graph (addresses)"));
            let resolver: Box<dyn Resolver> =
                Box::new(GraphResolver::open(&g).expect("graph (resolver)"));
            let conn = rusqlite::Connection::open(self.dir.join("engine.db")).expect("engine db");
            let store = graph::store::Store::open(&g).expect("graph db");
            (
                backend,
                gq,
                Box::new(time::WinClock::default()),
                resolver,
                conn,
                store,
                PROTECTED.iter().map(|s| s.to_string()).collect(),
            )
        }
    }

    fn authn_for(opts: &Opts, h: windows_sys::Win32::Foundation::HANDLE) -> authn::WinAuthn {
        #[cfg(feature = "test-signer")]
        if let Some(pin) = &opts.test_pin {
            return authn::WinAuthn::with_test_pin(pin, h);
        }
        #[cfg(feature = "test-signer")]
        if let Some(cn) = &opts.test_signer {
            return authn::WinAuthn::with_test_signer(cn, h);
        }
        let _ = opts;
        authn::WinAuthn::new(h)
    }

    /// 서비스 본체. `events` 가 Stop/Shutdown 을 주거나 끊기면 끝난다.
    fn body(events: Receiver<ServiceEvent>, opts: Opts) {
        // ① 데이터 폴더
        let (base, persist) = match &opts.data_base {
            Some(b) => (b.clone(), false),
            None => (data_dir::base(), true),
        };
        let chosen = match data_dir::ensure(&base, persist) {
            Ok(x) => x,
            Err(e) => {
                // 기록할 곳도 없다: 임시 폴더에 남기고 끝낸다(SCM 이 재시작)
                let _ = std::fs::write(
                    std::env::temp_dir().join("story-firewall-svc-error.txt"),
                    &e,
                );
                return;
            }
        };
        let dir = chosen.path.clone();
        let moved = chosen.moved.clone();
        let log = Log::open(&dir.join("service.log"));
        log.w(format!(
            "service: start v{} dir={}",
            SVC_VERSION,
            dir.display()
        ));
        // 자기 구성요소: 설치 폴더(관리자만 쓰기)의 우리 파일은 서명 내용이 온전하면 판정 뿌리로 삼지 않는다(L015)
        if let Some(d) = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.display().to_string()))
        {
            log.w(format!("judge: self dir={d}"));
            judge::set_self_dirs(vec![d]);
            judge::rules::set_system_drive(
                &std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()),
            );
        }
        // 원격 주소의 국가·ASN (설치 폴더 geo\, 관리자만 쓰기). 없으면 종류만 표시
        if let Some(gdir) = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.join("geo")))
        {
            let (g, errs) = geo::Geo::open_dir(&gdir);
            log.w(format!(
                "geo: country={} built={:?} errors={:?}",
                g.has_country(),
                g.country_built,
                errs
            ));
            geo::init_global(g);
        }
        if chosen.pruned > 0 {
            log.w(format!(
                "data_dir: pruned {} old untrusted folders (keep {})",
                chosen.pruned,
                data_dir::KEEP_UNTRUSTED
            ));
        }
        // ② 고정 파이프 이름 점유자 (서비스는 고정 이름을 만들지 않는다 → 점유자 = 가로채기 시도)
        let squat = pipe_name::holder_of(pipe::PIPE_NAME);
        // ③ 엔진 (재시작 대조는 Runtime 이 스레드 시작 때)
        let rt = Runtime::start_with(
            Box::new(Product {
                dir: dir.clone(),
                log: log.clone(),
            }),
            SVC_VERSION,
            Some(Box::new(process::WinHost)),
        );
        if let Some(why) = &chosen.fallback {
            log.w(format!(
                "data_dir: fallback (could not move untrusted base: {why}) -> {}",
                dir.display()
            ));
            let _ = rt.tx.send(Command::RecordEvent { kind: "data_dir_held".into(), severity: 3, detail: format!("다른 프로그램이 데이터 폴더를 붙잡고 있어 치우지 못했습니다({why}). 대체 폴더를 씁니다: {}", dir.display()) });
        }
        if let Some(m) = &moved {
            log.w(format!(
                "data_dir: untrusted folder moved aside -> {}",
                m.display()
            ));
            let _ = rt.tx.send(Command::RecordEvent {
                kind: "data_dir_untrusted".into(),
                severity: 3,
                detail: format!(
                    "서비스보다 먼저 만들어진 데이터 폴더(소유자 불명 또는 정션)를 치웠습니다: {}",
                    m.display()
                ),
            });
        }
        if let Some((pid, sess)) = squat {
            let img = authn::image_of_pid(pid);
            log.w(format!(
                "squat: fixed pipe name held by pid={pid} image={img:?} session={sess:?}"
            ));
            // A29: 점유자를 그래프의 프로세스(PID@생성 시각)로 잇는다 — 수집 세션의 시작 스냅샷이 같은 키로 노드를 만든다
            let target = serde_json::json!({ "type": "process", "pid": pid, "create_ft": process::create_time(pid), "image": img, "session": sess }).to_string();
            let _ = rt.tx.send(Command::RecordEventRef {
                kind: "pipe_squat".into(),
                severity: 3,
                detail: format!("다른 프로그램이 Story Firewall 의 예전 파이프 이름을 차지하고 있습니다: PID {pid} {} (세션 {})", img.clone().unwrap_or_default(), sess.map(|s| s.to_string()).unwrap_or_else(|| "?".into())),
                target,
            });
        }
        // ④ 수집 세션 → 배치 복사본 → 엔진
        let (sink_tx, sink_rx) = mpsc::channel::<Vec<graph::Event>>();
        let cfg = collector::Config {
            db_path: dir.join("graph.db").to_string_lossy().into_owned(),
            ..collector::Config::default()
        };
        let session = match collector::start(cfg, Some(sink_tx)) {
            Ok(s) => {
                log.w("collector: started");
                let _ = svc::defender::COLLECTOR_COUNTS.set(Box::new(s.counts_reader()));
                // 명령줄 수집 상태를 서비스 기록에 남긴다(5분 뒤 한 번, 그 뒤 1시간마다) — 진단(diag)이 따로 도는 프로세스라
                // 수집기 카운터를 직접 못 읽는다. 이름만(값은 개수) — 명령줄 내용은 없다
                {
                    let read = s.counts_reader();
                    let log5 = log.clone();
                    std::thread::spawn(move || {
                        let mut wait = std::time::Duration::from_secs(300);
                        loop {
                            std::thread::sleep(wait);
                            wait = std::time::Duration::from_secs(3600);
                            let line: Vec<String> = read()
                                .into_iter()
                                .filter(|(k, _)| {
                                    k.starts_with("cmdline_")
                                        || k.starts_with("svchost_")
                                        || k.starts_with("kernel_")
                                })
                                .map(|(k, v)| format!("{k}={v}"))
                                .collect();
                            log5.w(format!("collector: counts {}", line.join(" ")));
                        }
                    });
                }
                Some(s)
            }
            Err(e) => {
                log.w(format!("collector: start failed {e}"));
                None
            }
        };
        // install-128 실측: 옛 큰 DB 는 원시 기록 바이트 합이 없다 — 한 번만, 낮은 우선순위로 따로 센다(읽기 연결 → 엔진·수집을 막지 않음)
        {
            let db = dir.join("graph.db");
            let log4 = log.clone();
            std::thread::spawn(move || {
                let t = std::time::Instant::now();
                match graph::store::Store::init_raw_size(&db) {
                    Ok(Some(b)) => log4.w(format!(
                        "raw_size: bytes={b} ms={}",
                        t.elapsed().as_millis()
                    )),
                    Ok(None) => {}
                    Err(e) => log4.w(format!("raw_size: failed {e}")),
                }
            });
        }
        // 개편안 2판 1-2②: 차단 통신 집계 — WFP CLASSIFY_DROP 구독(감사 정책 불필요) → 채널 → 집계 스레드 → traffic_hourly.blocked
        {
            let (sink, rx, lost) = svc::blocked::channel();
            let ours = rt.our_filters.clone();
            let db = dir.join("graph.db").to_string_lossy().into_owned();
            let log2 = log.clone();
            let recent = rt.blocked_recent.clone();
            // 필터 번호 → 이름·공급자: 집계 스레드 안에서 WFP 세션을 열어 쓴다(열지 못하면 정보 없이 기록만)
            let resolver: svc::blocked::ResolverFactory = Box::new(|| {
                let eng = policy::wfp::Engine::open().ok();
                Box::new(move |id| eng.as_ref().and_then(|e| e.filter_info(id)))
            });
            std::thread::spawn(move || {
                svc::blocked::run(rx, lost, ours, recent, resolver, db, move |s| log2.w(s))
            });
            let log3 = log.clone();
            std::thread::spawn(move || {
                // 구독용 엔진 세션은 이 스레드가 평생 들고 있는다(끊기면 1분 뒤 다시 연다)
                loop {
                    match policy::wfp::Engine::open() {
                        Ok(mut eng) => {
                            let s = sink.clone();
                            let conv =
                                |d: policy::wfp::DropEvent, backfill: bool| svc::blocked::Drop {
                                    ts_ft: d.ts,
                                    filter_id: d.filter_id,
                                    remote: d
                                        .remote_v4
                                        .map(|a| a.to_string())
                                        .or_else(|| d.remote_v6.map(|a| a.to_string()))
                                        .unwrap_or_default(),
                                    rport: d.remote_port,
                                    lport: d.local_port,
                                    proto: d.protocol,
                                    dir: d.direction,
                                    loopback: d.loopback,
                                    app: d.app_id,
                                    backfill,
                                };
                            match eng.subscribe_drops(Box::new(move |d| s.push(conv(d, false)))) {
                                Ok(()) => {
                                    log3.w("blocked: WFP 차단 사건 구독 시작");
                                    // 차단 기록: 서비스가 꺼져 있던 동안 것도 보이게 BFE 기록의 최근 하루(최대 200건)를 되읽는다(시간대 집계에는 넣지 않음)
                                    let since = svc::runtime::unix_to_filetime(
                                        std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .map(|d| d.as_secs() as i64)
                                            .unwrap_or(0)
                                            - 86_400,
                                    );
                                    match eng.drops_since(since) {
                                        Ok(xs) => {
                                            let n = xs.len();
                                            for d in xs {
                                                sink.push(conv(d, true));
                                            }
                                            log3.w(format!("blocked: backfill {n}"));
                                        }
                                        Err(e) => log3.w(format!("blocked: backfill failed {e}")),
                                    }
                                    loop {
                                        std::thread::sleep(Duration::from_secs(3600));
                                    }
                                }
                                Err(e) => log3.w(format!("blocked: subscribe failed {e}")),
                            }
                        }
                        Err(e) => log3.w(format!("blocked: engine open failed {e}")),
                    }
                    std::thread::sleep(Duration::from_secs(60));
                }
            });
        }
        // 10판 5-9 (3): Defender 운영 로그의 CFA 차단·감사(1123·1124)를 1분마다 읽어 엔진에 넘긴다(읽기 전용, 외부 전송 없음)
        {
            let tx = rt.tx.clone();
            let log = log.clone();
            std::thread::spawn(move || {
                let mut last_err: Option<String> = None;
                loop {
                    match svc::defender::query_events() {
                        Ok(evs) => {
                            last_err = None;
                            if tx.send(Command::DefenderEvents(evs)).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            // 같은 오류(채널 없음 등)는 한 번만 남긴다
                            if last_err.as_deref() != Some(e.as_str()) {
                                log.w(format!("defender events: {e}"));
                                last_err = Some(e);
                            }
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_secs(60));
                }
            });
        }
        let tx = rt.tx.clone();
        std::thread::spawn(move || {
            for b in sink_rx {
                if tx.send(Command::Batch(b)).is_err() {
                    break;
                }
            }
        });
        // L061: 미끼 폴더 찾기(읽기만) — UI(사용자 권한)가 만든 미끼를 판정에 등록한다. 서비스는 사용자 폴더에 쓰지 않는다
        // (SYSTEM 쓰기는 정션 심기 권한 상승의 표적). 시작할 때와 10분마다
        // L066: 등록은 엔진 스레드가 한다 — 그 프로그램의 실제 설치가 보이면 빼고(설치 엑스레이)
        {
            let tx = rt.tx.clone();
            std::thread::spawn(move || loop {
                let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
                let root = PathBuf::from(format!("{drive}\\Users"));
                let dirs: Vec<String> = decoy::discover(&root)
                    .into_iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect();
                if tx.send(Command::DecoyDirs(dirs)).is_err() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(600));
            });
        }
        // ⑤ 주기 판정(15초, 실시간 3)
        let stop = Arc::new(AtomicBool::new(false));
        {
            let tx = rt.tx.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                // 구조 개선 B: 시작 직후 첫 판정(조회가 판정을 대신 돌리지 않게), 그 뒤 1분마다.
                // L057: 10초 → 3초. 첫 판정이 이야기 문장도 미리 만든다 — 재시작 직후 화면을 열면 첫 조회가 3초 걸렸다(install-27)
                std::thread::sleep(std::time::Duration::from_secs(3));
                while !stop.load(Ordering::SeqCst) {
                    if tx.send(Command::Judge).is_err() {
                        break;
                    }
                    std::thread::sleep(JUDGE_EVERY);
                }
            });
        }
        // ⑥ 파이프: 무작위 이름으로 첫 인스턴스를 만든 뒤 공개, 연결마다 스레드
        let name = pipe_name::random_name();
        match pipe::PipeServer::create(&name, true) {
            Err(e) => log.w(format!("pipe: create failed {e}")),
            Ok(first) => {
                match pipe_name::publish(&name) {
                    Ok(()) => log.w(format!("pipe: published {name}")),
                    Err(e) => log.w(format!("pipe: publish failed {e}")),
                }
                let tx = rt.tx.clone();
                let log2 = log.clone();
                let opts2 = opts.clone();
                std::thread::spawn(move || {
                    let ids = AtomicU64::new(0);
                    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                    let mut next = Some(first);
                    loop {
                        let mut s = match next.take() {
                            Some(s) => s,
                            None => match pipe::PipeServer::create(&name, false) {
                                Ok(s) => s,
                                Err(e) => {
                                    log2.w(format!("pipe: instance failed {e}"));
                                    std::thread::sleep(Duration::from_secs(1));
                                    continue;
                                }
                            },
                        };
                        if s.wait_client().is_err() {
                            continue;
                        }
                        let id = ids.fetch_add(1, Ordering::SeqCst) + 1;
                        // 28차 Gemini Q5: 연결을 많이 열어 엔진을 묶는 것을 막는다 — 동시 연결 상한(연결 하나는 한 번에 요청 하나만 처리한다)
                        if active.load(Ordering::SeqCst) >= MAX_PIPE_CONNECTIONS {
                            log2.w(format!("pipe: connection {id} refused: too many connections ({MAX_PIPE_CONNECTIONS})"));
                            s.disconnect();
                            continue;
                        }
                        active.fetch_add(1, Ordering::SeqCst);
                        let active2 = active.clone();
                        let tx = tx.clone();
                        let log3 = log2.clone();
                        let opts3 = opts2.clone();
                        std::thread::spawn(move || {
                            let au = authn_for(&opts3, s.raw());
                            let why = svc::handler::serve(id, &mut s, &au, &tx);
                            log3.w(format!("pipe: connection {id} closed: {why}"));
                            s.disconnect();
                            active2.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                });
            }
        }
        log.w("service: running");
        // ⑦ SCM 이벤트
        for ev in events {
            match ev {
                ServiceEvent::Stop | ServiceEvent::Shutdown => {
                    log.w(format!("event: {ev:?}"));
                    break;
                }
                ServiceEvent::Resume => {
                    let _ = rt.tx.send(Command::Resume);
                }
                ServiceEvent::TimeChanged => {
                    let _ = rt.tx.send(Command::TimeChanged);
                }
                _ => {}
            }
        }
        // ⑧ 정리: 공개 이름 → 판정 타이머 → 수집 세션 → 엔진
        pipe_name::unpublish();
        stop.store(true, Ordering::SeqCst);
        if let Some(s) = session {
            match s.stop() {
                Ok(r) => log.w(format!(
                    "collector: stopped ingested={} dropped={} lost={:?}",
                    r.events_ingested,
                    r.dropped,
                    r.session.as_ref().map(|x| x.events_lost)
                )),
                Err(e) => log.w(format!("collector: stop error {e}")),
            }
        }
        rt.shutdown();
        log.w("service: stopped");
    }

    fn wait_state(want: u32, secs: u64) -> Option<u32> {
        for _ in 0..secs * 4 {
            match service::query_state(SERVICE_NAME) {
                Ok(s) if s == want => return Some(s),
                Ok(_) => std::thread::sleep(Duration::from_millis(250)),
                Err(_) => return None,
            }
        }
        service::query_state(SERVICE_NAME).ok()
    }

    /// L028 진단(관리자): 데이터 폴더 크기, 서비스 기록 끝, 표 행 수, 화면이 자주 부르는 조회의 걸린 시간.
    /// 내용(경로·주소)은 찍지 않는다 — 개수와 밀리초만
    /// 정책 실측 확인(2026-11-06 ICMP 차단 제보): 엔진 DB 를 읽기 전용으로 열어 최근 정책·이력·필터 명세를 찍는다.
    /// 노트북 확인을 화면 제어 없이 하려는 것. 쓰지 않는다(OPEN_READ_ONLY)
    fn diag_policies(path: &std::path::Path) {
        use rusqlite::OpenFlags;
        let c = match rusqlite::Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        {
            Ok(c) => c,
            Err(e) => return println!("diag: policy open failed {e}"),
        };
        let q = |sql: &str, f: &dyn Fn(&rusqlite::Row) -> rusqlite::Result<String>| match c
            .prepare(sql)
        {
            Ok(mut st) => {
                let rows = st.query_map([], |r| f(r));
                match rows {
                    Ok(it) => it.flatten().for_each(|l| println!("diag: {l}")),
                    Err(e) => println!("diag: query failed {e}"),
                }
            }
            Err(e) => println!("diag: prepare failed {e}"),
        };
        q(
            "SELECT id, name, state, version, created, confirm_deadline FROM policies ORDER BY id DESC LIMIT 8",
            &|r| Ok(format!(
                "policy id={} name={} state={} v={} created={} deadline={:?}",
                r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?, r.get::<_, i64>(4)?, r.get::<_, Option<i64>>(5)?
            )),
        );
        q(
            "SELECT ts, policy_id, action, actor, COALESCE(result,'') FROM policy_history ORDER BY id DESC LIMIT 20",
            &|r| Ok(format!(
                "history ts={} policy={} {} by {} {}",
                r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?,
                r.get::<_, String>(3)?, r.get::<_, String>(4)?.chars().take(160).collect::<String>()
            )),
        );
        q(
            "SELECT filter_id, policy_id, version, spec_json FROM wfp_filters ORDER BY policy_id DESC, filter_id LIMIT 30",
            &|r| Ok(format!(
                "filter id={} policy={} v={} spec={}",
                r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?.chars().take(400).collect::<String>()
            )),
        );
        q(
            "SELECT p.id, v.yaml FROM policies p JOIN policy_versions v ON v.policy_id = p.id AND v.version = p.version WHERE p.name = 'ACL'",
            &|r| Ok(format!("acl policy={} yaml={}", r.get::<_, i64>(0)?, r.get::<_, String>(1)?.replace('\n', " / "))),
        );
    }

    fn diag() {
        let dir = pipe_name::reg_get(data_dir::REG_DATA_DIR)
            .map(PathBuf::from)
            .unwrap_or_else(data_dir::base);
        for f in ["graph.db", "graph.db-wal", "engine.db"] {
            let n = std::fs::metadata(dir.join(f)).map(|m| m.len()).unwrap_or(0);
            println!("diag: file {f} bytes={n}");
        }
        if let Ok(t) = std::fs::read_to_string(dir.join("service.log")) {
            let lines: Vec<&str> = t.lines().collect();
            for l in &lines[lines.len().saturating_sub(40)..] {
                println!("diag: log {l}");
            }
        }
        // L056: 서비스가 1분마다 남기는 처리 시간 표(오래 걸린 순)
        if let Ok(t) = std::fs::read_to_string(dir.join("timings.json")) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
                println!("diag: timings wall={}", v["wall"]);
                for r in v["timings"].as_array().into_iter().flatten() {
                    println!(
                        "diag: timing {} count={} avg_ms={} max_ms={} last_ms={}",
                        r["name"].as_str().unwrap_or("?"),
                        r["count"],
                        r["avg_ms"],
                        r["max_ms"],
                        r["last_ms"]
                    );
                }
            }
        }
        diag_policies(&dir.join("engine.db"));
        let t0 = std::time::Instant::now();
        let store = match graph::store::Store::open(dir.join("graph.db")) {
            Ok(s) => s,
            Err(e) => {
                println!("diag: open failed {e}");
                return;
            }
        };
        println!("diag: open ms={}", t0.elapsed().as_millis());
        // install-124·126 실측(시작 때 보관 정리 6분): 마지막 보관 정리의 단계별 시간
        if let Ok(Some(v)) = store.get_meta("retention_last") {
            println!("diag: retention_last {v}");
        }
        // 2026-11-10: 높음·심각 사건의 근거 항목(무엇 때문에 그 등급인지) — 실행 파일 이름과 근거 글자만, 경로·주소 없음.
        // 판정은 쓰지 않는 assess(읽기만). 서비스와 같게 자기 구성요소 폴더를 알려 준다(안 주면 우리 화면이 뿌리로 잡힌다 — diag-140 실측)
        if let Some(d) = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.display().to_string()))
        {
            judge::set_self_dirs(vec![d]);
            judge::rules::set_system_drive(
                &std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()),
            );
        }
        // 전체 판정 "불러오기" 단계별 시간(diag-156: 12초)
        {
            let mut lp = judge::LoadProfile::default();
            let t = std::time::Instant::now();
            match judge::View::load_profiled(&store, 0, i64::MAX, &mut lp) {
                Ok(_) => println!(
                    "diag: view_load total_ms={} edges_ms={} n_edges={} nodes_ms={} n_nodes={} index_ms={} table_only_ms={} debug_ports_ms={}",
                    t.elapsed().as_millis(),
                    lp.edges.as_millis(),
                    lp.n_edges,
                    lp.nodes.as_millis(),
                    lp.n_nodes,
                    lp.index.as_millis(),
                    lp.table_only.as_millis(),
                    lp.debug_ports.as_millis()
                ),
                Err(e) => println!("diag: view_load error {e}"),
            }
        }
        // svchost 서비스 이름(명령줄 -s) 수집 확인: 최근 svchost 노드 8개의 SCM 목록·명령줄 서비스 이름
        {
            let rows: Vec<String> = store
                .conn()
                .prepare(
                    "SELECT key, COALESCE(json_extract(attrs_json, '$.services'), ''),
                            COALESCE(json_extract(attrs_json, '$.service_arg'), '-'),
                            COALESCE(json_extract(attrs_json, '$.ended'), 0)
                     FROM nodes WHERE kind = 'process' AND lower(json_extract(attrs_json, '$.image')) LIKE '%svchost.exe'
                     ORDER BY first_ts DESC LIMIT 8",
                )
                .and_then(|mut st| {
                    st.query_map([], |x| {
                        Ok(format!(
                            "{} scm={} arg={} ended={}",
                            x.get::<_, String>(0)?,
                            x.get::<_, String>(1)?,
                            x.get::<_, String>(2)?,
                            x.get::<_, i64>(3)?
                        ))
                    })?
                    .collect()
                })
                .unwrap_or_default();
            let with_arg: i64 = store
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM nodes WHERE kind = 'process' AND json_extract(attrs_json, '$.service_arg') IS NOT NULL",
                    [],
                    |x| x.get(0),
                )
                .unwrap_or(-1);
            println!("diag: svchost service_arg nodes={with_arg}");
            for r in rows {
                println!("diag: svchost recent {r}");
            }
        }
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            match judge::Baseline::open(&store, now)
                .and_then(|b| judge::assess(&store, 0, i64::MAX, &b))
            {
                Ok(stories) => {
                    // diag-180: 인시던트 목록 문장이 한 번에 10~18초 — 사건별 문장 시간과 선 수(가장 느린 8건)
                    {
                        let mut t: Vec<(u128, usize, String, u8)> = stories
                            .iter()
                            .filter(|s| s.score >= 40)
                            .take(101)
                            .map(|s| {
                                let t0 = std::time::Instant::now();
                                let _ = story::narrate(
                                    &store,
                                    std::slice::from_ref(s),
                                    story::Voice::Plain,
                                );
                                (
                                    t0.elapsed().as_millis(),
                                    s.edges.len(),
                                    s.root_label
                                        .rsplit(['\\', '/'])
                                        .next()
                                        .unwrap_or("")
                                        .to_string(),
                                    s.score,
                                )
                            })
                            .collect();
                        let total: u128 = t.iter().map(|x| x.0).sum();
                        t.sort_by(|a, b| b.0.cmp(&a.0));
                        println!("diag: narrate total_ms={total} n={}", t.len());
                        for (ms, n, name, sc) in t.iter().take(8) {
                            println!("diag: narrate ms={ms} edges={n} score={sc} root={name}");
                        }
                    }
                    for s in stories
                        .iter()
                        .filter(|s| s.level.rank() >= judge::Level::Suspicious.rank())
                        .take(20)
                    {
                        let name = s.root_label.rsplit(['\\', '/']).next().unwrap_or("");
                        let why: Vec<String> = s
                            .reasons
                            .iter()
                            .map(|r| {
                                // 금고 근거면 어느 브라우저의 어느 저장소인지(종류만 — 경로 없음)
                                let extra = r
                                    .edge_id
                                    .filter(|_| r.what.contains("브라우저 저장소"))
                                    .and_then(|eid| {
                                        store
                                            .conn()
                                            .query_row(
                                                "SELECT n.key FROM edges e JOIN nodes n ON n.id = e.dst WHERE e.id = ?1",
                                                [eid],
                                                |x| x.get::<_, String>(0),
                                            )
                                            .ok()
                                    })
                                    .and_then(|k| graph::vault::classify(&k))
                                    .map(|v| format!("[{:?}/{:?}]", v.browser, v.what))
                                    .unwrap_or_default();
                                format!("{}{}({:+})", r.what, extra, r.points)
                            })
                            .collect();
                        println!(
                            "diag: story level={} ch={:?} score={} root={} reasons={}",
                            format!("{:?}", s.level),
                            s.chapter,
                            s.score,
                            name,
                            why.join(" | ")
                        );
                        // 고립 svchost 소음 조사: 노드 속성(서비스 목록·PID·시작 상태)과 귀속 없는 외부 원격지 몇 개
                        if s.root_kind == judge::RootKind::IsolatedSvchost {
                            let attrs: String = store
                                .conn()
                                .query_row(
                                    "SELECT COALESCE(attrs_json, '{}') FROM nodes WHERE id = ?1",
                                    [s.root],
                                    |x| x.get(0),
                                )
                                .unwrap_or_default();
                            let remotes: Vec<String> = store
                                .conn()
                                .prepare(
                                    "SELECT r.key, COUNT(*) FROM edges e JOIN nodes r ON r.id = e.dst
                                     WHERE e.src = ?1 AND e.rel = 'connected'
                                       AND NOT EXISTS (SELECT 1 FROM edges v WHERE v.dst = r.id AND v.rel = 'connected_via')
                                     GROUP BY r.id ORDER BY 2 DESC LIMIT 4",
                                )
                                .and_then(|mut st| {
                                    st.query_map([s.root], |x| {
                                        Ok(format!("{}×{}", x.get::<_, String>(0)?, x.get::<_, i64>(1)?))
                                    })?
                                    .collect()
                                })
                                .unwrap_or_default();
                            println!(
                                "diag: svchost attrs={} remotes={}",
                                attrs.chars().take(400).collect::<String>(),
                                remotes.join(", ")
                            );
                        }
                    }
                }
                Err(e) => println!("diag: story failed {e}"),
            }
        }
        let ms = |name: &str, f: &mut dyn FnMut() -> String| {
            let t = std::time::Instant::now();
            let r = f();
            println!("diag: {name} ms={} {r}", t.elapsed().as_millis());
        };
        for table in ["raw_events", "nodes", "edges", "ingest_gaps"] {
            ms(&format!("count {table}"), &mut || {
                store
                    .conn()
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| {
                        r.get::<_, i64>(0)
                    })
                    .map(|n| format!("rows={n}"))
                    .unwrap_or_else(|e| format!("err={e}"))
            });
        }
        ms("snapshot ts (old, no index)", &mut || {
            store
                .conn()
                .prepare("SELECT DISTINCT ts FROM raw_events NOT INDEXED WHERE source = 'snapshot'")
                .and_then(|mut st| st.query_map([], |r| r.get::<_, i64>(0))?.count().pipe_ok())
                .map(|n| format!("n={n}"))
                .unwrap_or_else(|e| format!("err={e}"))
        });
        let now_ft = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0))
            * 10_000_000
            + 116_444_736_000_000_000;
        let from = now_ft - 86_400 * 10_000_000;
        // 과제 23: 일관성(최근 24시간에 보인 프로세스). bad/total — 비율이 크면 수집·병합 결함을 의심
        ms(
            "consistency 24h",
            &mut || match graph::views::consistency(&store, from) {
                Ok(v) => v
                    .iter()
                    .map(|c| format!("{}={}/{}", c.name, c.bad, c.total))
                    .collect::<Vec<_>>()
                    .join(" "),
                Err(e) => format!("err={e}"),
            },
        );
        // 49차 답변 1·2: 세션 속성이 없는 프로세스 노드가 얼마나 되나(세션 모름 = 보임 규칙·DB 재확인 비용의 근거)
        ms("process nodes without session", &mut || {
            store
                .conn()
                .query_row(
                    "SELECT COUNT(*), \
                            SUM(json_extract(attrs_json,'$.session') IS NULL), \
                            SUM(json_extract(attrs_json,'$.session') IS NULL AND COALESCE(json_extract(attrs_json,'$.ended'),0) = 1), \
                            SUM(json_extract(attrs_json,'$.session') IS NULL AND COALESCE(json_extract(attrs_json,'$.preexisting'),0) = 1) \
                     FROM nodes WHERE kind = 'process'",
                    [],
                    |r| {
                        Ok(format!(
                            "total={} no_session={} no_session_ended={} no_session_preexisting={}",
                            r.get::<_, i64>(0)?,
                            r.get::<_, Option<i64>>(1)?.unwrap_or(0),
                            r.get::<_, Option<i64>>(2)?.unwrap_or(0),
                            r.get::<_, Option<i64>>(3)?.unwrap_or(0)
                        ))
                    },
                )
                .unwrap_or_else(|e| format!("err={e}"))
        });
        // D021: 연결 탭 첫 로드(실기기 수 초~20초) — 연결 목록(최근 5분)·"오늘 처음" 기준 집합 질의
        ms("views::connections 5min", &mut || {
            graph::views::connections(&store, now_ft - 300 * 10_000_000, 500)
                .map(|v| format!("rows={}", v.len()))
                .unwrap_or_else(|e| format!("err={e}"))
        });
        // L072(14판 20-4): 원격 도구 기준값 실측 — 지금 통신 중인 원격 도구의 누적 송수신·기간(유휴 평균 송신 속도를 본다)
        // 32차 Q1: 지금 활성 RDP 세션(WTS) — 서비스와 같은 판단의 입력
        ms(
            "rdp sessions now",
            &mut || match svc::win::wts::rdp_sessions() {
                Ok(v) => format!("n={}", v.len()),
                Err(e) => format!("err={e}"),
            },
        );
        ms("remote tools (10min)", &mut || {
            match graph::remote::running_tools(&store, now_ft - 600 * 10_000_000) {
            Ok(v) if v.is_empty() => "none".to_string(),
            Ok(v) => v
                .iter()
                .map(|(pid, _, key)| {
                    let (s, r, f, l): (i64, i64, i64, i64) = store
                        .conn()
                        .query_row(
                            "SELECT COALESCE(SUM(sent),0), COALESCE(SUM(recv),0), COALESCE(MIN(first_ts),0), COALESCE(MAX(last_ts),0) FROM conn_bytes WHERE pid = ?1",
                            [pid],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                        )
                        .unwrap_or((0, 0, 0, 0));
                    let secs = ((l - f) / 10_000_000).max(1);
                    format!("{key}:{pid} sent={s} recv={r} span_s={secs} sent_per_min={}", s * 60 / secs)
                })
                .collect::<Vec<_>>()
                .join(" | "),
            Err(e) => format!("err={e}"),
        }
        });
        ms("seen_before remotes (30d)", &mut || {
            let day = 86_400 * 10_000_000i64;
            store
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM nodes WHERE kind = 'remote' AND first_ts < ?1 AND last_ts >= ?2",
                    rusqlite::params![now_ft - day, now_ft - 30 * day],
                    |r| r.get::<_, i64>(0),
                )
                .map(|n| format!("remotes={n}"))
                .unwrap_or_else(|e| format!("err={e}"))
        });
        // L030 뒤: 서비스가 실제로 쓰는 길(가장 늦은 선 2만 개)과 단계별 시간
        ms("facts::collect_recent 24h", &mut || {
            story::facts::collect_recent(&store, from, now_ft, 20_000)
                .map(|(v, tr)| format!("facts={} truncated={tr}", v.len()))
                .unwrap_or_else(|e| format!("err={e}"))
        });
        ms("story::tell_recent 24h (service path)", &mut || {
            story::tell_recent(&store, from, now_ft, story::Voice::Plain, 20_000)
                .map(|(v, tr)| format!("sentences={} truncated={tr}", v.len()))
                .unwrap_or_else(|e| format!("err={e}"))
        });
        ms("story::tell 24h", &mut || {
            story::tell(&store, from, now_ft, story::Voice::Plain)
                .map(|v| format!("sentences={}", v.len()))
                .unwrap_or_else(|e| format!("err={e}"))
        });
        let bl = judge::Baseline::open(&store, now_ft);
        ms("judge::run 24h", &mut || match &bl {
            Ok(b) => judge::run(&store, from, now_ft, b)
                .map(|v| format!("stories={}", v.len()))
                .unwrap_or_else(|e| format!("err={e}")),
            Err(e) => format!("baseline err={e}"),
        });
        if let Ok(b) = &bl {
            if let Ok(st) = judge::run(&store, from, now_ft, b) {
                ms("story::narrate 24h", &mut || {
                    story::narrate(&store, &st, story::Voice::Plain)
                        .map(|v| format!("narratives={}", v.len()))
                        .unwrap_or_else(|e| format!("err={e}"))
                });
            }
        }
    }

    trait PipeOk: Sized {
        fn pipe_ok(self) -> rusqlite::Result<Self> {
            Ok(self)
        }
    }
    impl PipeOk for usize {}

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        let opts = match parse_opts(&args) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        };
        match args.get(1).map(|s| s.as_str()).unwrap_or("") {
            "install" => {
                let exe = std::env::current_exe().expect("exe");
                let signer = opts
                    .test_signer
                    .as_ref()
                    .map(|cn| format!(" --test-signer \"{cn}\""))
                    .unwrap_or_default()
                    + &opts
                        .test_pin
                        .as_ref()
                        .map(|p| format!(" --test-signer-sha256 {p}"))
                        .unwrap_or_default();
                let cmd = format!("\"{}\" run{signer}", exe.display());
                match service::install_auto(SERVICE_NAME, DISPLAY, &cmd, DESCRIPTION) {
                    Ok(true) => println!("install: ok ({cmd})"),
                    Ok(false) => println!("install: updated existing service ({cmd})"),
                    Err(e) => {
                        println!("install: {e}");
                        std::process::exit(4);
                    }
                }
            }
            "uninstall" => {
                // 멈추고(실패해도 진행) → 등록 해제 → 필터 → 공개 이름
                let _ = service::stop(SERVICE_NAME);
                wait_state(1, 20);
                match service::uninstall(SERVICE_NAME) {
                    Ok(()) => println!("uninstall: service removed"),
                    Err(e) => println!("uninstall: {e}"),
                }
                match policy::wfp::Engine::open().and_then(|e| e.remove_all()) {
                    Ok(n) => println!("uninstall: wfp filters removed={n}"),
                    Err(e) => println!("uninstall: wfp cleanup failed {e}"),
                }
                pipe_name::unpublish();
                // 데이터 폴더는 기본으로 남긴다(사용자 기록). `--purge-data`(제거 때 사용자가 "지우기"를 고름)면 검사한 뒤 지운다
                if args.iter().any(|a| a == "--purge-data") {
                    let extra = pipe_name::reg_get(data_dir::REG_DATA_DIR).map(PathBuf::from);
                    let gone = data_dir::purge(&data_dir::base(), extra);
                    println!("uninstall: data removed={gone:?}");
                }
                // 가리키는 값은 지운다 — 재설치 때 다시 검사
                pipe_name::reg_delete(data_dir::REG_DATA_DIR);
                println!("uninstall: ok");
            }
            "start" => {
                // install-171(2026-11-11): 설치 프로그램이 서비스를 멈추는 중(STOP_PENDING=3)에 시작을 부르면
                // 0x420(이미 실행 중)으로 실패하고, 곧 멈춰 서비스가 꺼진 채로 남았다(7분). 멈추는 중이면 끝나기를 기다렸다가
                // 시작하고, 실패하면 상태를 다시 보고 한 번 더 시도한다
                if service::query_state(SERVICE_NAME).ok() == Some(3) {
                    wait_state(1, 60);
                }
                let mut r = service::start(SERVICE_NAME);
                if let Err(e) = &r {
                    match service::query_state(SERVICE_NAME).ok() {
                        Some(4) | Some(2) => {
                            println!("start: already running/starting ({e})");
                            r = Ok(());
                        }
                        _ => {
                            wait_state(1, 60);
                            std::thread::sleep(Duration::from_millis(500));
                            println!("start: retry after {e}");
                            r = service::start(SERVICE_NAME);
                        }
                    }
                }
                match r {
                    Ok(()) => println!("start: ok state={:?}", wait_state(4, 20)),
                    Err(e) => println!("start: {e}"),
                }
            }
            "stop" => match service::stop(SERVICE_NAME) {
                Ok(()) => println!("stop: ok state={:?}", wait_state(1, 30)),
                // 0x425(제어를 받을 수 없음 = 이미 멈추는 중) 등: 멈출 때까지 기다린다
                Err(e) => println!("stop: {e} → state={:?}", wait_state(1, 60)),
            },
            "status" => {
                let st = service::query_state(SERVICE_NAME)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|e| format!("({e})"));
                let name = pipe_name::resolve();
                let published = if pipe_name::valid(&name) {
                    name
                } else {
                    "-".into()
                };
                // 제거 뒤에는 Provider 가 없어 열거가 오류일 수 있다 — 그때도 "우리 필터 0개"다
                let (filters, note) = match policy::wfp::Engine::open().and_then(|e| e.list_ours())
                {
                    Ok(v) => (v.len(), String::new()),
                    Err(e) => (0, format!(" wfp_note=({e})")),
                };
                let dir = pipe_name::reg_get(data_dir::REG_DATA_DIR)
                    .map(PathBuf::from)
                    .unwrap_or_else(data_dir::base);
                let trusted = dir.exists() && data_dir::owner_trusted(&dir);
                println!("status: state={st} published={published} wfp_filters={filters} data_dir={} owner_trusted={trusted}{note}", dir.display());
            }
            "diag" => diag(),
            "run" => {
                let o = opts.clone();
                if let Err(e) = service::run(SERVICE_NAME, Box::new(move |rx| body(rx, o))) {
                    eprintln!("service: {e}");
                    std::process::exit(5);
                }
            }
            "console" => {
                let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(30);
                let (tx, rx) = mpsc::channel();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_secs(secs));
                    let _ = tx.send(ServiceEvent::Stop);
                });
                body(rx, opts);
                println!("console: done");
            }
            _ => {
                eprintln!("사용법: story-firewall-svc install|uninstall|start|stop|status|diag|run|console <secs> [--test-signer CN]");
                std::process::exit(2);
            }
        }
    }
}
