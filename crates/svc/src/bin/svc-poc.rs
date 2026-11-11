//! A17 PoC (Windows 러너): 파이프 서버·클라이언트, 서명·관리자 검사, 시각대.
//!
//! svc-poc server <expected-signer-CN> [n] [--demo] [--concurrent] : --demo 면 재현 이벤트를 넣고 시작 (A22 실제 UI 시험). 파이프를 열고 연결 n개를 차례로 처리(기본 2). 연결마다 PID·이미지·서명·관리자 결과를 찍고
//!                                            handler::serve 로 넘긴다(가짜 WFP 엔진, 실제 Transport·Authn).
//! svc-poc client                             : 연결 → rpc.hello → policy.list → settings.set(관리자) → 응답 출력
//! svc-poc tz                                 : 로컬 시각 오프셋
//! svc-poc install <log-path>                 : SCM 에 "StoryFirewallPoc" 서비스 등록 (명령줄 = 이 exe service <log-path>)
//! svc-poc uninstall | sc-start | sc-stop | sc-state
//! svc-poc service <log-path>                 : SCM 이 띄우는 본체. 받은 제어 이벤트를 log-path 에 한 줄씩 적는다
//! svc-poc create-time <pid>                  : 생성 시각(FILETIME) 출력
//! svc-poc collect <secs> <db>                : A18 — 수집 세션(ETW) + 엔진을 같이 띄워 배치 복사본이 엔진에 닿는지 (관리자)
//! svc-poc kill <pid> [create-filetime]       : 생성 시각이 같을 때만 TerminateProcess
//! svc-poc probe | squat-hold <name> <secs> | squat-instance <name> | sddl-demo <secs> : A25 파이프 이름·DACL 시험
//! svc-poc stress <n>                         : A24 파이프 읽기 경쟁 재현
//! svc-poc rpc <method> <params.json>          : 연결 → rpc.hello → 메서드 한 번 → "rpc: <응답 JSON>" (A30 등 워크플로가 흐름을 짠다)

#[cfg(any(windows, feature = "host-check"))]
fn main() {
    use dsl::expand::Resolver;
    use engine::backend::{FakeWfp, GraphQuery, NoGraph, WfpBackend};
    use engine::Clock;
    use svc::runtime::{Parts, Runtime};
    use svc::win::{authn, pipe, process, service, time};
    const POC_SERVICE: &str = "StoryFirewallPoc";

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
                Box::new(time::WinClock::default()),
                Box::new(R),
                rusqlite::Connection::open_in_memory().unwrap(),
                graph::store::Store::open_in_memory().unwrap(),
                vec!["svc-poc.exe".into()],
            )
        }
    }

    /// 파일 DB 를 쓰는 부품 (수집 세션과 같은 파일, 두 번째 연결)
    struct PFile(String);
    impl Parts for PFile {
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
                Box::new(time::WinClock::default()),
                Box::new(R),
                rusqlite::Connection::open_in_memory().unwrap(),
                graph::store::Store::open(&self.0).unwrap(),
                vec!["svc-poc.exe".into()],
            )
        }
    }

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()).unwrap_or("") {
        "tz" => {
            println!("local_offset_minutes={}", time::local_offset_minutes());
            let c = time::WinClock::default();
            let utc = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            println!("wall={} utc={} local={} wall_is_utc={}", c.wall(), utc, c.local(), (c.wall() - utc).abs() <= 1);
        }
        #[cfg(feature = "test-signer")]
        "server" => {
            let signer = args.get(2).cloned().unwrap_or_default();
            let n: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2);
            let rt = Runtime::start_with(Box::new(P), "0.1.0-poc", Some(Box::new(process::WinHost)));
            if args.iter().any(|a| a == "--demo") {
                // A22: 실제 UI(WebView2) 시험용 재현 이벤트 (svc-dev 와 같은 것)
                let now_ft = time::WinClock::default().wall() * 10_000_000 + 116_444_736_000_000_000;
                geo::init_global(svc::demo::demo_geo());
                // 시연 프로세스를 이 서버의 로그온 세션에 둔다 — 일반 사용자 화면(A27)은 자기 세션·시스템 세션의 프로세스만 본다
                let evs = svc::demo::demo_events(now_ft);
                let mut sid = 0u32;
                // SAFETY: 자기 PID 와 유효한 출력 포인터
                let ok = unsafe {
                    windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(std::process::id(), &mut sid)
                };
                let evs = if ok != 0 { svc::demo::with_session(evs, sid) } else { evs };
                let _ = rt.tx.send(svc::runtime::Command::Ingest(evs));
                let _ = rt.tx.send(svc::runtime::Command::Judge);
            }
            // --concurrent: 연결마다 스레드로 처리하고 곧바로 다음 인스턴스를 연다(실제 서비스 구조, A22 실제 UI 시험).
            // 기본(차례 처리)은 poc4 판정이 로그 줄 순서에 기대므로 그대로 둔다.
            let concurrent = args.iter().any(|a| a == "--concurrent");
            let mut workers = Vec::new();
            for i in 0..n {
                let mut srv = match pipe::PipeServer::create(pipe::PIPE_NAME, i == 0) {
                    Ok(s) => s,
                    Err(e) => { println!("server: create failed: {e}"); std::process::exit(2); }
                };
                println!("server: waiting connection {}", i + 1);
                if let Err(e) = srv.wait_client() { println!("server: {e}"); continue; }
                let pid = { use svc::Transport; srv.client_pid() };
                let (sig_ok, sig_detail) = authn::client_signature_ok(pid, &signer);
                // 관리자 검사는 handler 가 hello 를 읽은 뒤에 한다 (읽기 전 Impersonate 는 0x558). 여기서는 서명만 찍는다.
                println!("server: client pid={pid} image={:?} signature_ok={sig_ok} ({sig_detail})", authn::image_of_pid(pid));
                let signer2 = signer.clone();
                let tx = rt.tx.clone();
                let mut job = move || {
                    let au = authn::WinAuthn::with_test_signer(&signer2, srv.raw());
                    let why = svc::handler::serve(i as u64 + 1, &mut srv, &au, &tx);
                    println!("server: connection {} closed: {why}", i + 1);
                    srv.disconnect();
                };
                if concurrent {
                    workers.push(std::thread::spawn(job));
                } else {
                    job();
                }
            }
            for w in workers {
                let _ = w.join();
            }
            rt.shutdown();
        }
        "client" => {
            // A25: 서비스가 공개한 이름(HKLM) → 없으면 고정 이름(시험 서버)
            let name = svc::win::pipe_name::resolve();
            println!("client: pipe={name}");
            // 시험 서버가 아직 파이프를 못 만들었으면(0x2, 러너에서 3초 넘게 걸린 적 있음) 10초까지 다시 시도
            let mut tries = 0;
            let mut c = loop {
                match pipe::PipeClient::connect(&name) {
                    Ok(c) => break c,
                    Err(e) if tries < 20 && (e.contains("0x2") || e.contains("0xe7")) => { tries += 1; std::thread::sleep(std::time::Duration::from_millis(500)); }
                    Err(e) => { println!("client: connect failed: {e}"); std::process::exit(3); }
                }
            };
            let reqs = [
                r#"{"jsonrpc":"2.0","id":1,"method":"rpc.hello","params":{"client_version":"0.1.0-poc","api":[1,0]}}"#.to_string(),
                r#"{"jsonrpc":"2.0","id":2,"method":"policy.list","params":{}}"#.to_string(),
                r#"{"jsonrpc":"2.0","id":3,"method":"settings.set","params":{"request_id":"0f3c2a1e-9b7d-4c6a-8e5f-123456789abc","theme":"dark"}}"#.to_string(),
            ];
            for r in reqs {
                let mut line = r.clone();
                line.push('\n');
                if !c.send(&line) { println!("client: send failed"); break; }
                match c.recv() {
                    Some(resp) => println!("client: {resp}"),
                    None => { println!("client: closed by server"); break; }
                }
            }
        }
        // 22차 남은 항목(a28): 설치된 서비스에 관리자 서명 클라이언트로 정책 1건 적용 + 확인 → 업그레이드 재설치 뒤 필터 유지 시험.
        // 막는 대상은 notepad.exe 아웃바운드(러너 시험에 영향 없음). 출력: "apply: policy_id=N version=V filters=F confirm=ok"
        "client-apply" => {
            let name = svc::win::pipe_name::resolve();
            let mut tries = 0;
            let mut c = loop {
                match pipe::PipeClient::connect(&name) {
                    Ok(c) => break c,
                    Err(e) if tries < 20 && (e.contains("0x2") || e.contains("0xe7")) => { tries += 1; std::thread::sleep(std::time::Duration::from_millis(500)); }
                    Err(e) => { println!("apply: connect failed: {e}"); std::process::exit(3); }
                }
            };
            let mut next = 0u64;
            let mut call = |m: &str, p: serde_json::Value| -> serde_json::Value {
                next += 1;
                let line = format!("{}\n", serde_json::json!({"jsonrpc": "2.0", "id": next, "method": m, "params": p}));
                if !c.send(&line) { return serde_json::json!({"error": "send"}); }
                // 알림(id 없음)은 건너뛰고 응답을 기다린다
                loop {
                    match c.recv() {
                        Some(r) => {
                            let v: serde_json::Value = serde_json::from_str(&r).unwrap_or_default();
                            if v.get("id").is_some() { return v; }
                        }
                        None => return serde_json::json!({"error": "closed"}),
                    }
                }
            };
            let rid = "0f3c2a1e-9b7d-4c6a-8e5f-0000000a2800";
            println!("apply: hello {}", call("rpc.hello", serde_json::json!({"client_version": "0.1.0-poc", "api": [1, 0]})));
            let yaml = "- name: a28-keep\n  action: block\n  match: { direction: out, process: ['C:/Windows/System32/notepad.exe'] }\n";
            let v = call("policy.apply", serde_json::json!({"request_id": rid, "yaml": yaml}));
            let (Some(pid), Some(ver)) = (v["result"]["policy_id"].as_i64(), v["result"]["version"].as_i64()) else {
                println!("apply: failed {v}");
                std::process::exit(4);
            };
            let conf = call("policy.confirm", serde_json::json!({"request_id": rid, "policy_id": pid, "version": ver}));
            let ok = conf["result"]["ok"] == serde_json::json!(true);
            println!("apply: policy_id={pid} version={ver} filters={} confirm={}", v["result"]["filters"], if ok { "ok" } else { "failed" });
            if !ok { println!("apply: confirm reply {conf}"); std::process::exit(5); }
        }
        "rpc" => {
            let m = args.get(2).cloned().unwrap_or_default();
            let params: serde_json::Value = args
                .get(3)
                .and_then(|f| std::fs::read_to_string(f).ok())
                .and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).ok())
                .unwrap_or_else(|| serde_json::json!({}));
            let name = svc::win::pipe_name::resolve();
            let mut tries = 0;
            let mut c = loop {
                match pipe::PipeClient::connect(&name) {
                    Ok(c) => break c,
                    Err(e) if tries < 40 && (e.contains("0x2") || e.contains("0xe7")) => { tries += 1; std::thread::sleep(std::time::Duration::from_millis(500)); }
                    Err(e) => { println!("rpc: connect failed: {e}"); std::process::exit(3); }
                }
            };
            let mut next = 0u64;
            let mut call = |m: &str, p: serde_json::Value| -> serde_json::Value {
                next += 1;
                let line = format!("{}\n", serde_json::json!({"jsonrpc": "2.0", "id": next, "method": m, "params": p}));
                if !c.send(&line) { return serde_json::json!({"error": "send"}); }
                loop {
                    match c.recv() {
                        Some(r) => {
                            let v: serde_json::Value = serde_json::from_str(&r).unwrap_or_default();
                            if v.get("id").is_some() { return v; }
                        }
                        None => return serde_json::json!({"error": "closed"}),
                    }
                }
            };
            let _ = call("rpc.hello", serde_json::json!({"client_version": "0.1.0-poc", "api": [1, 0]}));
            let v = call(&m, params);
            println!("rpc: {v}");
            if v.get("error").is_some() { std::process::exit(4); }
        }
        // A29(대시보드 개편안 2판 4-2, 8단계 실집행): 설정을 켜고, 서명 없는 시험 프로그램(args[2])이
        // cmd → vssadmin delete shadows 를 실행하게 한 뒤, 서비스가 묻지 않고 끊는지(사건 조치함·메모 auto:·
        // 정책 확정·시험 프로그램 종료) 확인하고, [자동 대응 되돌리기]와 같은 policy.rollback 으로 되돌린다.
        // 출력 줄 "a29: ..." 를 워크플로가 판정한다. 실패 시 0 이 아닌 종료 코드.
        "auto-destroy" => {
            let sim = args.get(2).cloned().unwrap_or_default();
            let name = svc::win::pipe_name::resolve();
            let mut tries = 0;
            let mut c = loop {
                match pipe::PipeClient::connect(&name) {
                    Ok(c) => break c,
                    Err(e) if tries < 40 && (e.contains("0x2") || e.contains("0xe7")) => { tries += 1; std::thread::sleep(std::time::Duration::from_millis(500)); }
                    Err(e) => { println!("a29: connect failed: {e}"); std::process::exit(3); }
                }
            };
            let mut next = 0u64;
            let mut call = |m: &str, p: serde_json::Value| -> serde_json::Value {
                next += 1;
                let line = format!("{}\n", serde_json::json!({"jsonrpc": "2.0", "id": next, "method": m, "params": p}));
                if !c.send(&line) { return serde_json::json!({"error": "send"}); }
                loop {
                    match c.recv() {
                        Some(r) => {
                            let v: serde_json::Value = serde_json::from_str(&r).unwrap_or_default();
                            if v.get("id").is_some() { return v; }
                        }
                        None => return serde_json::json!({"error": "closed"}),
                    }
                }
            };
            let rid = |n: u64| format!("0f3c2a1e-9b7d-4c6a-8e5f-{n:012x}");
            println!("a29: hello {}", call("rpc.hello", serde_json::json!({"client_version": "0.1.0-poc", "api": [1, 0]})));
            let v = call("settings.set", serde_json::json!({"request_id": rid(0xa29001), "auto_destroy_response": true}));
            println!("a29: settings.set {v}");
            if v["result"]["ok"] != serde_json::json!(true) { std::process::exit(4); }
            // 수집기가 새 프로세스를 보기 시작하도록 잠깐
            std::thread::sleep(std::time::Duration::from_secs(3));
            let mut child = match std::process::Command::new(&sim).spawn() {
                Ok(ch) => ch,
                Err(e) => { println!("a29: spawn {sim} failed: {e}"); std::process::exit(5); }
            };
            println!("a29: sim pid={}", child.id());
            // 주기 판정 15초 + 여유
            let t0 = std::time::Instant::now();
            let mut hit: Option<serde_json::Value> = None;
            while t0.elapsed().as_secs() < 150 {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let v = call("story.events", serde_json::json!({"level_min": "watch", "triage": "all", "limit": 200}));
                if let Some(items) = v["result"]["items"].as_array() {
                    if let Some(it) = items.iter().find(|x| x["triage"]["note"].as_str().is_some_and(|n| n.starts_with("auto:"))) {
                        hit = Some(it.clone());
                        break;
                    }
                }
            }
            let secs = t0.elapsed().as_secs();
            let exited = matches!(child.try_wait(), Ok(Some(_)));
            let Some(it) = hit else {
                println!("a29: no auto response within {secs}s, sim_exited={exited}");
                let v = call("story.events", serde_json::json!({"level_min": "normal", "triage": "all", "limit": 50}));
                println!("a29: events {}", v["result"]["items"].as_array().map(|a| a.iter().map(|x| format!("{}|{}|{}", x["title"], x["level"], x["chapter"])).collect::<Vec<_>>().join(" ; ")).unwrap_or_default());
                let _ = child.kill();
                std::process::exit(6);
            };
            println!("a29: auto response after {secs}s title={} level={} triage={}", it["title"], it["level"], it["triage"]);
            println!("a29: sim_exited={exited}");
            let note = it["triage"]["note"].as_str().unwrap_or("").to_string();
            let parts: Vec<i64> = note.trim_start_matches("auto:").split(':').filter_map(|x| x.parse().ok()).collect();
            let pl = call("policy.list", serde_json::json!({}));
            let items = pl["result"]["items"].as_array().cloned().unwrap_or_default();
            println!("a29: policies {}", items.iter().map(|x| format!("{}:{}:{}", x["id"], x["version"], x["state"])).collect::<Vec<_>>().join(","));
            let mut rolled = false;
            if parts.len() == 2 && parts[0] > 0 {
                // version 없이 = 제거(version 을 주면 그 판으로 되돌리기라 그대로 남는다 — A29 첫 통과 판에서 발견)
                let v = call("policy.rollback", serde_json::json!({"request_id": rid(0xa29002), "policy_id": parts[0]}));
                println!("a29: rollback {v}");
                let pl = call("policy.list", serde_json::json!({}));
                let after = pl["result"]["items"].as_array().cloned().unwrap_or_default();
                println!("a29: policies after rollback {}", after.iter().map(|x| format!("{}:{}:{}", x["id"], x["version"], x["state"])).collect::<Vec<_>>().join(","));
                // 되돌리기 성공 = 응답 ok 이고 그 정책이 더 이상 Confirmed 가 아님
                let still = after.iter().any(|x| x["id"].as_i64() == Some(parts[0]) && x["state"] == serde_json::json!("Confirmed"));
                rolled = v["result"]["ok"] == serde_json::json!(true) && !still;
            }
            let h = call("service.events", serde_json::json!({"since_secs": 600, "limit": 30}));
            for e in h["result"]["items"].as_array().cloned().unwrap_or_default() {
                let k = e["kind"].as_str().unwrap_or("");
                if k.starts_with("auto_destroy") || k == "cut_terminate" { println!("a29: event {k}: {}", e["detail"]); }
            }
            if !exited { let _ = child.kill(); }
            println!("a29: RESULT exited={exited} policy={} rolled_back={rolled}", parts.first().copied().unwrap_or(0));
            if !exited || !rolled { std::process::exit(7); }
        }
        // A25: 표준 사용자로 돌려 서비스 파이프에 닿는지, 서버가 session 0 인지, 서비스 이미지 경로를 읽을 수 있는지(18차 Q5 측정)
        "probe" => {
            let name = svc::win::pipe_name::resolve();
            let valid = svc::win::pipe_name::valid(&name);
            // 서비스는 연결을 차례로 받으므로 다른 연결로 엿보지 않고 이 연결 하나로 다 본다
            let mut c = match pipe::PipeClient::connect(&name) {
                Ok(c) => c,
                Err(e) => { println!("probe: name={name} valid={valid} connect failed {e}"); return; }
            };
            let (pid, sess) = c.server();
            // 18차 Q5 측정: 일반 사용자가 서비스 프로세스를 열어 이미지·세션을 읽을 수 있는가
            let img = {
                use windows_sys::Win32::Foundation::CloseHandle;
                use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
                let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
                if h.is_null() {
                    format!("denied(open {})", std::io::Error::last_os_error())
                } else {
                    let mut buf = [0u16; 1024];
                    let mut n = buf.len() as u32;
                    let ok = unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut n) } != 0;
                    unsafe { CloseHandle(h) };
                    if ok { format!("ok({})", String::from_utf16_lossy(&buf[..n as usize])) } else { format!("denied(query {})", std::io::Error::last_os_error()) }
                }
            };
            println!("probe: name={name} valid={valid} server_pid={pid} session={} image_query={img}", sess.map(|s| s.to_string()).unwrap_or_else(|| "?".into()));
            let ok = c.send("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"rpc.hello\",\"params\":{\"client_version\":\"0.1.0-poc\",\"api\":[1,0]}}\n") && c.recv().is_some_and(|r| r.contains("\"result\""));
            println!("probe: hello {}", if ok { "ok" } else { "failed" });
        }
        // A26: 데이터 폴더 선점 흉내 (표준 사용자로 %ProgramData%\StoryFirewall 를 먼저 만들고 가짜 정책 DB 를 심는다)
        "plant" => {
            let dir = args.get(2).cloned().unwrap_or_else(|| r"C:\ProgramData\StoryFirewall".into());
            match std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(std::path::Path::new(&dir).join("engine.db"), b"planted by a standard user")) {
                Ok(()) => println!("plant: created {dir}"),
                Err(e) => println!("plant: failed {dir} {e}"),
            }
        }
        // 21차 반영: 데이터 폴더를 먼저 만들고 그 핸들을 "삭제 공유 없이" 쥐고 버틴다 → 서비스가 치우지(MoveFile) 못함
        "plant-hold" => {
            use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
            let dir = args.get(2).cloned().unwrap_or_else(|| r"C:\ProgramData\StoryFirewall".into());
            let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(40);
            if let Err(e) = std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(std::path::Path::new(&dir).join("engine.db"), b"planted")) {
                println!("plant-hold: create failed {dir} {e}");
                return;
            }
            let w: Vec<u16> = dir.encode_utf16().chain(std::iter::once(0)).collect();
            let h = unsafe { CreateFileW(w.as_ptr(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, std::ptr::null(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, std::ptr::null_mut()) };
            if h == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                println!("plant-hold: open failed {}", std::io::Error::last_os_error());
                return;
            }
            println!("plant-hold: holding {dir} (no FILE_SHARE_DELETE)");
            std::thread::sleep(std::time::Duration::from_secs(secs));
        }
        // A26: 실제 서비스(실제 WFP)로 차단 왕복 — curl 기준 → policy.apply(curl 아웃바운드 차단) → confirm → curl 실패 → rollback → curl 정상.
        // filters 는 서비스가 만든 실제 WFP 필터 수(주소 조건 없는 프로그램 차단 = V4·V6 2개, A26 접점)
        "wfp-roundtrip" => {
            let exe = args.get(2).cloned().unwrap_or_else(|| r"C:\Windows\System32\curl.exe".into());
            let curl = || std::process::Command::new(&exe).args(["-s", "-o", "NUL", "--max-time", "15", "https://www.rust-lang.org/"]).status().map(|s| s.code().unwrap_or(-1)).unwrap_or(-2);
            let name = svc::win::pipe_name::resolve();
            let mut c = match pipe::PipeClient::connect(&name) {
                Ok(c) => c,
                Err(e) => { println!("roundtrip: connect failed {e}"); std::process::exit(3); }
            };
            let mut next = 0i64;
            let mut call = |m: &str, p: serde_json::Value| -> serde_json::Value {
                next += 1;
                let line = format!("{}\n", serde_json::json!({"jsonrpc": "2.0", "id": next, "method": m, "params": p}));
                if !c.send(&line) { return serde_json::json!({"error": "send"}); }
                c.recv().and_then(|r| serde_json::from_str(&r).ok()).unwrap_or(serde_json::json!({"error": "recv"}))
            };
            let h = call("rpc.hello", serde_json::json!({"client_version": "0.1.0-poc", "api": [1, 0]}));
            if h.get("error").is_some() { println!("roundtrip: hello failed {h}"); std::process::exit(4); }
            let base = curl();
            let yaml = format!("- name: roundtrip-block\n  action: block\n  match: {{ direction: out, process: ['{}'] }}\n", exe.replace('\\', "/"));
            let r = call("policy.apply", serde_json::json!({"request_id": svc::change::new_uuid(), "yaml": yaml}));
            let Some(pid) = r["result"]["policy_id"].as_i64() else { println!("roundtrip: apply failed {r}"); std::process::exit(5); };
            let ver = r["result"]["version"].as_i64().unwrap_or(1);
            let filters = r["result"]["filters"].as_u64().unwrap_or(0);
            let cf = call("policy.confirm", serde_json::json!({"request_id": svc::change::new_uuid(), "policy_id": pid, "version": ver}));
            let blocked = curl();
            let rb = call("policy.rollback", serde_json::json!({"request_id": svc::change::new_uuid(), "policy_id": pid}));
            std::thread::sleep(std::time::Duration::from_millis(500));
            let after = curl();
            println!("roundtrip: baseline={base} blocked={blocked} filters={filters} after={after} confirm_ok={} rollback_ok={}", cf.get("result").is_some(), rb.get("result").is_some());
        }
        // A25: 파이프 이름 선점 (서비스 시작 전, 표준 사용자로)
        "squat-hold" => {
            let name = args.get(2).cloned().unwrap_or_else(|| pipe::PIPE_NAME.to_string());
            let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(30);
            match pipe::PipeServer::create(&name, true) {
                Ok(_s) => { println!("squat-hold: holding {name}"); std::thread::sleep(std::time::Duration::from_secs(secs)); }
                Err(e) => println!("squat-hold: failed {name} {e}"),
            }
        }
        // A25: 이미 있는 파이프에 서버 인스턴스를 더 만들 수 있는가 (DACL 의 FILE_CREATE_PIPE_INSTANCE)
        "squat-instance" => {
            let name = args.get(2).cloned().unwrap_or_else(svc::win::pipe_name::resolve);
            match pipe::PipeServer::create(&name, false) {
                Ok(_s) => println!("squat-instance: {name} created (VULNERABLE)"),
                Err(e) => println!("squat-instance: {name} denied {e}"),
            }
        }
        // A25: 예전 SDDL(GRGW) 과 고친 SDDL 을 나란히 띄워 표준 사용자의 인스턴스 추가를 비교
        "sddl-demo" => {
            let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(25);
            let a = pipe::PipeServer::create_with_sddl(r"\\.\pipe\sf-demo-legacy", true, pipe::SDDL_LEGACY);
            let b = pipe::PipeServer::create_with_sddl(r"\\.\pipe\sf-demo-fixed", true, pipe::SDDL);
            println!("sddl-demo: legacy={} fixed={}", a.is_ok(), b.is_ok());
            std::thread::sleep(std::time::Duration::from_secs(secs));
        }
        // A24: 서버 읽기의 "대기 끝 ↔ 완료" 경쟁 재현. 요청 간격을 200ms 조각 경계(190~210ms)에 흩어 보내고,
        // 응답이 5초 안에 안 오면 잃은 것으로 본다. 동기 파이프라 막히면 다음 요청을 못 보내므로 감시는 다른 스레드에서.
        "stress" => {
            let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(300);
            // 경쟁 창 = 대기 시간이 끝난 뒤 서버 스레드가 실제로 다시 돌기까지의 지연. 한가한 러너에선 µs 라 잘 안 나오므로
            // CPU 를 바쁘게 해 스케줄 지연을 늘린다(실제 앱 시험에서는 WebView2 등이 같은 역할을 했다)
            let busy = std::thread::available_parallelism().map(|x| x.get()).unwrap_or(2) * 2;
            for _ in 0..busy {
                std::thread::spawn(|| { let mut x = 0u64; loop { x = x.wrapping_mul(6364136223846793005).wrapping_add(1); std::hint::black_box(x); } });
            }
            println!("stress: busy threads={busy}");
            let (tx, rx) = std::sync::mpsc::channel::<(usize, u128)>();
            std::thread::spawn(move || {
                let mut c = match pipe::PipeClient::connect(pipe::PIPE_NAME) {
                    Ok(c) => c,
                    Err(e) => { println!("stress: connect failed: {e}"); std::process::exit(3); }
                };
                let hello = "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"rpc.hello\",\"params\":{\"client_version\":\"0.1.0-poc\",\"api\":[1,0]}}\n";
                if !c.send(hello) || c.recv().is_none() { println!("stress: hello failed"); std::process::exit(3); }
                for i in 0..n {
                    std::thread::sleep(std::time::Duration::from_millis(190 + (i as u64 * 7) % 21));
                    let t0 = std::time::Instant::now();
                    let req = format!("{{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"policy.list\",\"params\":{{}}}}\n", i + 1);
                    if !c.send(&req) { println!("stress: send failed at {i}"); std::process::exit(4); }
                    match c.recv() {
                        Some(r) if r.contains(&format!("\"id\":{}", i + 1)) => { let _ = tx.send((i, t0.elapsed().as_millis())); }
                        Some(r) => { println!("stress: wrong response at {i}: {r}"); std::process::exit(4); }
                        None => { println!("stress: closed at {i}"); std::process::exit(4); }
                    }
                }
            });
            let mut max_ms = 0u128;
            let mut done = 0usize;
            while done < n {
                match rx.recv_timeout(std::time::Duration::from_secs(5)) {
                    Ok((_, ms)) => { done += 1; max_ms = max_ms.max(ms); }
                    Err(_) => { println!("stress: lost response at i={done} (no reply in 5s) lost=1"); std::process::exit(5); }
                }
            }
            println!("stress: done n={n} lost=0 max_ms={max_ms}");
        }
        #[cfg(not(feature = "test-signer"))]
        "server" => println!("server 모드는 test-signer feature 빌드에서만 (제품 CN={})", authn::PRODUCT_SIGNER_CN),
        "install" => {
            let log = args.get(2).cloned().unwrap_or_else(|| "svc-poc-service.log".into());
            let exe = std::env::current_exe().unwrap();
            // 시험: 서비스가 받을 클라이언트 서명자 CN (test-signer 빌드에서만 쓰인다)
            let signer = args.get(3).map(|s| format!(" \"{s}\"")).unwrap_or_default();
            let cmd = format!("\"{}\" service \"{}\"{signer}", exe.display(), log);
            match service::install(POC_SERVICE, "Story Firewall PoC", &cmd) {
                Ok(()) => println!("install: ok ({cmd})"),
                Err(e) => { println!("install: {e}"); std::process::exit(4); }
            }
        }
        "uninstall" => match service::uninstall(POC_SERVICE) { Ok(()) => println!("uninstall: ok"), Err(e) => println!("uninstall: {e}") },
        "sc-start" => match service::start(POC_SERVICE) { Ok(()) => println!("start: ok"), Err(e) => println!("start: {e}") },
        "sc-stop" => match service::stop(POC_SERVICE) { Ok(()) => println!("stop: ok"), Err(e) => println!("stop: {e}") },
        "sc-state" => match service::query_state(POC_SERVICE) { Ok(s) => println!("state={s}"), Err(e) => println!("state: {e}") },
        "service" => {
            // SCM 이 띄운다. 콘솔이 없으므로 파일에 적는다.
            let log = args.get(2).cloned().unwrap_or_else(|| "svc-poc-service.log".into());
            let signer: Option<String> = args.get(3).cloned();
            let body = Box::new(move |rx: std::sync::mpsc::Receiver<service::ServiceEvent>| {
                use std::io::Write;
                let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&log).ok();
                let mut w = |line: String| { if let Some(f) = f.as_mut() { let _ = writeln!(f, "{} {line}", time::WinClock::default().wall()); let _ = f.flush(); } };
                w("service: running".into());
                // 엔진도 같이 띄워 Resume/TimeChanged 가 Command 로 이어지는지 본다
                let rt = Runtime::start(Box::new(P), "0.1.0-poc");
                // A25: 고정 이름을 누가 들고 있나 (서비스는 고정 이름을 만들지 않으므로 = 가로채기 시도). 제품에서는 사건으로 남긴다
                if let Some((pid, sess)) = svc::win::pipe_name::holder_of(pipe::PIPE_NAME) {
                    w(format!("squat: fixed pipe name held by pid={pid} image={:?} session={sess:?}", authn::image_of_pid(pid)));
                } else {
                    w("squat: fixed pipe name free".into());
                }
                // 무작위 이름으로 첫 인스턴스를 먼저 만들고 → 공개
                let name = svc::win::pipe_name::random_name();
                match pipe::PipeServer::create(&name, true) {
                    Err(e) => w(format!("pipe: create failed {e}")),
                    Ok(first) => {
                        match svc::win::pipe_name::publish(&name) {
                            Ok(()) => w(format!("pipe: published {name}")),
                            Err(e) => w(format!("pipe: publish failed {e}")),
                        }
                        let tx = rt.tx.clone();
                        let signer = signer.clone();
                        let name2 = name.clone();
                        let logp = log.clone();
                        std::thread::spawn(move || {
                            use std::io::Write;
                            let mut lf = std::fs::OpenOptions::new().create(true).append(true).open(&logp).ok();
                            let mut srv = Some(first);
                            for i in 0u64.. {
                                let mut s = match srv.take() { Some(s) => s, None => match pipe::PipeServer::create(&name2, false) { Ok(s) => s, Err(_) => break } };
                                if s.wait_client().is_err() { continue; }
                                #[cfg(feature = "test-signer")]
                                let au = match &signer { Some(cn) => authn::WinAuthn::with_test_signer(cn, s.raw()), None => authn::WinAuthn::new(s.raw()) };
                                #[cfg(not(feature = "test-signer"))]
                                let au = { let _ = &signer; authn::WinAuthn::new(s.raw()) };
                                let why = svc::handler::serve(i + 1, &mut s, &au, &tx);
                                if let Some(f) = lf.as_mut() { let _ = writeln!(f, "pipe: connection {} closed: {why}", i + 1); }
                                s.disconnect();
                            }
                        });
                    }
                }
                for ev in rx {
                    w(format!("event: {ev:?}"));
                    match ev {
                        service::ServiceEvent::Stop | service::ServiceEvent::Shutdown => {
                            svc::win::pipe_name::unpublish();
                            w("pipe: unpublished".into());
                            break;
                        }
                        service::ServiceEvent::Resume => { let _ = rt.tx.send(svc::runtime::Command::Resume); }
                        service::ServiceEvent::TimeChanged => { let _ = rt.tx.send(svc::runtime::Command::TimeChanged); }
                        _ => {}
                    }
                }
                rt.shutdown();
                w("service: stopped".into());
            });
            if let Err(e) = service::run(POC_SERVICE, body) {
                eprintln!("service: {e}");
                std::process::exit(5);
            }
        }
        "collect" => {
            let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(15);
            let db = args.get(3).cloned().unwrap_or_else(|| "svc-collect.db".into());
            let _ = std::fs::remove_file(&db);
            let rt = Runtime::start_with(Box::new(PFile(db.clone())), "0.1.0-poc", Some(Box::new(process::WinHost)));
            let (sink_tx, sink_rx) = std::sync::mpsc::channel::<Vec<graph::Event>>();
            let cfg = collector::Config { db_path: db.clone(), ..collector::Config::default() };
            let session = match collector::start(cfg, Some(sink_tx)) {
                Ok(s) => s,
                Err(e) => { println!("collect: start failed: {e}"); std::process::exit(6); }
            };
            // 배치 복사본 → 엔진. 건수만 센다
            let engine_tx = rt.tx.clone();
            let counter = std::thread::spawn(move || {
                let (mut batches, mut events, mut starts) = (0u64, 0u64, 0u64);
                for b in sink_rx {
                    batches += 1;
                    events += b.len() as u64;
                    starts += b.iter().filter(|e| matches!(e.kind, graph::event::EventKind::ProcessStart { .. })).count() as u64;
                    let _ = engine_tx.send(svc::runtime::Command::Batch(b));
                }
                (batches, events, starts)
            });
            std::thread::sleep(std::time::Duration::from_secs(secs));
            let report = session.stop();
            let (batches, events, starts) = counter.join().unwrap_or((0, 0, 0));
            // 엔진이 같은 파일을 읽어 판정까지 도는지
            let _ = rt.tx.send(svc::runtime::Command::Judge);
            rt.shutdown();
            match report {
                Ok(r) => println!("collect: ingested={} edges={} dropped={} lost={:?}", r.events_ingested, r.edges_created, r.dropped, r.session.as_ref().map(|s| s.events_lost)),
                Err(e) => println!("collect: report error: {e}"),
            }
            println!("collect: sink batches={batches} events={events} process_starts={starts}");
            let g = graph::store::Store::open(&db).unwrap();
            let n: i64 = g.conn().query_row("SELECT COUNT(*) FROM nodes WHERE kind='process'", [], |r| r.get(0)).unwrap_or(-1);
            println!("collect: process_nodes={n}");
        }
        "listeners" => {
            use svc::host::Host;
            match process::WinHost.listeners() {
                Ok(ls) => {
                    let tcp = ls.iter().filter(|l| l.proto == "tcp").count();
                    let udp = ls.iter().filter(|l| l.proto == "udp").count();
                    println!("listeners: tcp={tcp} udp={udp}");
                    for l in ls.iter().filter(|l| l.lport == 135 || l.lport == 445) {
                        println!("listener: {} {}:{} pid={} any={}", l.proto, l.laddr, l.lport, l.pid, l.any_addr);
                    }
                }
                Err(e) => println!("listeners: {e}"),
            }
        }
        "create-time" => {
            let pid: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            println!("create_time={:?}", process::create_time(pid));
        }
        "kill" => {
            let pid: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            let exp: Option<i64> = args.get(3).and_then(|s| s.parse().ok());
            println!("kill pid={pid} expected={exp:?} -> {:?}", process::terminate(pid, exp));
        }
        _ => println!("usage: svc-poc server <signerCN> [n] | client | tz | install | uninstall | sc-start | sc-stop | sc-state | service | create-time <pid> | kill <pid> [ft]"),
    }
}

#[cfg(not(any(windows, feature = "host-check")))]
fn main() {
    println!("svc-poc 는 Windows 전용");
}
