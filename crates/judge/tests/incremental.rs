//! 갈래 C: 증분 주기 판정 = 전체 판정 (무작위 덧붙임·제자리 변경·삭제·보관 정리 순서에서)
//!
//! 매 판정마다 같은 DB 에서
//! - 증분 판정(`Incremental::run`, 장 기록 있음)의 사건 목록과
//! - 전체 판정(`judge::run`)의 사건 목록을 비교하고(뿌리·장·점수·등급·이유·선),
//! - 증분이 쓴 장(edges.chapter)이 전체 판정이 쓸 값과 같은지(전체 판정이 아무것도 바꾸지 않는지) 본다.

use graph::store::Store;
use graph::{NodeKind, Rel};
use judge::{Baseline, Incremental};

const T0: i64 = 133_800_000_000_000_000;
const SEC: i64 = 10_000_000;

/// 작은 결정적 난수(xorshift64*)
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
    fn pick<T: Copy>(&mut self, v: &[T]) -> T {
        v[self.below(v.len())]
    }
}

struct World {
    files: Vec<i64>,
    procs: Vec<i64>,
    remotes: Vec<i64>,
    domains: Vec<i64>,
    autoruns: Vec<i64>,
    commands: Vec<i64>,
    n: u32,
}

const FILES: &[(&str, &str)] = &[
    (
        r"C:\Users\u\AppData\Local\Temp\tool.exe",
        r#"{"sig_status":"nosignature"}"#,
    ),
    (r"C:\Users\u\Downloads\setup.exe", r#"{"zone_id":3}"#),
    (
        r"C:\Windows\System32\svchost.exe",
        r#"{"sig_status":"valid","signer":"Microsoft Windows"}"#,
    ),
    (
        r"C:\Program Files\Vendor\app.exe",
        r#"{"sig_status":"valid","signer":"Vendor Inc"}"#,
    ),
    (r"C:\Users\u\Downloads\run.ps1", r#"{"zone_id":3}"#),
    (
        r"C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk",
        r#"{}"#,
    ),
    (r"C:\Users\u\Documents\report.docx", r#"{}"#),
    (
        r"C:\Users\u\AppData\Local\Temp\bad.exe",
        r#"{"sig_status":"untrusted:bad_digest"}"#,
    ),
    (
        r"C:\Windows\System32\vssadmin.exe",
        r#"{"sig_status":"valid","signer":"Microsoft Windows"}"#,
    ),
    // (사) 브라우저 금고 경비: 브라우저·권한 상승 서비스 실행 파일, 금고 파일, 미끼 파일
    (
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r#"{"sig_status":"valid","signer":"Google LLC"}"#,
    ),
    (
        r"C:\Program Files\Google\Chrome\Application\131.0.6778.86\elevation_service.exe",
        r#"{"sig_status":"valid","signer":"Google LLC"}"#,
    ),
    (
        r"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        r#"{}"#,
    ),
    (
        r"C:\Users\u\AppData\Local\Google\Chrome\User Data\Local State",
        r#"{}"#,
    ),
    (
        r"C:\Users\u\AppData\Roaming\Exodus\exodus.wallet\seed.seco",
        r#"{}"#,
    ),
    (
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe",
        r#"{"sig_status":"valid","signer":"Microsoft Windows"}"#,
    ),
];
const IMAGES: &[&str] = &[
    r"C:\Program Files\Microsoft Office\winword.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Program Files\Google\Chrome\chrome.exe",
    r"C:\Windows\System32\vssadmin.exe",
    r"C:\Users\u\AppData\Local\Temp\tool.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Google\Chrome\Application\131.0.6778.86\elevation_service.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe",
];
const IPS: &[&str] = &["8.8.8.8", "10.0.0.5", "140.82.112.3", "192.168.0.1"];
/// (사) 이 PC 안 디버깅 포트 후보(9222 기본, 9333 은 디버깅 실행 명령줄이 들어와야 집합에 든다)
const LOOPBACK: &[(&str, u16)] = &[("127.0.0.1", 9222), ("127.0.0.1", 9333), ("::1", 9222)];

fn new_proc(s: &Store, w: &mut World, r: &mut Rng, ts: i64) {
    w.n += 1;
    let img = r.pick(IMAGES);
    let services = if img.ends_with("svchost.exe") && r.chance(50) {
        r#"["Dnscache"]"#
    } else {
        "[]"
    };
    let attrs = format!(
        r#"{{"image":{},"pid":{},"services":{services}}}"#,
        serde_json::to_string(img).unwrap(),
        w.n
    );
    let label = img.rsplit('\\').next().unwrap();
    let id = s
        .upsert_node(
            NodeKind::Process,
            &format!("{}@{ts}", w.n),
            label,
            ts,
            Some(&attrs),
        )
        .unwrap();
    w.procs.push(id);
}

fn setup(s: &Store, r: &mut Rng) -> World {
    let mut w = World {
        files: vec![],
        procs: vec![],
        remotes: vec![],
        domains: vec![],
        autoruns: vec![],
        commands: vec![],
        n: 0,
    };
    for (p, a) in FILES {
        let label = p.rsplit('\\').next().unwrap();
        w.files.push(
            s.upsert_node(NodeKind::File, p, label, T0, Some(a))
                .unwrap(),
        );
    }
    for _ in 0..6 {
        new_proc(s, &mut w, r, T0);
    }
    for (i, ip) in IPS.iter().enumerate() {
        let a = if i % 2 == 0 {
            format!(r#"{{"ip":"{ip}","port":443,"domain":"d{i}.example.com"}}"#)
        } else {
            format!(r#"{{"ip":"{ip}","port":{}}}"#, 8000 + i)
        };
        w.remotes.push(
            s.upsert_node(NodeKind::Remote, &format!("{ip}:443"), ip, T0, Some(&a))
                .unwrap(),
        );
    }
    for (ip, port) in LOOPBACK {
        let a = format!(r#"{{"ip":"{ip}","port":{port}}}"#);
        w.remotes.push(
            s.upsert_node(NodeKind::Remote, &format!("{ip}:{port}"), ip, T0, Some(&a))
                .unwrap(),
        );
    }
    for d in ["a.example.com", "b.example.org"] {
        w.domains
            .push(s.upsert_node(NodeKind::Domain, d, d, T0, None).unwrap());
    }
    w.autoruns.push(
        s.upsert_node(NodeKind::Autorun, r"HKCU\Run\Upd", "Upd", T0, None)
            .unwrap(),
    );
    for c in [
        "vssadmin delete shadows /all /quiet",
        "vssadmin list shadows",
        "chrome.exe --remote-debugging-port=9222 --headless=new",
        "chrome.exe --remote-debugging-port=9333",
        "msedge.exe --remote-debugging-pipe",
    ] {
        w.commands
            .push(s.upsert_node(NodeKind::Command, c, c, T0, None).unwrap());
    }
    w
}

fn random_ts(r: &mut Rng, step: i64) -> i64 {
    // 대개 늘어나는 시각, 가끔 옛 시각·같은 시각(정렬 (ts, id) 확인)
    match r.below(10) {
        0 => T0 + (r.below(5) as i64) * SEC,
        1 => T0,
        _ => T0 + step * SEC + (r.below(3) as i64) * SEC,
    }
}

fn raw(s: &Store, ts: i64, source: &str) -> i64 {
    s.insert_raw(ts, source, "{}").unwrap()
}

fn add_random_edge(s: &Store, w: &mut World, r: &mut Rng, step: i64) {
    let ts = random_ts(r, step);
    match r.below(13) {
        11 | 12 => {
            // (사) 파일 열기(금고·미끼·평범한 파일)
            let (p, f) = (r.pick(&w.procs), r.pick(&w.files));
            s.insert_edge(p, f, Rel::Opened, ts, Some(raw(s, ts, "etw:file:open")))
                .unwrap();
        }
        0 => {
            let (p, f) = (r.pick(&w.procs), r.pick(&w.files));
            s.insert_edge(p, f, Rel::Downloaded, ts, Some(raw(s, ts, "motw")))
                .unwrap();
        }
        1 => {
            let (p, f) = (r.pick(&w.procs), r.pick(&w.files));
            s.insert_edge(p, f, Rel::Wrote, ts, Some(raw(s, ts, "etw:file")))
                .unwrap();
        }
        2 | 3 => {
            // 새 프로세스를 만들고 실행 파일·부모 선
            new_proc(s, w, r, ts);
            let p = *w.procs.last().unwrap();
            let f = r.pick(&w.files);
            s.insert_edge(f, p, Rel::ExecutedAs, ts, Some(raw(s, ts, "etw:process")))
                .unwrap();
            let parent = r.pick(&w.procs[..w.procs.len() - 1]);
            s.insert_edge(parent, p, Rel::Spawned, ts, Some(raw(s, ts, "etw:process")))
                .unwrap();
        }
        4 => {
            let (a, b) = (r.pick(&w.procs), r.pick(&w.procs));
            if a != b {
                s.insert_edge(a, b, Rel::Spawned, ts, Some(raw(s, ts, "etw:process")))
                    .unwrap();
            }
        }
        5 | 6 => {
            let (p, rm) = (r.pick(&w.procs), r.pick(&w.remotes));
            let src = if r.chance(40) {
                "conntable"
            } else {
                "etw:network"
            };
            s.insert_edge(p, rm, Rel::Connected, ts, Some(raw(s, ts, src)))
                .unwrap();
        }
        7 => {
            let (p, rm) = (r.pick(&w.procs), r.pick(&w.remotes));
            let conf = if r.chance(50) { "high" } else { "low" };
            let method = if r.chance(50) { "capi2" } else { "window" };
            s.insert_edge_with_attrs(
                p,
                rm,
                Rel::ConnectedVia,
                ts,
                Some(raw(s, ts, "capi2")),
                &format!(r#"{{"method":"{method}","confidence":"{conf}"}}"#),
            )
            .unwrap();
        }
        8 => {
            let (p, a) = (r.pick(&w.procs), r.pick(&w.autoruns));
            s.insert_edge(p, a, Rel::Registered, ts, Some(raw(s, ts, "autorun")))
                .unwrap();
        }
        9 => {
            let (p, c) = (r.pick(&w.procs), r.pick(&w.commands));
            s.insert_edge(p, c, Rel::Ran, ts, Some(raw(s, ts, "etw:process")))
                .unwrap();
        }
        _ => {
            let (p, d) = (r.pick(&w.procs), r.pick(&w.domains));
            s.insert_edge(p, d, Rel::Resolved, ts, Some(raw(s, ts, "etw:dns")))
                .unwrap();
        }
    }
}

fn random_edge_id(s: &Store, r: &mut Rng, rel: Option<&str>) -> Option<i64> {
    let ids: Vec<i64> = {
        let sql = match rel {
            Some(_) => "SELECT id FROM edges WHERE rel = ?1",
            None => "SELECT id FROM edges WHERE ?1 IS NULL OR 1",
        };
        let mut st = s.conn().prepare(sql).unwrap();
        st.query_map([rel], |x| x.get(0))
            .unwrap()
            .map(|x| x.unwrap())
            .collect()
    };
    (!ids.is_empty()).then(|| r.pick(&ids))
}

/// 제자리 변경·삭제
fn mutate(s: &Store, w: &mut World, r: &mut Rng, step: i64, bl: &Baseline) {
    match r.below(11) {
        9 => {
            // 끝난 프로세스의 마지막 시각이 늦게 들어옴 / 첫 시각이 앞당겨짐 — (사) 보조 근거가 읽는다
            let p = r.pick(&w.procs);
            if r.chance(50) {
                s.conn()
                    .execute(
                        "UPDATE nodes SET last_ts = MAX(last_ts, ?1) WHERE id = ?2",
                        [random_ts(r, step), p],
                    )
                    .unwrap();
            } else {
                s.conn()
                    .execute(
                        "UPDATE nodes SET first_ts = MIN(first_ts, ?1) WHERE id = ?2",
                        [T0 - (r.below(30) as i64) * SEC, p],
                    )
                    .unwrap();
            }
        }
        10 => {
            // 프로세스 종료(ingest 의 ProcessStop 과 같은 두 갱신)
            let p = r.pick(&w.procs);
            s.conn()
                .execute(
                    "UPDATE nodes SET last_ts = ?1 WHERE id = ?2",
                    [random_ts(r, step), p],
                )
                .unwrap();
            s.merge_node_attrs(p, &serde_json::json!({ "ended": true }))
                .unwrap();
        }
        0 => {
            // 서명 결과가 늦게 들어오거나 바뀜
            let f = r.pick(&w.files);
            let v = match r.below(6) {
                5 => serde_json::json!({"sig_status": "valid", "signer": "Google LLC"}),
                0 => serde_json::json!({"sig_status": "nosignature"}),
                1 => serde_json::json!({"sig_status": "valid", "signer": "Microsoft Windows"}),
                2 => serde_json::json!({"sig_status": "valid", "signer": "Vendor Inc"}),
                3 => serde_json::json!({"zone_id": 3}),
                _ => serde_json::json!({"zone_id": 1}),
            };
            s.merge_node_attrs(f, &v).unwrap();
        }
        1 => {
            // svchost 서비스 목록·프로세스 종료 표시
            let p = r.pick(&w.procs);
            let v = if r.chance(50) {
                serde_json::json!({"services": ["Dnscache"]})
            } else {
                serde_json::json!({"ended": true, "services": []})
            };
            s.merge_node_attrs(p, &v).unwrap();
        }
        2 => {
            // 원격지 주소가 바뀜(외부 ↔ 내부)
            let rm = r.pick(&w.remotes);
            let ip = r.pick(IPS);
            s.merge_node_attrs(rm, &serde_json::json!({ "ip": ip }))
                .unwrap();
        }
        3 => {
            // CAPI2 가 창 귀속 선을 지움(ingest 와 같은 삭제)
            if let Some(e) = random_edge_id(s, r, Some("connected_via")) {
                s.conn()
                    .execute("DELETE FROM edges WHERE id = ?1", [e])
                    .unwrap();
            }
        }
        4 => {
            // 아무 선이나 지움(가장 큰 id 를 지우면 다음 선이 id 를 다시 쓴다)
            if r.chance(50) {
                s.conn()
                    .execute(
                        "DELETE FROM edges WHERE id = (SELECT MAX(id) FROM edges)",
                        [],
                    )
                    .unwrap();
            } else if let Some(e) = random_edge_id(s, r, None) {
                s.conn()
                    .execute("DELETE FROM edges WHERE id = ?1", [e])
                    .unwrap();
            }
        }
        5 => {
            // 부팅 시각 보정처럼 선 시각을 바꿈(목록 순서가 바뀐다)
            if let Some(e) = random_edge_id(s, r, None) {
                let ts = random_ts(r, step);
                s.conn()
                    .execute("UPDATE edges SET ts = ?1 WHERE id = ?2", [ts, e])
                    .unwrap();
            }
        }
        6 => {
            // 연결 표뿐이던 접속에 ETW 근거가 붙음(table_only 해제)
            if let Some(e) = random_edge_id(s, r, Some("connected")) {
                let rid = raw(s, T0 + step * SEC, "etw:network");
                s.add_evidence(e, rid).unwrap();
            }
        }
        7 => {
            // ran 선에 원래 도구 이름이 붙음(ingest 와 같은 갱신)
            if let Some(e) = random_edge_id(s, r, Some("ran")) {
                let tool = r.pick(&["vssadmin.exe", "notepad.exe"]);
                s.conn()
                    .execute(
                        "UPDATE edges SET attrs_json = json_object('tool', ?1) WHERE id = ?2",
                        rusqlite::params![tool, e],
                    )
                    .unwrap();
            }
        }
        _ => {
            // "정상" 피드백(점수만 바뀐다 — 뷰는 그대로)
            let f = r.pick(&w.files);
            let node = s.node(f).unwrap();
            bl.mark_normal(s, &node).unwrap();
        }
    }
}

fn chapters(s: &Store) -> Vec<(i64, Option<i64>)> {
    let mut st = s
        .conn()
        .prepare("SELECT id, chapter FROM edges ORDER BY id")
        .unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|x| x.unwrap())
        .collect()
}

type Shape = (
    Vec<graph::Node>,
    Vec<graph::Edge>,
    Vec<(i64, Vec<i64>)>,
    Vec<(i64, Vec<i64>)>,
    Vec<i64>,
);
/// 뷰의 내용(위치 번호가 아니라 선 id 로). 노드 시각(first_ts·last_ts)은 증분 뷰에서 낡을 수 있어 판정이 읽는 것만 비교한다
fn view_shape(v: &judge::View) -> Shape {
    let mut nodes: Vec<graph::Node> = v
        .nodes
        .values()
        .map(|n| {
            // 판정이 읽는 시각은 맞아야 한다: 프로세스의 first_ts, 끝난 프로세스의 last_ts ((사) 보조 근거)
            let proc = n.kind == "process";
            let ended = n.attr("ended").and_then(|x| x.as_bool()).unwrap_or(false);
            graph::Node {
                first_ts: if proc { n.first_ts } else { 0 },
                last_ts: if proc && ended { n.last_ts } else { 0 },
                ..n.clone()
            }
        })
        .collect();
    nodes.sort_by_key(|n| n.id);
    let mut edges: Vec<graph::Edge> = v
        .by_id
        .keys()
        .map(|id| graph::Edge {
            chapter: None,
            ..v.edge(*id).unwrap().clone()
        })
        .collect();
    edges.sort_by_key(|e| e.id);
    let lists = |m: &std::collections::HashMap<i64, Vec<usize>>| {
        let mut l: Vec<(i64, Vec<i64>)> = m
            .iter()
            .map(|(n, ix)| (*n, ix.iter().map(|i| v.edges[*i].id).collect()))
            .collect();
        l.sort();
        l
    };
    let mut t: Vec<i64> = v.table_only.iter().copied().collect();
    t.sort();
    (nodes, edges, lists(&v.out), lists(&v.inc), t)
}

/// 증분 판정에서 본 뿌리 종류·이유(무작위 시험이 실제로 모든 규칙을 지났는지 확인)
static SEEN: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn check(s: &Store, inc: &mut Incremental, bl: &Baseline, ctx: &str) -> judge::Profile {
    let (a, prof) = inc.run(s, 0, i64::MAX, bl).unwrap();
    if prof.mode == "incremental" {
        let mut seen = SEEN.lock().unwrap();
        for st in &a {
            let k = format!("{:?}", st.root_kind);
            if !seen.contains(&k) {
                seen.push(k);
            }
            for r in &st.reasons {
                if !seen.iter().any(|x| x == r.what) {
                    seen.push(r.what.to_string());
                }
            }
        }
    }
    // 메모리 뷰 = 지금 DB 를 처음부터 읽은 뷰 (노드 집합·속성, 선마다 나가는·들어오는 목록과 그 순서, table_only)
    let fresh = judge::View::load(s, 0, i64::MAX).unwrap();
    let mine = inc.view().expect("뷰");
    let (x, y) = (view_shape(mine), view_shape(&fresh));
    assert_eq!(x.0, y.0, "{ctx}: 증분({}) 뷰 노드 다름", prof.mode);
    assert_eq!(x.1, y.1, "{ctx}: 증분({}) 뷰 선 다름", prof.mode);
    assert_eq!(x.2, y.2, "{ctx}: 증분({}) 뷰 나가는 목록 다름", prof.mode);
    assert_eq!(x.3, y.3, "{ctx}: 증분({}) 뷰 들어오는 목록 다름", prof.mode);
    assert_eq!(x.4, y.4, "{ctx}: 증분({}) 뷰 table_only 다름", prof.mode);
    let before = chapters(s);
    // 전체 판정(쓰기 있음): 증분이 쓴 장이 맞으면 아무것도 바꾸지 않는다
    let b = judge::run(s, 0, i64::MAX, bl).unwrap();
    let after = chapters(s);
    let ja = serde_json::to_value(&a).unwrap();
    let jb = serde_json::to_value(&b).unwrap();
    if ja != jb {
        if let Ok(d) = std::env::var("SF_INC_DUMP") {
            std::fs::write(
                format!("{d}/a.json"),
                serde_json::to_string_pretty(&ja).unwrap(),
            )
            .unwrap();
            std::fs::write(
                format!("{d}/b.json"),
                serde_json::to_string_pretty(&jb).unwrap(),
            )
            .unwrap();
        }
    }
    assert_eq!(ja, jb, "{ctx}: 증분({}) ≠ 전체", prof.mode);
    assert_eq!(before, after, "{ctx}: 증분이 쓴 장이 전체 판정과 다름");
    prof
}

/// (사) 미끼 폴더 등록(프로세스 전역). 모든 시험이 판정 전에 부른다 — 한 번만 바뀌므로(설정 세대가 한 번 오른다)
/// 다른 시험이 도는 중에 "설정 바뀜 → 전체 다시"가 끼어들지 않는다
fn init() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        judge::set_decoy_dirs(vec![
            r"C:\Users\u\AppData\Roaming\Exodus\exodus.wallet".into()
        ]);
    });
}

fn run_seed(seed: u64, steps: i64, full_every: u32) -> (usize, usize) {
    init();
    let s = Store::open_in_memory().unwrap();
    let bl = Baseline::open(&s, T0 + 30 * 24 * 3600 * SEC).unwrap();
    let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut w = setup(&s, &mut r);
    let mut inc = Incremental::new();
    inc.full_every = full_every;
    let (mut n_inc, mut n_full) = (0, 0);
    for step in 1..=steps {
        for _ in 0..=r.below(4) {
            if r.chance(70) {
                add_random_edge(&s, &mut w, &mut r, step);
            } else {
                mutate(&s, &mut w, &mut r, step, &bl);
            }
        }
        // 가끔 보관 정리(대량 삭제 → "전체 다시" 표시)
        if r.chance(4) {
            let now = T0 + (step + 4 * 24 * 3600) * SEC;
            graph::retention::apply(&s, now, graph::retention::RetentionPolicy::default()).unwrap();
            // 고아 노드가 지워졌다 — 노드 목록을 다시(같은 키는 같은 노드, 지워진 것은 새로)
            let n = w.n;
            w = setup(&s, &mut r);
            w.n += n;
        }
        if r.chance(60) {
            let p = check(&s, &mut inc, &bl, &format!("seed {seed} step {step}"));
            if p.mode == "incremental" {
                n_inc += 1;
            } else {
                n_full += 1;
            }
        }
    }
    // 변경 기록은 소비 뒤 지워진다(마지막 판정 이후 것만 남음)
    let left: i64 = s
        .conn()
        .query_row("SELECT COUNT(*) FROM graph_changes", [], |x| x.get(0))
        .unwrap();
    assert!(left < 200, "변경 기록이 지워지지 않음: {left}");
    (n_inc, n_full)
}

#[test]
fn incremental_equals_full_on_random_sequences() {
    let (mut ni, mut nf) = (0, 0);
    let only: Option<u64> = std::env::var("SF_INC_SEED")
        .ok()
        .and_then(|v| v.parse().ok());
    // 더 많이: SF_INC_SEEDS=500 cargo test --release -p judge --test incremental
    let seeds: u64 = std::env::var("SF_INC_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24);
    for seed in 1..=seeds {
        if only.is_some_and(|o| o != seed) {
            continue;
        }
        let steps: i64 = std::env::var("SF_INC_STEPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120);
        let (i, f) = run_seed(seed, steps, 1000);
        ni += i;
        nf += f;
    }
    // 증분 경로가 실제로 많이 돌았는가(전체 다시로만 통과하지 않게)
    assert!(ni > nf * 3, "증분 {ni}회 / 전체 {nf}회");
    // 증분 경로에서 모든 뿌리 규칙과 (사) 신호·보조 근거가 나왔는가(시험이 그 길을 실제로 지났는가)
    if only.is_none() {
        let seen = SEEN.lock().unwrap();
        for k in [
            "IngressFile",
            "UnsignedProcess",
            "IsolatedSvchost",
            "LolbinFromDocApp",
            "RecoveryInhibit",
            "VaultAccess",
            "SignedPersist",
            "브라우저가 아닌 프로그램이 브라우저 저장소를 엶",
            "미끼 파일 접근",
            "디버깅 모드로 브라우저 실행",
            "브라우저 디버깅 포트 접속",
            "브라우저가 아닌 프로그램이 브라우저 권한 상승 서비스를 실행",
            "브라우저 종료 직후 권한 상승 서비스 시작",
        ] {
            assert!(
                seen.iter().any(|x| x == k),
                "증분 경로에서 {k} 가 한 번도 나오지 않음: {seen:?}"
            );
        }
    }
}

#[test]
fn periodic_full_rebuild_safety_net() {
    init();
    let s = Store::open_in_memory().unwrap();
    let bl = Baseline::open(&s, T0).unwrap();
    let mut r = Rng(7);
    let mut w = setup(&s, &mut r);
    let mut inc = Incremental::new();
    inc.full_every = 3;
    let mut modes = Vec::new();
    for step in 1..=8 {
        add_random_edge(&s, &mut w, &mut r, step);
        modes.push(check(&s, &mut inc, &bl, "safety").mode);
    }
    assert_eq!(
        modes,
        vec![
            "full",
            "incremental",
            "incremental",
            "incremental",
            "full",
            "incremental",
            "incremental",
            "incremental"
        ]
    );
}

#[test]
fn retention_marks_reset_and_chapter_writes_do_not_log() {
    init();
    let s = Store::open_in_memory().unwrap();
    let bl = Baseline::open(&s, T0).unwrap();
    let mut r = Rng(11);
    let mut w = setup(&s, &mut r);
    for step in 1..=30 {
        add_random_edge(&s, &mut w, &mut r, step);
    }
    let mut inc = Incremental::new();
    check(&s, &mut inc, &bl, "first");
    // 판정 자신의 장 기록은 변경 기록을 남기지 않는다 → 아무 변경 없으면 증분이 아무것도 다시 모으지 않는다
    let p = check(&s, &mut inc, &bl, "idle");
    assert_eq!(p.mode, "incremental");
    assert_eq!(p.delta_edges, 0);
    assert_eq!(p.chains_built, 0);
    assert_eq!(p.updates, 0);
    // 보관 정리로 지운 것이 있으면 다음 판정은 전체 다시
    graph::retention::apply(
        &s,
        T0 + 40 * 24 * 3600 * SEC,
        graph::retention::RetentionPolicy::default(),
    )
    .unwrap();
    let p = check(&s, &mut inc, &bl, "after retention");
    assert_eq!(p.mode, "full");
    // 보관 정리 중 트리거는 꺼져 있었다(행마다 기록하지 않음) — 표시 하나만 남았다가 소비됨
    let left: i64 = s
        .conn()
        .query_row("SELECT COUNT(*) FROM graph_changes", [], |x| x.get(0))
        .unwrap();
    assert_eq!(left, 0);
    let bulk: Option<String> = s.get_meta(graph::changes::BULK_KEY).unwrap();
    assert!(bulk.is_none(), "대량 변경 표시가 남음");
}

/// 사슬 캐시가 (사) 신호 판단의 "끝점 밖" 노드를 의존으로 갖는가 — 무작위 시험에서는 다른 사건의 장 기록에 가려지기 쉬워 따로 고정한다.
/// ① 앞 사건(유입 파일)이 가진 백신 프로세스가 금고 파일을 연다. 백신 실행 파일의 서명이 Microsoft → 다른 회사로 바뀌면
///    면제가 풀려 그 선이 신호(2장)가 된다. 백신 프로세스는 앞 사건에 묶여 (사) 뿌리가 되지 않으므로 앞 사건의 사슬이 다시 모여야 한다
/// ② (사) 뿌리 프로세스의 실행 파일(확장자 없음 — (가) 뿌리가 아님)이 나중에 Zone 3 이 되면 1장(유입)이 생긴다
#[test]
fn chain_cache_tracks_vault_dependencies_outside_endpoints() {
    init();
    let s = Store::open_in_memory().unwrap();
    let bl = Baseline::open(&s, T0).unwrap();
    let file = |p: &str, a: &str| {
        let label = p.rsplit('\\').next().unwrap();
        s.upsert_node(NodeKind::File, p, label, T0, Some(a))
            .unwrap()
    };
    let proc_ = |key: &str, img: &str| {
        let a = format!(
            r#"{{"image":{},"pid":{}}}"#,
            serde_json::to_string(img).unwrap(),
            key.len() + 100
        );
        let label = img.rsplit('\\').next().unwrap();
        s.upsert_node(NodeKind::Process, key, label, T0, Some(&a))
            .unwrap()
    };
    let edge = |a: i64, b: i64, rel: Rel, k: i64| {
        let ts = T0 + k * SEC;
        s.insert_edge(a, b, rel, ts, Some(raw(&s, ts, "etw:process")))
            .unwrap();
    };
    const MPENG: &str =
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe";
    const LOGIN: &str = r"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data";
    const TOOL: &str = r"C:\Users\u\Downloads\tool.exe";
    const STEALER: &str = r"C:\Users\u\AppData\Local\Temp\stealer";
    // ①
    let x = file(TOOL, r#"{"zone_id":3}"#);
    let a = proc_("1@1", TOOL);
    let m = file(
        MPENG,
        r#"{"sig_status":"valid","signer":"Microsoft Windows"}"#,
    );
    let d = proc_("2@2", MPENG);
    let login = file(LOGIN, "{}");
    edge(x, a, Rel::ExecutedAs, 1);
    edge(a, d, Rel::Spawned, 2);
    edge(m, d, Rel::ExecutedAs, 2);
    edge(d, login, Rel::Opened, 3);
    // ②
    let st = file(STEALER, r#"{"sig_status":"valid","signer":"Vendor Inc"}"#);
    let p = proc_("3@3", STEALER);
    edge(st, p, Rel::ExecutedAs, 4);
    edge(p, login, Rel::Opened, 5);

    let mut inc = Incremental::new();
    assert_eq!(check(&s, &mut inc, &bl, "first").mode, "full");
    assert_eq!(check(&s, &mut inc, &bl, "idle").mode, "incremental");
    s.merge_node_attrs(
        m,
        &serde_json::json!({"sig_status": "valid", "signer": "Vendor Inc"}),
    )
    .unwrap();
    let p1 = check(&s, &mut inc, &bl, "① 백신 서명 바뀜");
    assert_eq!(p1.mode, "incremental");
    assert!(p1.chains_built > 0, "① 사슬을 다시 모으지 않음");
    s.merge_node_attrs(st, &serde_json::json!({"zone_id": 3}))
        .unwrap();
    let p2 = check(&s, &mut inc, &bl, "② 실행 파일 Zone 3");
    assert_eq!(p2.mode, "incremental");
    assert!(p2.chains_built > 0, "② 사슬을 다시 모으지 않음");
}

/// 30차 Q8: 느린 사슬 — 유입 → 실행 뒤 수십 분 간격으로 자리잡기·외부 접속이 붙어도, 매 분 증분 판정이 전체 판정과 같고
/// 마지막에 4장(외부 접속)까지 이어진다. 새 선의 끝점이 바뀐 노드로 들어가 그 주변 뿌리를 다시 분류하는지 본다
#[test]
fn slow_chain_over_tens_of_minutes_matches_full() {
    init();
    let s = Store::open_in_memory().unwrap();
    let bl = Baseline::open(&s, T0).unwrap();
    let min = 60 * SEC;
    let edge = |a: i64, b: i64, rel: Rel, ts: i64| {
        s.insert_edge(a, b, rel, ts, Some(raw(&s, ts, "etw:process")))
            .unwrap();
    };
    const DL: &str = r"C:\Users\u\Downloads\invoice.exe";
    let f = s
        .upsert_node(
            NodeKind::File,
            DL,
            "invoice.exe",
            T0,
            Some(r#"{"zone_id":3,"sig_status":"nosignature"}"#),
        )
        .unwrap();
    let br = s
        .upsert_node(NodeKind::Process, "10@1", "msedge.exe", T0, Some(r#"{"image":"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe","pid":10}"#))
        .unwrap();
    let p = s
        .upsert_node(
            NodeKind::Process,
            "20@2",
            "invoice.exe",
            T0,
            Some(&format!(
                r#"{{"image":{},"pid":20}}"#,
                serde_json::to_string(DL).unwrap()
            )),
        )
        .unwrap();
    let mut inc = Incremental::new();
    // 0분: 내려받기, 1분: 실행
    edge(br, f, Rel::Downloaded, T0);
    edge(f, p, Rel::ExecutedAs, T0 + min);
    assert_eq!(check(&s, &mut inc, &bl, "0~1분").mode, "full");
    // 매 분 아무 일 없음(증분)
    for k in 2..15 {
        let pf = check(&s, &mut inc, &bl, &format!("{k}분 조용"));
        assert_eq!(pf.mode, "incremental");
    }
    // 15분: 자리잡기
    let run = s
        .upsert_node(
            NodeKind::Autorun,
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Inv",
            "Inv",
            T0 + 15 * min,
            None,
        )
        .unwrap();
    edge(p, run, Rel::Registered, T0 + 15 * min);
    assert_eq!(
        check(&s, &mut inc, &bl, "15분 자리잡기").mode,
        "incremental"
    );
    for k in 16..30 {
        check(&s, &mut inc, &bl, &format!("{k}분 조용"));
    }
    // 30분: 처음 보는 해외 서버 접속
    let r = s
        .upsert_node(
            NodeKind::Remote,
            "203.0.113.7:8443",
            "203.0.113.7",
            T0 + 30 * min,
            Some(r#"{"ip":"203.0.113.7","port":8443,"proto":"tcp"}"#),
        )
        .unwrap();
    edge(p, r, Rel::Connected, T0 + 30 * min);
    let pf = check(&s, &mut inc, &bl, "30분 외부 접속");
    assert_eq!(pf.mode, "incremental");
    let (stories, _) = inc.run(&s, 0, i64::MAX, &bl).unwrap();
    let st = stories
        .iter()
        .find(|x| x.root == f)
        .expect("유입 파일이 뿌리인 사건");
    assert_eq!(
        st.chapter,
        judge::Chapter::Egress,
        "30분 뒤 접속까지 한 사건으로 이어진다"
    );
}
