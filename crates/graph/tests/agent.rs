//! AI 에이전트 감시 (기획서 14판 20-5): 뿌리 고르기와 도구별 사실

use graph::agent::{agent_activity, agent_roots};
use graph::event::{Direction, Event, EventKind, ProcRef, Proto};
use graph::ingest::Ingester;
use graph::Store;

const T: i64 = 133_800_000_000_000_000;
const S: i64 = 10_000_000;

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
fn cmd(ts: i64, pid: u32, line: &str) -> Event {
    ev(
        ts,
        "etw:process",
        EventKind::ProcessCommand {
            proc: ProcRef::new(pid, None),
            cmdline: line.into(),
            tool: None,
        },
    )
}
fn connect(ts: i64, pid: u32, raddr: &str) -> Event {
    ev(
        ts,
        "etw:network",
        EventKind::Connect {
            proc: ProcRef::new(pid, None),
            proto: Proto::Tcp,
            direction: Direction::Out,
            laddr: "10.0.0.2".into(),
            lport: 50000,
            raddr: raddr.into(),
            rport: 443,
        },
    )
}

const CLAUDE: &str = r"C:\Users\u\AppData\Local\AnthropicClaude\app-1.0.0\claude.exe";
const NODE: &str = r"C:\Program Files\nodejs\node.exe";

fn scenario() -> Store {
    let st = Store::open_in_memory().unwrap();
    let mut ing = Ingester::new(&st);
    let evs = vec![
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
        // 데스크톱 앱: 자기 자식(같은 이름)과 MCP 서버(node)를 띄우고, MCP 서버가 셸을 실행
        start(T + S, 2000, 1000, CLAUDE),
        start(T + 2 * S, 2001, 2000, CLAUDE),
        start(T + 3 * S, 2100, 2000, NODE),
        cmd(
            T + 3 * S,
            2100,
            r"node C:\Users\u\AppData\Roaming\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js C:\work",
        ),
        start(T + 4 * S, 2200, 2100, r"C:\Windows\System32\cmd.exe"),
        cmd(T + 4 * S, 2200, "cmd.exe /c dir C:\\work"),
        connect(T + 5 * S, 2001, "203.0.113.30"),
        // 터미널에서 돈 코딩 도우미(node + 패키지 이름)
        start(T + 10 * S, 3000, 1000, r"C:\Windows\System32\cmd.exe"),
        start(T + 11 * S, 3100, 3000, NODE),
        cmd(
            T + 11 * S,
            3100,
            r#""C:\Program Files\nodejs\node.exe" C:\Users\u\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js"#,
        ),
        connect(T + 12 * S, 3100, "203.0.113.31"),
        // 평범한 node(도구 아님)
        start(T + 20 * S, 4000, 1000, NODE),
        cmd(T + 20 * S, 4000, "node server.js"),
    ];
    for e in &evs {
        ing.ingest(e).unwrap();
    }
    st
}

#[test]
fn roots_skip_children_of_agents() {
    let st = scenario();
    let roots = agent_roots(&st, T, 10).unwrap();
    let got: Vec<(&str, &str)> = roots.iter().map(|r| (r.1.key, r.2)).collect();
    // 최신 먼저: 터미널의 Claude Code(명령줄로), 데스크톱 앱(이름으로). 자식 claude.exe·MCP 서버·평범한 node 는 뿌리 아님
    assert_eq!(got, vec![("claude", "cmdline"), ("claude", "image")]);
}

#[test]
fn activity_collects_subtree_facts() {
    let st = scenario();
    let acts = agent_activity(&st, T, 10, 100).unwrap();
    let desktop = acts.iter().find(|a| a.found_by == "image").unwrap();
    // 자손(자식 claude.exe, MCP 서버 node, 그 셸)까지
    assert_eq!(desktop.run.procs.len(), 4, "{:?}", desktop.run.procs);
    assert!(
        desktop.run.commands.iter().any(|c| c.contains("dir")),
        "{:?}",
        desktop.run.commands
    );
    assert!(
        desktop
            .run
            .remotes
            .iter()
            .any(|r| r.0.contains("203.0.113.30")),
        "{:?}",
        desktop.run.remotes
    );
    let cli = acts.iter().find(|a| a.found_by == "cmdline").unwrap();
    assert!(
        cli.run.remotes.iter().any(|r| r.0.contains("203.0.113.31")),
        "{:?}",
        cli.run.remotes
    );
    // 나중 기간: 아직 도는(끝 표시 없는) 데스크톱 앱만 남는다. 끝난 CLI 는 빠진다
    let mut ing = Ingester::new(&st);
    ing.ingest(&ev(
        T + 50 * S,
        "etw:process",
        EventKind::ProcessStop { pid: 3100 },
    ))
    .unwrap();
    let later = agent_activity(&st, T + 100 * S, 10, 100).unwrap();
    let keys: Vec<&str> = later.iter().map(|a| a.found_by).collect();
    assert_eq!(keys, vec!["image"]);
}
