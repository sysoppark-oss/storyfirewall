//! AI 에이전트 감시 (기획서 14판 20-5): PC 의 AI 도구(데스크톱 앱·코딩 도우미·MCP 서버)가
//! 어디와 통신하고, 무엇을 실행하고, 어떤 파일을 만들었는지 도구별로 모은다.
//!
//! 판정하지 않는다 — 사실 목록만. 모으는 방법은 설치 엑스레이와 같다(뿌리 프로세스 + 자손 트리, `install::install_xray`).
//! 플랫폼 전용 코드 없음(엔진 공유 원칙).
//!
//! 찾는 방법
//! - 실행 파일 이름(목록). 이름을 바꾼 사본은 놓친다.
//! - node·python 으로 도는 도구는 실행 파일이 node.exe 라 이름으로 알 수 없다 → 명령줄(ran 선의 명령 노드)에 든 패키지 이름.
//!   명령줄을 받지 못한 프로세스는 놓친다(수집 한계).
//! - 뿌리만 고른다: 부모가 같은 도구면 자손 트리에 이미 들어 있으므로 뿌리로 세지 않는다.

use rusqlite::params;
use serde::Serialize;

use crate::install::{install_xray, InstallRun};
use crate::store::Store;
use crate::Result;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct AgentKind {
    pub key: &'static str,
    pub display: &'static str,
    /// 소문자 실행 파일 이름
    pub images: &'static [&'static str],
    /// 명령줄에 들어 있으면 이 도구(소문자 비교)
    pub cmd_markers: &'static [&'static str],
}

/// 첫 목록. 이름·패키지는 각 배포처(공식 설치본·npm 패키지 이름)에서 확인한다 — 실측으로 보탠다.
pub const AGENTS: &[AgentKind] = &[
    AgentKind {
        key: "claude",
        display: "Claude",
        images: &["claude.exe"],
        cmd_markers: &["@anthropic-ai/claude-code"],
    },
    AgentKind {
        key: "chatgpt",
        display: "ChatGPT",
        images: &["chatgpt.exe"],
        cmd_markers: &[],
    },
    AgentKind {
        key: "codex",
        display: "Codex",
        images: &["codex.exe"],
        cmd_markers: &["@openai/codex"],
    },
    AgentKind {
        key: "gemini",
        display: "Gemini CLI",
        images: &[],
        cmd_markers: &["@google/gemini-cli"],
    },
    AgentKind {
        key: "cursor",
        display: "Cursor",
        images: &["cursor.exe"],
        cmd_markers: &[],
    },
    AgentKind {
        key: "windsurf",
        display: "Windsurf",
        images: &["windsurf.exe"],
        cmd_markers: &[],
    },
    AgentKind {
        key: "ollama",
        display: "Ollama",
        images: &["ollama.exe", "ollama app.exe"],
        cmd_markers: &[],
    },
    AgentKind {
        key: "lmstudio",
        display: "LM Studio",
        images: &["lm studio.exe"],
        cmd_markers: &[],
    },
    // 다른 도구가 띄우지 않고 혼자 도는 MCP 서버(공식 SDK·참조 서버 패키지 이름)
    AgentKind {
        key: "mcp",
        display: "MCP 서버",
        images: &[],
        cmd_markers: &["@modelcontextprotocol/", "mcp-server-"],
    },
];

fn base_lower(image: &str) -> String {
    image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image)
        .to_ascii_lowercase()
}

pub fn agent_of_image(image: &str) -> Option<&'static AgentKind> {
    let b = base_lower(image);
    AGENTS.iter().find(|a| a.images.contains(&b.as_str()))
}

/// 명령줄의 패키지 이름. Windows npm 경로는 `node_modules\@scope\pkg` 처럼 역슬래시라 `/` 로 맞춰 비교한다
pub fn agent_of_cmd(cmd: &str) -> Option<&'static AgentKind> {
    let l = cmd.to_ascii_lowercase().replace('\\', "/");
    AGENTS
        .iter()
        .find(|a| a.cmd_markers.iter().any(|m| l.contains(m)))
}

pub fn display_of(key: &str) -> &'static str {
    AGENTS
        .iter()
        .find(|a| a.key == key)
        .map(|a| a.display)
        .unwrap_or("AI 도구")
}

/// 도구 하나의 실행 한 번(뿌리 프로세스와 자손)
#[derive(Debug, Clone, Serialize)]
pub struct AgentRun {
    pub key: &'static str,
    pub display: &'static str,
    /// 어떻게 알아봤나: "image"(실행 파일 이름) | "cmdline"(명령줄 패키지 이름)
    pub found_by: &'static str,
    pub run: InstallRun,
}

/// 프로세스 노드가 어느 도구인가(이름 먼저, 다음 명령줄)
fn agent_of_node(store: &Store, id: i64) -> Result<Option<(&'static AgentKind, &'static str)>> {
    let n = store.node(id)?;
    let image = n
        .attr("image")
        .and_then(|v| v.as_str().map(|s| s.to_string()));
    if let Some(a) = image.as_deref().and_then(agent_of_image) {
        return Ok(Some((a, "image")));
    }
    let mut st = store.conn().prepare_cached(
        "SELECT c.key FROM edges e JOIN nodes c ON c.id = e.dst WHERE e.src = ?1 AND e.rel = 'ran' LIMIT 4",
    )?;
    let cmds: Vec<String> = st
        .query_map(params![id], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(cmds
        .iter()
        .find_map(|c| agent_of_cmd(c))
        .map(|a| (a, "cmdline")))
}

/// 기간 전에 시작해 아직 도는 도구를 얼마나 거슬러 찾나(일)
pub const LONG_RUNNING_DAYS: i64 = 30;

/// `since_ts`(FILETIME) 이후 시작했거나 그 전부터 아직 도는 AI 도구 뿌리 프로세스(최신 먼저). (노드 id, 도구, 찾은 방법)
pub fn agent_roots(
    store: &Store,
    since_ts: i64,
    limit: usize,
) -> Result<Vec<(i64, &'static AgentKind, &'static str)>> {
    let conn = store.conn();
    let mut cands: Vec<(i64, i64)> = Vec::new();
    // 1) 이름: 라벨(파일 이름)로 거른다. 그 기간에 시작한 것 + 그 전에 시작해 아직 도는 것(데스크톱 앱은 며칠씩 켜 둔다).
    //    끝 표시 없는 오래된 노드는 서비스가 꺼진 사이 끝난 것일 수 있어 `LONG_RUNNING_DAYS` 안으로만
    {
        let names: Vec<&str> = AGENTS
            .iter()
            .flat_map(|a| a.images.iter().copied())
            .collect();
        let mut st = conn.prepare(
            "SELECT id, first_ts, lower(label), COALESCE(json_extract(attrs_json, '$.ended'), 0) FROM nodes
             WHERE kind = 'process' AND first_ts >= ?1",
        )?;
        let oldest = since_ts - LONG_RUNNING_DAYS * 86_400 * 10_000_000;
        let rows = st.query_map(params![oldest], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        for row in rows {
            let (id, ts, label, ended) = row?;
            if names.contains(&label.as_str()) && (ts >= since_ts || ended == 0) {
                cands.push((id, ts));
            }
        }
    }
    // 2) 명령줄: 그 기간의 ran 선 중 패키지 이름이 든 것
    {
        let mut st = conn.prepare(
            "SELECT e.src, e.ts, c.key FROM edges e JOIN nodes c ON c.id = e.dst WHERE e.rel = 'ran' AND e.ts >= ?1",
        )?;
        let rows = st.query_map(params![since_ts], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (id, ts, cmd) = row?;
            if agent_of_cmd(&cmd).is_some() && !cands.iter().any(|c| c.0 == id) {
                cands.push((id, ts));
            }
        }
    }
    cands.sort_by(|a, b| b.1.cmp(&a.1).then(b.0.cmp(&a.0)));
    let mut parent_st = conn.prepare_cached(
        "SELECT e.src FROM edges e JOIN nodes n ON n.id = e.src WHERE e.dst = ?1 AND e.rel = 'spawned' AND n.kind = 'process' LIMIT 1",
    )?;
    let mut out = Vec::new();
    for (id, _) in cands {
        let Some((a, how)) = agent_of_node(store, id)? else {
            continue;
        };
        // 부모가 AI 도구면(같은 도구든, MCP 서버를 띄운 도구든) 그 트리에 들어 있다 — 뿌리 아님
        let parent: Option<i64> = parent_st.query_row(params![id], |r| r.get(0)).ok();
        if let Some(p) = parent {
            if agent_of_node(store, p)?.is_some() {
                continue;
            }
        }
        out.push((id, a, how));
        if out.len() >= limit {
            break;
        }
    }
    Ok(out)
}

/// 최근 AI 도구 실행 목록과 각 실행의 사실(통신한 곳·실행한 명령·만든 실행 파일·자동 실행 등록)
pub fn agent_activity(
    store: &Store,
    since_ts: i64,
    limit: usize,
    max_procs: usize,
) -> Result<Vec<AgentRun>> {
    let roots = agent_roots(store, since_ts, limit)?;
    let mut out = Vec::with_capacity(roots.len());
    for (id, a, how) in roots {
        out.push(AgentRun {
            key: a.key,
            display: a.display,
            found_by: how,
            run: install_xray(store, id, max_procs)?,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_markers() {
        assert_eq!(
            agent_of_image(r"C:\Users\u\AppData\Local\AnthropicClaude\app-1.0\claude.exe")
                .map(|a| a.key),
            Some("claude")
        );
        assert_eq!(
            agent_of_image(r"C:\x\Ollama App.exe").map(|a| a.key),
            Some("ollama")
        );
        assert!(agent_of_image(r"C:\Windows\System32\notepad.exe").is_none());
        assert_eq!(
            agent_of_cmd(r#""C:\Program Files\nodejs\node.exe" C:\Users\u\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js"#)
                .map(|a| a.key),
            Some("claude"),
            "Windows 경로 구분자(역슬래시)도 패키지 이름으로 맞춘다"
        );
        assert_eq!(
            agent_of_cmd("npx -y @modelcontextprotocol/server-filesystem C:/work").map(|a| a.key),
            Some("mcp")
        );
    }
}
