//! 자동 조사(사용자 2026-11-07: "지금과 같은 것을 할 수 있는 분석이 프로그램에 필요함, 좀 전에 프로세스 아이디를 찾는 과정을 했던 것과
//! 같은 것도 동일함"). 개발 세션이 손으로 한 조사를 서비스가 한다:
//! 1) 실물 확인 — 기록의 (PID, 생성 시각)이 지금 살아 있는 프로세스와 같은가, 그 경로·명령줄
//! 2) 서명 — 그래프에 있으면 그것, 없으면 지금 조회
//! 3) 알려진 정상 모양 — 브라우저 → (cmd.exe) → 브라우저 확장 보조 프로그램(레지스트리 NativeMessagingHosts 에 등록된 매니페스트의 path 와
//!    실행 파일 경로가 같고 서명이 유효)
//! 4) 판단과 권장 조치 — 사실만으로. 의도를 단정하지 않는다.
//! 읽기 경로: DB 에 쓰지 않는다. 외부 문자열(경로·명령줄·등록 이름)은 자료로만 화면에 넘긴다.
use crate::host::{Host, NativeHost, SigInfo};
use graph::Store;

/// 확인한 사실 한 줄. ok: Some(true)=정상 쪽 근거, Some(false)=의심 쪽 근거, None=판단에 쓰지 않는 정보·확인 못 함
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Fact {
    pub label: String,
    pub value: String,
    pub ok: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// 알려진 정상 모양으로 확인됨(등록·경로·서명 모두 맞음)
    KnownNormal,
    /// 위험 쪽 사실이 겹침(서명 없음 + 사용자가 쓸 수 있는 위치 등)
    Risky,
    /// 판단할 사실이 모자람 — 사람이 확인
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// "이건 정상입니다"(사건 닫기)
    MarkNormal,
    /// "여기서부터 끊기"
    Cut,
    /// 사실을 더 보고 정한다(카드에 남겨 둠)
    Review,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Investigation {
    pub root: i64,
    pub facts: Vec<Fact>,
    pub verdict: Verdict,
    pub recommend: Action,
    /// 판단 한 문장(사실만)
    pub reason: String,
    /// 브라우저 확장 보조 프로그램으로 확인된 등록
    pub native_host: Option<NativeHost>,
}

const BROWSERS: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "firefox.exe",
    "chromium.exe",
];

fn file_name(p: &str) -> String {
    p.rsplit(['\\', '/'])
        .next()
        .unwrap_or(p)
        .to_ascii_lowercase()
}

fn norm_path(p: &str) -> String {
    p.trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase()
}

/// 사용자가 쓸 수 있는 위치(임시·내려받기·바탕 화면·AppData 로밍/로컬 Temp)
pub fn user_writable(path: &str) -> bool {
    let l = norm_path(path);
    l.contains("\\users\\")
        && [
            "\\appdata\\local\\temp\\",
            "\\downloads\\",
            "\\desktop\\",
            "\\appdata\\roaming\\",
        ]
        .iter()
        .any(|d| l.contains(d))
}

fn clip(s: &str, n: usize) -> String {
    let t: String = s.chars().filter(|c| !c.is_control()).take(n).collect();
    if s.chars().count() > n {
        format!("{t}…")
    } else {
        t
    }
}

fn sig_text(s: &SigInfo) -> (String, Option<bool>) {
    match s.status.as_str() {
        "valid" => (
            format!(
                "유효 · {}",
                s.signer
                    .clone()
                    .unwrap_or_else(|| "서명자 이름 없음".into())
            ),
            Some(true),
        ),
        "nosignature" => ("서명 없음".into(), Some(false)),
        st => (format!("확인 안 됨({st})"), Some(false)),
    }
}

/// 그래프의 실행 파일 노드 서명(수집기가 이미 확인한 것). 없으면 None
fn graph_sig(store: &Store, proc_id: i64) -> Option<SigInfo> {
    let d = graph::views::process_detail(store, proc_id, 0).ok()?;
    let s = d.signature?;
    let status = s.get("sig_status").and_then(|v| v.as_str())?.to_string();
    Some(SigInfo {
        status,
        signer: s
            .get("signer")
            .and_then(|v| v.as_str())
            .map(|x| x.to_string()),
    })
}

fn sig_of(store: &Store, host: &dyn Host, proc_id: i64, image: &str) -> Option<SigInfo> {
    graph_sig(store, proc_id).or_else(|| {
        if image.is_empty() {
            None
        } else {
            host.signature(image)
        }
    })
}

/// 사건 뿌리 → 조사. 파일 뿌리면 그 파일로 실행된 가장 최근 프로세스를 본다
pub fn investigate(store: &Store, host: &dyn Host, root: i64) -> graph::Result<Investigation> {
    let node = store.node(root)?;
    let proc_id = if node.kind == "process" {
        Some(root)
    } else {
        store
            .conn()
            .query_row(
                "SELECT dst FROM edges WHERE src = ?1 AND rel = 'executed_as' ORDER BY ts DESC LIMIT 1",
                [root],
                |r| r.get::<_, i64>(0),
            )
            .ok()
    };
    let mut facts = Vec::new();
    let Some(pid_node) = proc_id else {
        facts.push(Fact {
            label: "실행 기록".into(),
            value: "이 파일로 실행된 프로세스 기록이 없습니다".into(),
            ok: None,
        });
        return Ok(Investigation {
            root,
            facts,
            verdict: Verdict::Unknown,
            recommend: Action::Review,
            reason: "실행 기록이 없어 실물을 확인할 수 없습니다.".into(),
            native_host: None,
        });
    };
    let d = graph::views::process_detail(store, pid_node, 50)?;
    // 1) 실물 확인(개발 세션이 PowerShell Get-CimInstance 로 한 것과 같은 일)
    let live = if d.ended {
        None
    } else {
        host.live_image(d.pid, d.create_ts, d.node.first_ts)
    };
    let image = if d.image.is_empty() {
        live.as_ref().map(|(p, _)| p.clone()).unwrap_or_default()
    } else {
        d.image.clone()
    };
    facts.push(Fact {
        label: "지금 상태".into(),
        value: match (&live, d.ended) {
            (Some(_), _) => format!("실행 중 (PID {}, 생성 시각이 기록과 같음)", d.pid),
            (None, true) => format!("끝남 (PID {})", d.pid),
            (None, false) => format!(
                "확인 못 함 (PID {} — 같은 번호의 다른 프로그램일 수 있어 확인하지 않음)",
                d.pid
            ),
        },
        ok: None,
    });
    facts.push(Fact {
        label: "경로".into(),
        value: if image.is_empty() {
            "모름".into()
        } else {
            clip(&image, 300)
        },
        ok: None,
    });
    if live.is_some() {
        if let Some(c) = host.cmdline(d.pid, live.as_ref().map(|x| x.1).unwrap_or(d.create_ts)) {
            facts.push(Fact {
                label: "명령줄".into(),
                value: clip(&c, 400),
                ok: None,
            });
        }
    }
    let parent = d.parents.iter().find(|p| p.kind == "process");
    let parent_name = parent.map(|p| file_name(&p.label)).unwrap_or_default();
    if let Some(p) = parent {
        facts.push(Fact {
            label: "부모".into(),
            value: clip(&p.label, 120),
            ok: None,
        });
    }
    // 2) 서명
    let sig = sig_of(store, host, pid_node, &image);
    match &sig {
        Some(s) => {
            let (t, ok) = sig_text(s);
            facts.push(Fact {
                label: "서명".into(),
                value: t,
                ok,
            });
        }
        None => facts.push(Fact {
            label: "서명".into(),
            value: "확인 못 함".into(),
            ok: None,
        }),
    }
    // 3) 브라우저 확장 보조 프로그램: 브라우저가 부모인 이 프로세스(또는 cmd.exe 를 거친 자식)의 실행 파일이 등록된 path 와 같은가
    let mut native: Option<(NativeHost, i64, String)> = None;
    if BROWSERS.contains(&parent_name.as_str()) {
        let hosts = host.native_hosts();
        let mut cands: Vec<(i64, String)> = vec![(pid_node, image.clone())];
        if file_name(&image) == "cmd.exe" {
            for c in d.children.iter().filter(|c| c.kind == "process") {
                let img = graph::views::process_detail(store, c.node_id, 0)
                    .map(|x| x.image)
                    .unwrap_or_default();
                if !img.is_empty() && file_name(&img) != "conhost.exe" {
                    cands.push((c.node_id, img));
                }
            }
        }
        for (id, img) in &cands {
            if let Some(h) = hosts
                .iter()
                .find(|h| !h.path.is_empty() && norm_path(&h.path) == norm_path(img))
            {
                native = Some((h.clone(), *id, img.clone()));
                break;
            }
        }
        match &native {
            Some((h, _, img)) => facts.push(Fact {
                label: "브라우저 확장 보조 프로그램".into(),
                value: format!(
                    "등록됨 — {} ({}, {}) · 실행 파일 {}",
                    clip(&h.name, 120),
                    h.browser,
                    h.scope,
                    clip(&file_name(img), 80)
                ),
                ok: Some(true),
            }),
            None => facts.push(Fact {
                label: "브라우저 확장 보조 프로그램".into(),
                value: if hosts.is_empty() {
                    "등록 정보를 읽지 못했습니다".into()
                } else {
                    format!("등록된 {}개 중 경로가 같은 것 없음", hosts.len())
                },
                ok: if hosts.is_empty() { None } else { Some(false) },
            }),
        }
    }
    // 4) 판단
    if let Some((h, id, img)) = native {
        let hs = sig_of(store, host, id, &img);
        if id != pid_node {
            if let Some(s) = &hs {
                let (t, ok) = sig_text(s);
                facts.push(Fact {
                    label: format!("서명({})", clip(&file_name(&img), 80)),
                    value: t,
                    ok,
                });
            }
        }
        let valid = hs.as_ref().is_some_and(|s| s.status == "valid");
        return Ok(if valid {
            Investigation {
                root,
                reason: format!(
                    "브라우저({parent_name})가 확장 프로그램용으로 등록된 보조 프로그램({})을 실행했습니다. 실행 파일 경로가 등록 정보와 같고 서명이 유효합니다.",
                    clip(&h.name, 120)
                ),
                facts,
                verdict: Verdict::KnownNormal,
                recommend: Action::MarkNormal,
                native_host: Some(h),
            }
        } else {
            Investigation {
                root,
                reason: "등록된 보조 프로그램 경로와 같지만 서명을 확인하지 못했습니다. 서명을 확인한 뒤 정하세요.".into(),
                facts,
                verdict: Verdict::Unknown,
                recommend: Action::Review,
                native_host: Some(h),
            }
        });
    }
    let unsigned = sig.as_ref().is_some_and(|s| s.status != "valid");
    if unsigned && !image.is_empty() && user_writable(&image) {
        return Ok(Investigation {
            root,
            reason:
                "서명이 없거나 확인되지 않은 프로그램이 사용자가 쓸 수 있는 위치에서 실행됐습니다."
                    .into(),
            facts,
            verdict: Verdict::Risky,
            recommend: Action::Cut,
            native_host: None,
        });
    }
    Ok(Investigation {
        root,
        reason: "알려진 정상 모양으로 확인되지 않았습니다.".into(),
        facts,
        verdict: Verdict::Unknown,
        recommend: Action::Review,
        native_host: None,
    })
}
