//! 파괴 행위 자동 대응 집행(대시보드 개편안 2판 4-2). 판정은 `judge::respond`, 여기는 집행만.
//!
//! - 설정 `auto_destroy_response`(bool). **기본 켬**(2판 4-2; A29 러너 실집행 통과 뒤 사용자 결정 2026-11-08 "켬").
//!   `auto_destroy_allow_signers`(문자열 배열): 서명자 이름 정확 일치(대소문자·앞뒤 공백 무시, 44차 Q1-②) — 백업 도구 같은 정당한 예외.
//! - Full: 기존 "여기서부터 끊기"(`cut::plan_with` → `engine.apply_full(source=cut)` → 종료)를 승인 없이 부른다.
//!   정책은 바로 `confirm` 한다(60초 확인 창은 사람이 있을 때의 안전장치이고, 여기 대상은 서명 없는 원인 프로그램의
//!   경로와 그 접속지뿐 — 가드 규칙은 엔진이 그대로 지킨다). 되돌리기는 정책 이력의 이 request_id 로(`policy.rollback`).
//! - ChildOnly(핵심 프로세스·Windows 도구가 부모): 명령을 실행한 프로세스만 종료. 필터 없음.
//! - 격리·자리잡기 제거는 끊기와 같이 아직 "할 일(pending)"로만 남긴다(끊기 경로와 같은 수준).
//! - 한 사건은 한 번만(사건 추적 상태가 열려 있을 때만), 서명 예외로 건너뛴 사건은 사건 기록 한 줄만 남긴다.
//! - 한계: ETW 는 사후 통지 — 이 대응은 피해를 "줄이기"이지 "막기"가 아니다.

use crate::runtime::World;
use judge::respond::{self, Mode, Verdict};

pub const SETTING_ON: &str = "auto_destroy_response";
pub const SETTING_ALLOW: &str = "auto_destroy_allow_signers";
pub const ACTOR: &str = "system:auto_destroy";
/// 사건 추적 메모 머리 — UI 가 [되돌리기] 를 붙이는 표시. 꼴: `auto:<policy_id>:<version>` (정책 없으면 0:0)
pub const NOTE_PREFIX: &str = "auto:";

pub fn enabled(world: &World) -> bool {
    world
        .settings
        .get(SETTING_ON)
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

pub fn allow_signers(world: &World) -> Vec<String> {
    world
        .settings
        .get(SETTING_ALLOW)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// 주기 판정 뒤에 부른다. 돌려주는 값: 이번에 집행한 사건 수
pub fn run_after_judge(world: &mut World, stories: &[judge::Story]) -> usize {
    if !enabled(world) {
        return 0;
    }
    let allow = allow_signers(world);
    let candidates: Vec<judge::Story> = stories
        .iter()
        .filter(|s| s.chapter == judge::Chapter::Destroy)
        .filter(|s| !world.auto_seen.contains(&s.root))
        .cloned()
        .collect();
    if candidates.is_empty() {
        return 0;
    }
    let mut done = 0;
    for s in candidates {
        // 이미 조치·닫힘이면(사람이 먼저 했거나 전에 자동 대응) 다시 하지 않는다
        if !crate::triage::get(&world.graph, s.root).state.is_open() {
            world.auto_seen.insert(s.root);
            continue;
        }
        let verdict = match world.judge_inc.view() {
            Some(v) => respond::judge(v, &s, &allow),
            None => continue,
        };
        world.auto_seen.insert(s.root);
        match verdict {
            Verdict::NoDestroy => {}
            Verdict::TrustedAncestor { signer, .. } => {
                let _ = world.engine.record_event(
                    "auto_destroy_skipped",
                    1,
                    format!(
                        "뿌리 {} {} — 부모 사슬에 서명 예외({signer}), 자동 대응 안 함",
                        s.root, s.root_label
                    ),
                );
            }
            Verdict::Respond(r) => {
                execute(world, &s, &r);
                done += 1;
            }
        }
    }
    if done > 0 {
        crate::runtime::flush_events(world);
    }
    done
}

fn execute(world: &mut World, s: &judge::Story, r: &respond::AutoResponse) {
    let now = world.engine_wall();
    let rid = format!("auto-destroy-{}-{now}", s.root);
    let mut policies = 0usize;
    let mut killed = 0usize;
    let mut applied: Option<(i64, i64)> = None;
    let mut notes = Vec::new();
    match r.mode {
        Mode::Full => {
            let plan = match crate::cut::plan_with(
                &world.graph,
                r.origin,
                &["terminate".to_string()],
                &|pid, ft, seen| world.host.live_image(pid, ft, seen),
            ) {
                Ok(p) => p,
                Err(e) => {
                    let _ = world.engine.record_event(
                        "auto_destroy_failed",
                        2,
                        format!("뿌리 {} 끊기 계획 실패: {e}", s.root),
                    );
                    return;
                }
            };
            if !plan.yaml.is_empty() {
                let extra: Vec<(String, String, u16, u8)> = plan
                    .addresses
                    .iter()
                    .map(|a| {
                        (
                            format!("{} ({})", a.who, a.why),
                            a.ip.clone(),
                            a.port,
                            a.proto,
                        )
                    })
                    .collect();
                // 순서: 막고 → 끊는다
                match world.engine.apply_full(
                    &plan.yaml,
                    &[],
                    &rid,
                    ACTOR,
                    Some(dsl::model::Source::Cut),
                    &extra,
                ) {
                    Ok(ar) => {
                        // 60초 확인 창 없이 바로 확정 — 되돌리기는 policy.rollback(policy_id, version)
                        if let Err(e) = world.engine.confirm(ar.policy_id, ar.version, ACTOR) {
                            notes.push(format!("확정 실패: {e}"));
                        }
                        policies += 1;
                        applied = Some((ar.policy_id, ar.version));
                        notes.push(format!("정책 {}:{}", ar.policy_id, ar.version));
                    }
                    Err(e) => {
                        notes.push(format!("정책 적용 실패: {e}"));
                    }
                }
            }
            for t in &plan.terminate {
                let outcome = world.host.terminate(t.pid, Some(t.create_ts));
                let _ = world.engine.record_event(
                    "cut_terminate",
                    2,
                    format!("pid {} {} → {outcome}", t.pid, t.image),
                );
                killed += 1;
            }
            if !plan.autoruns.is_empty() {
                notes.push(format!(
                    "자리잡기 등록 {}건은 사람이 지워야 함",
                    plan.autoruns.len()
                ));
            }
        }
        Mode::ChildOnly => {
            if let Some((pid, ct, image)) = proc_ident(world, r.trigger_proc) {
                let outcome = world.host.terminate(pid, Some(ct));
                let _ = world.engine.record_event(
                    "cut_terminate",
                    2,
                    format!("pid {pid} {image} → {outcome}"),
                );
                killed += 1;
            }
            notes.push("핵심 프로세스·Windows 도구가 부모 — 명령 실행 프로세스만 종료".into());
        }
    }
    let detail = format!(
        "뿌리 {} {} — {} 명령({}) 실행, 자동 대응: 정책 {}건·종료 {}건{}",
        s.root,
        s.root_label,
        r.what,
        match r.mode {
            Mode::Full => "원인 프로그램부터 끊기",
            Mode::ChildOnly => "자식만",
        },
        policies,
        killed,
        if notes.is_empty() {
            String::new()
        } else {
            format!(" · {}", notes.join(" · "))
        }
    );
    let _ = world
        .engine
        .record_event("auto_destroy_response", 3, detail.clone());
    let (pid_, ver_) = applied.unwrap_or((0, 0));
    let note = format!("{NOTE_PREFIX}{pid_}:{ver_}");
    let _ = crate::dispatch::set_triage(
        world,
        s.root,
        crate::triage::State::Acted,
        Some(crate::triage::Action::Cut),
        ACTOR,
        Some(&note),
    );
    world.notify(
        api::methods::NOTIFY_EVENT,
        serde_json::json!({"kind": "auto_destroy_response", "severity": 3, "root": s.root, "label": s.root_label, "request_id": rid, "detail": detail}),
    );
}

/// 프로세스 노드의 (pid, 생성 시각, 경로)
fn proc_ident(world: &World, node: i64) -> Option<(u32, i64, String)> {
    let n = world.graph.node(node).ok()?;
    if n.kind != "process" {
        return None;
    }
    // 프로세스 키 = pid@create_ft
    let (pid, ct) = graph::views::parse_proc_key(&n.key).unwrap_or((0, n.first_ts));
    if pid == 0 {
        return None;
    }
    let image = n
        .attr("image")
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();
    Some((pid, ct, image))
}
