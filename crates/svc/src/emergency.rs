//! 긴급 차단 (대시보드 개편안 3판 1-1) — 서비스 쪽: 입력 모으기, 승인 창 요약, 시작·해제·상태.
//! 필터 모양은 `policy::emergency`, 기한·60초 확인·재부팅 해제는 `engine::Engine::apply_emergency`·`reconcile`.

use crate::runtime::World;
use std::net::IpAddr;

/// 이 앱 실행 파일: 서비스 자신 + 같은 폴더의 화면(UI). **있는 것만** — 없는 경로는 WFP 가
/// FwpmGetAppIdFromFileName0 에서 0x2 로 실패해 긴급 차단 전체가 걸리지 않는다(A30 첫 실행: 러너 빌드 폴더에 UI 없음)
pub fn own_images() -> Vec<String> {
    let mut v = Vec::new();
    if let Ok(me) = std::env::current_exe() {
        v.push(me.to_string_lossy().into_owned());
        if let Some(dir) = me.parent() {
            let ui = dir.join("story-firewall-ui.exe");
            if ui.is_file() {
                v.push(ui.to_string_lossy().into_owned());
            }
        }
    }
    v
}

/// rdp_sessions() 의 이름 칸은 "상대IP\x1f클라이언트 이름" (win::wts). 상대 IP 만 꺼낸다
pub fn rdp_clients(sessions: &[(u32, String)]) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = sessions
        .iter()
        .filter_map(|(_, s)| s.split('\u{1f}').next())
        .filter_map(|ip| ip.trim().parse::<IpAddr>().ok())
        .filter(|ip| !ip.is_unspecified())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// 원격 도구 경로 검증: 시스템 핵심 프로세스(svchost 등)는 예외로 열지 않는다 — 넓은 구멍이 된다
pub fn check_tools(tools: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for t in tools {
        let t = t.trim();
        if t.is_empty() {
            continue;
        }
        if dsl::validate::is_system_image(t) {
            return Err(format!("시스템 핵심 프로세스는 예외로 둘 수 없습니다: {t}"));
        }
        out.push(t.to_string());
    }
    Ok(out)
}

pub fn input(world: &World, remote_tools: &[String]) -> Result<policy::emergency::Input, String> {
    let tools = check_tools(remote_tools)?;
    // 사용자가 적은 경로가 없으면 그 경로를 알려 주고 거부(조용히 빼면 그 도구가 막힌 줄 모른다)
    if let Some(missing) = tools.iter().find(|t| !std::path::Path::new(t.as_str()).is_file()) {
        return Err(format!("원격 도구 경로가 없습니다: {missing}"));
    }
    Ok(policy::emergency::Input {
        own_images: own_images(),
        remote_tools: tools,
        rdp_clients: rdp_clients(&world.host.rdp_sessions()),
        dns_service: world.host.service_sid_usable("Dnscache").then(|| "Dnscache".to_string()),
        dhcp_service: world.host.service_sid_usable("Dhcp").then(|| "Dhcp".to_string()),
    })
}

/// 지금(최근 10분 통신 기록) 돌고 있는 원격 도구의 (표시 이름, 실행 파일 경로). 긴급 차단 대화상자가 예외 칸을
/// 미리 채운다(사용자 승인 2026-11-08 "자동 채우기"). 시스템 핵심 프로세스·없는 파일은 뺀다(RDP 는 세션 IP 로 따로 연다)
pub fn suggested_tools(world: &World) -> Vec<(String, String)> {
    let since = crate::runtime::unix_to_filetime(world.engine_wall() - 600);
    let Ok(found) = graph::remote::running_tools(&world.graph, since) else {
        return Vec::new();
    };
    let mut out: Vec<(String, String)> = Vec::new();
    for (_, node, key) in found {
        let Ok(n) = world.graph.node(node) else { continue };
        let Some(img) = n.attr("image").and_then(|v| v.as_str().map(|s| s.to_string())) else { continue };
        if key == "rdp" || dsl::validate::is_system_image(&img) || !std::path::Path::new(&img).is_file() {
            continue;
        }
        if out.iter().any(|(_, p)| p.eq_ignore_ascii_case(&img)) {
            continue;
        }
        out.push((graph::remote::display_of(key).to_string(), img));
        if out.len() >= 8 {
            break;
        }
    }
    out
}

/// 상태 JSON: { active, policy_id, version, expires_at, remaining_secs, confirmed, suggested_tools }
pub fn status(world: &World) -> serde_json::Value {
    let mut v = status_core(world);
    if v["active"] == serde_json::json!(false) {
        v["suggested_tools"] = serde_json::json!(suggested_tools(world)
            .into_iter()
            .map(|(d, p)| serde_json::json!({"display": d, "path": p}))
            .collect::<Vec<_>>());
    }
    v
}

fn status_core(world: &World) -> serde_json::Value {
    match world.engine.emergency_status() {
        Ok(Some((id, ver, exp, st))) => {
            let now = world.engine_wall();
            serde_json::json!({
                "active": true,
                "policy_id": id,
                "version": ver,
                "expires_at": exp,
                "remaining_secs": (exp - now).max(0),
                "confirmed": st == engine::State::Confirmed,
            })
        }
        _ => serde_json::json!({ "active": false }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdp_client_ips_are_parsed_from_wts_names() {
        let s = vec![
            (2, "203.0.113.7\u{1f}LAPTOP".to_string()),
            (3, "\u{1f}NOADDR".to_string()),
            (4, "0.0.0.0\u{1f}X".to_string()),
            (5, "2001:db8::5\u{1f}Y".to_string()),
            (6, "203.0.113.7\u{1f}SAME".to_string()),
        ];
        let v = rdp_clients(&s);
        assert_eq!(v, vec!["203.0.113.7".parse::<IpAddr>().unwrap(), "2001:db8::5".parse().unwrap()]);
    }

    #[test]
    fn system_images_are_not_allowed_as_remote_tools() {
        assert!(check_tools(&[r"C:\Windows\System32\svchost.exe".into()]).is_err());
        assert_eq!(
            check_tools(&[r"C:\Program Files\TeamViewer\TeamViewer.exe".into(), " ".into()]).unwrap(),
            vec![r"C:\Program Files\TeamViewer\TeamViewer.exe".to_string()]
        );
    }
}
