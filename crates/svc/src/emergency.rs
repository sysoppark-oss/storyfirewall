//! 긴급 차단 (대시보드 개편안 3판 1-1) — 서비스 쪽: 입력 모으기, 승인 창 요약, 시작·해제·상태.
//! 필터 모양은 `policy::emergency`, 기한·60초 확인·재부팅 해제는 `engine::Engine::apply_emergency`·`reconcile`.

use crate::runtime::World;
use std::net::IpAddr;

/// 이 앱 실행 파일: 서비스 자신 + 같은 폴더의 화면(UI)
pub fn own_images() -> Vec<String> {
    let mut v = Vec::new();
    if let Ok(me) = std::env::current_exe() {
        v.push(me.to_string_lossy().into_owned());
        if let Some(dir) = me.parent() {
            v.push(dir.join("story-firewall-ui.exe").to_string_lossy().into_owned());
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
    Ok(policy::emergency::Input {
        own_images: own_images(),
        remote_tools: check_tools(remote_tools)?,
        rdp_clients: rdp_clients(&world.host.rdp_sessions()),
    })
}

/// 상태 JSON: { active, policy_id, version, expires_at, remaining_secs, confirmed }
pub fn status(world: &World) -> serde_json::Value {
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
