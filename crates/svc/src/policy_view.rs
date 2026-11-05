//! 정책 목록의 사람 말 요약(디자인 D006-4). 판정·적용과 무관한 표시용이다.
//! 정책 YAML 은 사용자·이야기에서 온 문자열(경로)을 담는다 — 화면은 텍스트 노드로만 넣는다.

/// 경로를 "앞 30자 + … + 파일 이름"으로 줄인다. 짧으면 그대로
pub fn short_path(p: &str) -> String {
    let file = p.rsplit(['\\', '/']).next().unwrap_or(p);
    let dir_len = p.len().saturating_sub(file.len());
    if p.chars().count() <= 48 || dir_len == 0 {
        return p.to_string();
    }
    let head: String = p.chars().take(30).collect();
    format!("{head}…\\{file}")
}

fn proc_label(p: &str) -> String {
    let file = p.rsplit(['\\', '/']).next().unwrap_or(p);
    if file.len() == p.len() {
        return file.to_string();
    }
    let dir = &p[..p.len() - file.len()].trim_end_matches(['\\', '/']);
    format!("{file}({})", short_path(dir))
}

/// "payload.exe(C:\Users\…\Temp) 의 나가는 연결 차단" 같은 한 줄. 여러 정책이 든 문서는 첫 정책 + "외 N건"
pub fn summary(yaml: &str) -> String {
    let Ok(doc) = dsl::parse(yaml) else {
        return "요약할 수 없는 정책(원문은 고급 편집에서)".into();
    };
    let Some(p) = doc.policies.first() else {
        return "빈 정책".into();
    };
    let m = &p.matcher;
    let mut who: Vec<String> = m.process.iter().map(|x| proc_label(x)).collect();
    if let Some(d) = &m.descendants_of {
        who.push(format!("{} 와 그 자손", proc_label(d)));
    }
    let who = match who.len() {
        0 => "모든 프로그램".to_string(),
        1 => who.remove(0),
        n => format!("{} 외 {}개", who[0], n - 1),
    };
    let dir = match m.direction {
        Some(dsl::model::Direction::Out) => "나가는",
        Some(dsl::model::Direction::In) => "들어오는",
        _ => "모든",
    };
    let mut target = String::new();
    if !m.remote_ip.is_empty() {
        let ips = if m.remote_ip.len() == 1 {
            m.remote_ip[0].clone()
        } else {
            format!("{} 외 {}곳", m.remote_ip[0], m.remote_ip.len() - 1)
        };
        let port = m
            .remote_port
            .first()
            .map(|p| format!(":{p}"))
            .unwrap_or_default();
        target = format!("{ips}{port} 으로 가는 ");
    } else if let Some(port) = m.remote_port.first() {
        target = format!("{port}번 포트로 가는 ");
    }
    let act = match p.action {
        dsl::model::Action::Block => "차단",
        dsl::model::Action::Allow => "허용",
    };
    let more = if doc.policies.len() > 1 {
        format!(" 외 {}건", doc.policies.len() - 1)
    } else {
        String::new()
    };
    format!("{who} 의 {target}{dir} 연결 {act}{more}")
}

/// 첫 정책의 만료(문자열 그대로: ISO 시각 또는 기간)
pub fn expires(yaml: &str) -> Option<String> {
    dsl::parse(yaml).ok()?.policies.first()?.expires.clone()
}

/// 이야기에서 만든 정책(끊기): 이름이 "cut-<이름>-<사건 뿌리 id>"
pub fn story_root(name: &str) -> Option<i64> {
    let rest = name.strip_prefix("cut-")?;
    rest.rsplit('-').next()?.parse().ok()
}

/// 상태의 한국어(D006-4). Applied = 적용했지만 60초 확인을 기다리는 중(확인 없으면 서비스가 되돌림), Confirmed = 확인돼 유지 중
pub fn state_ko(st: &str) -> (&'static str, &'static str) {
    match st {
        "Confirmed" => ("적용 중", "확인을 마치고 Windows 에 걸려 있습니다."),
        "Applied" => (
            "확인 대기",
            "적용했고 60초 안에 확인을 기다립니다. 확인하지 않으면 자동으로 되돌립니다.",
        ),
        "Paused" => (
            "일시 중지",
            "Windows 에서 내려 두었습니다. 다시 켤 수 있습니다.",
        ),
        "Expired" => ("만료", "정한 기한이 지나 내려졌습니다."),
        "RolledBack" => ("되돌림", "이전 상태로 되돌렸습니다."),
        _ => ("알 수 없음", ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_reads_like_a_sentence() {
        let y = "- name: b\n  action: block\n  match:\n    direction: out\n    process: ['C:/Users/pjg/AppData/Local/Temp/payload.exe']\n";
        assert_eq!(
            summary(y),
            "payload.exe(C:/Users/pjg/AppData/Local/Temp) 의 나가는 연결 차단"
        );
        let y2 = "- name: d\n  action: block\n  match:\n    direction: out\n    remote_ip: ['203.0.113.9']\n    remote_port: [443]\n";
        assert_eq!(
            summary(y2),
            "모든 프로그램 의 203.0.113.9:443 으로 가는 나가는 연결 차단"
        );
        assert!(summary("::: not yaml").starts_with("요약할 수 없는"));
    }

    #[test]
    fn long_paths_are_shortened_and_cut_names_give_root() {
        let p = r"C:\Users\someone\AppData\Local\Packages\VeryLongVendorName\LocalCache\Temp\x.exe";
        let s = short_path(p);
        assert!(
            s.ends_with(r"…\x.exe") && s.chars().count() < p.chars().count(),
            "{s}"
        );
        assert_eq!(story_root("cut-payload.exe-42"), Some(42));
        assert_eq!(story_root("block-updater"), None);
        assert_eq!(state_ko("Confirmed").0, "적용 중");
        assert_eq!(state_ko("Applied").0, "확인 대기");
    }
}

/// D036: 주소 차단 필터의 주소 글자 — "203.0.113.9:8443/tcp", 범위면 "a–b", IPv6 접두는 "addr/len".
/// 화면은 텍스트 노드로만 넣는다(링크 아님)
pub fn address_text(s: &policy::spec::BlockSpec) -> String {
    let mut hosts: Vec<String> = s
        .remote_v4
        .iter()
        .map(|r| {
            if r.lo == r.hi {
                r.lo.to_string()
            } else {
                format!("{}–{}", r.lo, r.hi)
            }
        })
        .collect();
    hosts.extend(s.remote_v6.iter().map(|p| {
        if p.prefix == 128 {
            format!("[{}]", p.addr)
        } else {
            format!("{}/{}", p.addr, p.prefix)
        }
    }));
    let ports: Vec<String> = s
        .remote_ports
        .iter()
        .map(|p| {
            if p.lo == p.hi {
                p.lo.to_string()
            } else {
                format!("{}-{}", p.lo, p.hi)
            }
        })
        .collect();
    let proto = match s.protocols.as_slice() {
        [6] => "/tcp",
        [17] => "/udp",
        _ => "",
    };
    let host = if hosts.is_empty() {
        "모든 주소".to_string()
    } else {
        hosts.join(", ")
    };
    match ports.as_slice() {
        [] => format!("{host}{proto}"),
        [p] => format!("{host}:{p}{proto}"),
        ps => format!("{host}:{}{proto}", ps.join(",")),
    }
}

#[cfg(test)]
mod address_tests {
    use super::address_text;
    #[test]
    fn address_text_shows_host_port_proto() {
        let s: policy::spec::BlockSpec = serde_json::from_value(serde_json::json!({
            "name": "x (주소 차단)", "direction": "out",
            "remote_v4": [{"lo": "203.0.113.9", "hi": "203.0.113.9"}],
            "remote_ports": [{"lo": 8443, "hi": 8443}], "protocols": [6]
        }))
        .unwrap();
        assert_eq!(address_text(&s), "203.0.113.9:8443/tcp");
    }
}
