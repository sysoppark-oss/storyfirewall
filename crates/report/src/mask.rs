//! 가리기(2.4): 내부 IP → 내부-N, MAC 뒤 3바이트, PC 이름·사용자 이름, 이 PC 의 공인 주소.
//! 바깥 목적지 주소·도메인은 가리지 않는다. 같은 주소는 보고서 안에서 같은 번호.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 이 PC 에서 가릴 이름들(부른 쪽이 OS 에 물어 채운다). 빈 값은 가리지 않는다
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Who {
    #[serde(default)]
    pub pc_name: String,
    /// 이 PC 의 사용자 이름들(로그온한 사용자, `C:\Users\<이름>` 폴더 이름)
    #[serde(default)]
    pub users: Vec<String>,
    /// 이 PC 의 공인 주소(알면)
    #[serde(default)]
    pub public_ips: Vec<String>,
}

pub struct Masker {
    who: Who,
    inner: HashMap<IpAddr, usize>,
}

fn is_inner_v4(a: Ipv4Addr) -> bool {
    // 사설 대역·링크 로컬·CGNAT(100.64/10). 루프백(127/8)은 PC 를 가리키지 않으므로 그대로 둔다
    a.is_private() || a.is_link_local() || (a.octets()[0] == 100 && (a.octets()[1] & 0xC0) == 64)
}
fn is_inner_v6(a: Ipv6Addr) -> bool {
    let s = a.segments()[0];
    (s & 0xFE00) == 0xFC00 || (s & 0xFFC0) == 0xFE80
}

/// IPv6 안에 든 IPv4: IPv4-mapped(::ffff:0:0/96), NAT64 잘 알려진 앞머리(64:ff9b::/96)
fn embedded_v4(a: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = a.segments();
    let mapped = s[..5] == [0, 0, 0, 0, 0] && s[5] == 0xFFFF;
    let nat64 = s[0] == 0x64 && s[1] == 0xFF9B && s[2..6] == [0, 0, 0, 0];
    (mapped || nat64)
        .then(|| Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8))
}

/// `\Users\<이름>\` · `/Users/<이름>/` 의 이름 자리를 가린다 — 이 PC 사용자 목록에 없는 이름, 8.3 짧은 이름(`LONGUS~1`)도 가려진다(53차 Q2).
/// 사용자 폴더가 아닌 것(Public·Default 등)은 그대로 둔다
fn mask_user_dirs(s: &str) -> String {
    const KEEP: &[&str] = &["public", "default", "default user", "all users", "사용자"];
    let lower = s.to_lowercase();
    // 소문자로 바꾸면 길이가 달라지는 글자가 있으면 자리 계산이 어긋난다 — 그때는 건드리지 않는다
    if lower.len() != s.len() {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut at = 0;
    while let Some(k) = ["\\users\\", "/users/"]
        .iter()
        .filter_map(|p| lower[at..].find(p).map(|i| (at + i, p.len())))
        .min()
    {
        let start = k.0 + k.1;
        let end = s[start..]
            .find(['\\', '/', '"', '\'', '<', '>', '|', '\n'])
            .map(|i| start + i)
            .unwrap_or(s.len());
        out.push_str(&s[at..start]);
        let name = &s[start..end];
        if name.is_empty() || KEEP.contains(&name.to_lowercase().as_str()) {
            out.push_str(name);
        } else {
            out.push_str("사용자");
        }
        at = end;
    }
    out.push_str(&s[at..]);
    out
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-'
}

impl Masker {
    pub fn new(who: Who) -> Self {
        Self {
            who,
            inner: HashMap::new(),
        }
    }

    fn inner_label(&mut self, ip: IpAddr) -> String {
        let n = self.inner.len() + 1;
        format!("내부-{}", *self.inner.entry(ip).or_insert(n))
    }

    /// 주소처럼 보이는 조각 하나(구분자로 자른 것)를 가린 글자. 가릴 것이 아니면 None
    fn token(&mut self, t: &str) -> Option<String> {
        // MAC: aa:bb:cc:dd:ee:ff 또는 aa-bb-cc-dd-ee-ff
        let sep = if t.contains(':') { ':' } else { '-' };
        let parts: Vec<&str> = t.split(sep).collect();
        if parts.len() == 6
            && parts
                .iter()
                .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return Some(format!(
                "{}{sep}{}{sep}{}{sep}**{sep}**{sep}**",
                parts[0], parts[1], parts[2]
            ));
        }
        // IPv6 는 구역 표시(%12)를 떼고 본다
        let bare = t.split('%').next().unwrap_or(t);
        let ip: IpAddr = bare.parse().ok()?;
        if self
            .who
            .public_ips
            .iter()
            .any(|p| p.parse::<IpAddr>().ok() == Some(ip))
        {
            return Some("내 공인 IP".into());
        }
        // IPv4 를 품은 IPv6(::ffff:a.b.c.d, NAT64 64:ff9b::/96)는 안의 IPv4 로 본다 — 같은 주소는 표기가 달라도 같은 번호(53차 Q2)
        let ip = match ip {
            IpAddr::V6(a) => match embedded_v4(a) {
                Some(v4) => IpAddr::V4(v4),
                None => ip,
            },
            v4 => v4,
        };
        if self
            .who
            .public_ips
            .iter()
            .any(|p| p.parse::<IpAddr>().ok() == Some(ip))
        {
            return Some("내 공인 IP".into());
        }
        let inner = match ip {
            IpAddr::V4(a) => is_inner_v4(a),
            IpAddr::V6(a) => is_inner_v6(a),
        };
        inner.then(|| self.inner_label(ip))
    }

    /// 글자 하나를 가린다
    pub fn text(&mut self, s: &str) -> String {
        // 1) 주소: 주소에 쓰이는 글자(16진수·점·쌍점·%·-)가 이어진 조각마다 본다. "ip:포트"는 포트를 떼고 다시 본다
        let mut out = String::with_capacity(s.len());
        let chars: Vec<char> = s.chars().collect();
        let addr_ch = |c: char| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '%' | '-');
        let mut i = 0;
        while i < chars.len() {
            if !addr_ch(chars[i]) || (i > 0 && chars[i - 1].is_alphanumeric()) {
                out.push(chars[i]);
                i += 1;
                continue;
            }
            let mut j = i;
            let mut zone = false;
            // 구역 표시(%) 뒤에는 글자도 온다(fe80::1%eth0)
            while j < chars.len()
                && (addr_ch(chars[j]) || (zone && chars[j].is_ascii_alphanumeric()))
            {
                zone |= chars[j] == '%';
                j += 1;
            }
            // 뒤에 글자가 바로 이어지면(낱말의 일부) 주소가 아니다
            let glued = j < chars.len() && chars[j].is_alphanumeric();
            let tok: String = chars[i..j].iter().collect();
            let trimmed = tok.trim_end_matches(['.', ':', '-']);
            let tail = &tok[trimmed.len()..];
            let masked = if glued {
                None
            } else if let Some(m) = self.token(trimmed) {
                Some(m)
            } else if let Some((host, port)) = trimmed.rsplit_once(':') {
                // IPv4:포트
                (host.contains('.') && port.chars().all(|c| c.is_ascii_digit()))
                    .then(|| self.token(host).map(|m| format!("{m}:{port}")))
                    .flatten()
            } else {
                None
            };
            match masked {
                Some(m) => {
                    out.push_str(&m);
                    out.push_str(tail);
                }
                None => out.push_str(&tok),
            }
            i = j;
        }
        // 2) 사용자 폴더 경로의 이름 자리
        out = mask_user_dirs(&out);
        // 3) 이름: 낱말 경계에서만(대소문자 무시). 긴 이름부터
        let mut names: Vec<(String, &str)> = self
            .who
            .users
            .iter()
            .filter(|u| u.chars().count() >= 2)
            .map(|u| (u.clone(), "사용자"))
            .collect();
        if self.who.pc_name.chars().count() >= 2 {
            names.push((self.who.pc_name.clone(), "PC-1"));
        }
        names.sort_by_key(|(n, _)| std::cmp::Reverse(n.chars().count()));
        for (name, label) in names {
            out = replace_word(&out, &name, label);
        }
        out
    }

    /// JSON 값 안의 모든 글자 값을 가린다(열쇠는 그대로)
    pub fn json(&mut self, v: &mut serde_json::Value) {
        match v {
            serde_json::Value::String(s) => *s = self.text(s),
            serde_json::Value::Array(a) => a.iter_mut().for_each(|x| self.json(x)),
            serde_json::Value::Object(o) => o.values_mut().for_each(|x| self.json(x)),
            _ => {}
        }
    }
}

/// `name` 이 낱말로 나온 곳을 `label` 로(대소문자 무시). 다른 낱말의 일부면 그대로 둔다
fn replace_word(s: &str, name: &str, label: &str) -> String {
    let hay: Vec<char> = s.chars().collect();
    let pat: Vec<char> = name.chars().collect();
    let eq = |a: char, b: char| a.to_lowercase().eq(b.to_lowercase());
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < hay.len() {
        let hit = i + pat.len() <= hay.len()
            && (0..pat.len()).all(|k| eq(hay[i + k], pat[k]))
            && (i == 0 || !is_word(hay[i - 1]))
            && (i + pat.len() == hay.len() || !is_word(hay[i + pat.len()]));
        if hit {
            out.push_str(label);
            i += pat.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who() -> Who {
        Who {
            pc_name: "DESKTOP-RBLMSDI".into(),
            users: vec!["pjg".into()],
            public_ips: vec!["203.0.113.77".into()],
        }
    }

    #[test]
    fn inner_addresses_get_stable_numbers_and_outer_stay() {
        let mut m = Masker::new(who());
        assert_eq!(
            m.text("192.168.219.105:51234 → 142.250.197.142:443"),
            "내부-1:51234 → 142.250.197.142:443"
        );
        assert_eq!(m.text("10.0.0.5 과 192.168.219.105"), "내부-2 과 내부-1");
        assert_eq!(
            m.text("fe80::1%12, fd00::5, 2001:4860:4860::8888"),
            "내부-3, 내부-4, 2001:4860:4860::8888"
        );
        assert_eq!(
            m.text("169.254.3.4 100.64.1.1 127.0.0.1 8.8.8.8."),
            "내부-5 내부-6 127.0.0.1 8.8.8.8."
        );
        assert_eq!(m.text("이 PC 203.0.113.77 에서"), "이 PC 내 공인 IP 에서");
    }

    #[test]
    fn mac_keeps_vendor_only() {
        let mut m = Masker::new(who());
        assert_eq!(m.text("aa:bb:cc:dd:ee:ff"), "aa:bb:cc:**:**:**");
        assert_eq!(m.text("AA-BB-CC-DD-EE-FF 장비"), "AA-BB-CC-**-**-** 장비");
    }

    #[test]
    fn names_only_as_whole_words() {
        let mut m = Masker::new(who());
        assert_eq!(
            m.text(r"C:\Users\pjg\AppData\Local\Temp\payload.exe"),
            r"C:\Users\사용자\AppData\Local\Temp\payload.exe"
        );
        assert_eq!(m.text(r"desktop-rblmsdi\PJG 로그온"), r"PC-1\사용자 로그온");
        // 다른 낱말의 일부는 건드리지 않는다
        assert_eq!(m.text("pjgtool.exe, mypjg"), "pjgtool.exe, mypjg");
    }

    #[test]
    fn ordinary_text_is_untouched() {
        let mut m = Masker::new(who());
        for s in [
            "svchost.exe 가 edge.microsoft.com 에 접속",
            "판 0.1.7-dev.468f50f, 오전 6:55, 11-14",
            "deadbeef cafe.exe 1.2.3 a-b",
            "",
        ] {
            assert_eq!(m.text(s), s);
        }
    }

    #[test]
    fn json_strings_are_masked() {
        let mut m = Masker::new(who());
        let mut v = serde_json::json!({ "ip": "192.168.0.2", "n": 3, "list": ["10.1.1.1", { "p": r"C:\Users\pjg\x" }] });
        m.json(&mut v);
        assert_eq!(
            v,
            serde_json::json!({ "ip": "내부-1", "n": 3, "list": ["내부-2", { "p": r"C:\Users\사용자\x" }] })
        );
    }
}

#[cfg(test)]
mod bypass_tests {
    use super::*;

    fn m(s: &str) -> String {
        let who = Who {
            pc_name: "DESKTOP-PJG".into(),
            users: vec!["pjg".into()],
            public_ips: vec!["203.0.113.50".into()],
        };
        Masker::new(who).text(s)
    }

    /// 53차 Q2: 표기를 바꿔도 내부 주소는 가려진다
    #[test]
    fn odd_address_forms_are_masked() {
        for s in [
            "::ffff:192.168.0.7",
            "[::ffff:192.168.0.7]:443",
            "::ffff:c0a8:7",
            "64:ff9b::c0a8:7",
            "fe80::1%12",
            "fe80::1%eth0",
            "[fe80::1%eth0]:80",
        ] {
            let o = m(s);
            assert!(o.contains("내부-1"), "{s} => {o}");
            assert!(
                !o.contains("192.168") && !o.contains("c0a8") && !o.contains("fe80"),
                "{s} => {o}"
            );
        }
        // 같은 주소는 표기가 달라도 같은 번호
        let who = Who::default();
        let mut k = Masker::new(who);
        assert_eq!(
            k.text("192.168.0.7 ::ffff:192.168.0.7 10.0.0.1"),
            "내부-1 내부-1 내부-2"
        );
        // 공인 주소를 품은 표기는 바깥 목적지라 그대로, 내 공인 주소는 가린다
        assert_eq!(m("::ffff:8.8.8.8"), "::ffff:8.8.8.8");
        assert_eq!(m("::ffff:203.0.113.50"), "내 공인 IP");
    }

    /// 53차 Q2: 사용자 폴더의 이름 자리는 목록에 없는 이름·짧은 이름도 가린다
    #[test]
    fn user_dir_segment_is_masked_whatever_the_name() {
        assert_eq!(
            m(r"C:\Users\LONGUS~1\AppData\a.exe"),
            r"C:\Users\사용자\AppData\a.exe"
        );
        assert_eq!(m(r"c:\users\Other Person\x"), r"c:\users\사용자\x");
        assert_eq!(
            m("C:/Users/kim/x 와 C:/Users/lee"),
            "C:/Users/사용자/x 와 C:/Users/사용자"
        );
        assert_eq!(m(r"C:\Users\Public\Desktop"), r"C:\Users\Public\Desktop");
        assert_eq!(m(r"C:\Users\"), r"C:\Users\");
        assert_eq!(m(r"\\DESKTOP-PJG\Users\pjg\a"), r"\\PC-1\Users\사용자\a");
    }
}
