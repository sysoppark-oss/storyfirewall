//! 부르는 쪽(화면의 Tauri 코어)이 쓰는 도우미: 이 PC 에서 가릴 이름 모으기, 파일을 한 번에 쓰기.
//! 대화상자·운영체제 호출은 여기 없다(Linux 에서 시험할 수 있게).
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::Who;

/// 공인 주소인가(사설·링크 로컬·CGNAT·루프백·미지정이 아닌 것)
pub fn is_public(a: IpAddr) -> bool {
    match a {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                || (o[0] == 100 && (o[1] & 0xC0) == 64))
        }
        IpAddr::V6(v) => {
            let s = v.segments()[0];
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s & 0xFE00) == 0xFC00
                || (s & 0xFFC0) == 0xFE80)
        }
    }
}

/// `C:\Users` 아래에서 사용자 이름이 아닌 폴더
const NOT_USERS: &[&str] = &[
    "public",
    "default",
    "default user",
    "all users",
    "defaultapppool",
];

/// 가릴 이름들. `pc`·`user` = 환경 변수 값, `profile_dirs` = 사용자 폴더들의 부모(`C:\Users`) 아래 폴더 이름,
/// `local_ips` = 이 PC 가 바깥으로 나갈 때 쓰는 주소(공인 주소가 PC 에 바로 붙은 경우만 가릴 대상이 된다).
/// 공유기 뒤의 공인 주소는 PC 가 알 수 없다 — 바깥에 묻지 않는다(2.3)
pub fn who_from(
    pc: Option<String>,
    user: Option<String>,
    profile_dirs: Vec<String>,
    local_ips: Vec<IpAddr>,
) -> Who {
    let mut users: Vec<String> = Vec::new();
    for n in user.into_iter().chain(profile_dirs) {
        let n = n.trim().to_string();
        if n.is_empty()
            || NOT_USERS.contains(&n.to_lowercase().as_str())
            || n.contains('.') && n.to_lowercase().ends_with(".ini")
        {
            continue;
        }
        if !users.iter().any(|u| u.eq_ignore_ascii_case(&n)) {
            users.push(n);
        }
    }
    Who {
        pc_name: pc.unwrap_or_default().trim().to_string(),
        users,
        public_ips: local_ips
            .into_iter()
            .filter(|a| is_public(*a))
            .map(|a| a.to_string())
            .collect(),
    }
}

/// 같은 폴더의 임시 이름에 다 쓴 뒤 이름을 바꾼다 — 쓰다 실패하거나 멈추면 반쪽 파일을 남기지 않는다(2.7).
/// `.html` 로 끝나지 않으면 붙인다. 돌려주는 값 = 실제로 쓴 경로
pub fn write_whole(path: &Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let mut path = path.to_path_buf();
    if !path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("html") || e.eq_ignore_ascii_case("htm"))
    {
        let mut s = path.into_os_string();
        s.push(".html");
        path = PathBuf::from(s);
    }
    let mut tmp = path.clone().into_os_string();
    tmp.push(format!(".{}.part", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let r = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &path)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r.map(|_| path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn who_keeps_users_once_and_only_public_addresses() {
        let w = who_from(
            Some(" DESKTOP-AB12 ".into()),
            Some("pjg".into()),
            vec![
                "PJG".into(),
                "Public".into(),
                "Default".into(),
                "desktop.ini".into(),
                "kim".into(),
            ],
            vec![
                "192.168.0.7".parse().unwrap(),
                "100.70.1.2".parse().unwrap(),
                "203.0.113.9".parse().unwrap(),
                "fe80::1".parse().unwrap(),
                "2001:db8::5".parse().unwrap(),
            ],
        );
        assert_eq!(w.pc_name, "DESKTOP-AB12");
        assert_eq!(w.users, vec!["pjg".to_string(), "kim".to_string()]);
        assert_eq!(
            w.public_ips,
            vec!["203.0.113.9".to_string(), "2001:db8::5".to_string()]
        );
    }

    #[test]
    fn write_whole_adds_extension_and_leaves_no_part_file() {
        let dir = std::env::temp_dir().join(format!("sf-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = write_whole(&dir.join("a"), b"<html>").unwrap();
        assert_eq!(p.file_name().unwrap(), "a.html");
        assert_eq!(std::fs::read(&p).unwrap(), b"<html>");
        // 덮어쓰기
        write_whole(&p, b"x").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"x");
        // 없는 폴더: 실패하고 아무것도 남기지 않는다
        assert!(write_whole(&dir.join("없는폴더").join("b.html"), b"x").is_err());
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left.len(), 1, "{left:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
