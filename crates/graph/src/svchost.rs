//! svchost 명령줄에서 서비스 이름(`-s <이름>`)만 꺼낸다.
//!
//! Windows 10 1703 뒤로 메모리가 넉넉한 PC 는 서비스마다 svchost 를 따로 띄우고(`svchost.exe -k <그룹> -p -s <서비스>`),
//! 트리거로 켜졌다 몇 초 만에 끝나는 서비스는 1초 SCM 폴링이 못 볼 수 있다. diag-146 실측: "고립 svchost" 높음 12건이 모두
//! 이렇게 끝난 svchost(서비스 목록 비어 있음, 부모 = services.exe)였고 접속지는 Microsoft 인증·업데이트 주소였다.
//! 명령줄 원문은 남기지 않는다 — 서비스 이름 하나만 돌려준다.

/// 서비스 이름으로 받아들이는 글자: 영문·숫자·`_`·`-`·`.`, 1~80자 (SCM 서비스 키 이름 범위 안에서 보수적으로)
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 80
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// 실행 파일이 `<시스템 폴더>\System32\svchost.exe` 인가 (대소문자 무시, `\\?\` 접두 허용).
/// SysWOW64·다른 폴더의 svchost 는 받아들이지 않는다 — 가짜 svchost 가 서비스 이름을 꾸며 넣는 길을 줄인다
pub fn is_system_svchost(image: &str) -> bool {
    let l = image.trim_start_matches(r"\\?\").to_ascii_lowercase();
    // 드라이브 문자 + :\windows\system32\svchost.exe
    l.len() == r"c:\windows\system32\svchost.exe".len()
        && l.as_bytes()[0].is_ascii_alphabetic()
        && l[1..] == *r":\windows\system32\svchost.exe"
}

/// 명령줄에서 `-s <서비스>` 값. 없거나 두 번 이상이거나 글자가 이상하면 None
pub fn service_arg(cmdline: &str) -> Option<String> {
    let mut toks = cmdline.split_whitespace();
    let mut found: Option<String> = None;
    while let Some(t) = toks.next() {
        if t.eq_ignore_ascii_case("-s") || t.eq_ignore_ascii_case("/s") {
            let v = toks.next()?.trim_matches('"');
            if found.is_some() || !valid_name(v) {
                return None;
            }
            found = Some(v.to_string());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_split_host_service_name() {
        assert_eq!(
            service_arg(r"C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s wlidsvc").as_deref(),
            Some("wlidsvc")
        );
        assert_eq!(
            service_arg(r#""C:\Windows\System32\svchost.exe" -k LocalSystemNetworkRestricted -p -S TokenBroker"#)
                .as_deref(),
            Some("TokenBroker")
        );
    }

    #[test]
    fn rejects_shared_host_and_odd_values() {
        // 공유 호스트(-s 없음): 어떤 서비스인지 명령줄로는 모른다
        assert_eq!(
            service_arg(r"C:\Windows\system32\svchost.exe -k netsvcs -p"),
            None
        );
        // 값 없음·이상한 글자·두 번
        assert_eq!(service_arg("svchost.exe -k x -s"), None);
        assert_eq!(service_arg("svchost.exe -k x -s a;b"), None);
        assert_eq!(service_arg("svchost.exe -s wuauserv -s evil"), None);
        assert_eq!(
            service_arg(&format!("svchost.exe -s {}", "a".repeat(81))),
            None
        );
    }

    #[test]
    fn only_system32_svchost() {
        assert!(is_system_svchost(r"C:\Windows\System32\svchost.exe"));
        assert!(is_system_svchost(r"\\?\D:\WINDOWS\system32\SVCHOST.EXE"));
        assert!(!is_system_svchost(r"C:\Windows\SysWOW64\svchost.exe"));
        assert!(!is_system_svchost(
            r"C:\Users\pjg\AppData\Local\Temp\svchost.exe"
        ));
        assert!(!is_system_svchost(r"C:\Windows\System32\svchost.exe.bak"));
    }
}
