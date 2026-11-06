//! NT 경로(\Device\HarddiskVolumeN\…) ↔ Win32 경로(C:\…) 치환
//!
//! Kernel-Process·Kernel-File 은 NT 경로를, 스냅샷·WFP 는 Win32 경로를 준다 (명세 4판 2-1).
//! 저장은 Win32 경로로 통일한다.

use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;

/// 드라이브 문자 A: ~ Z: 의 장치 이름을 조회해 (NT 접두, "X:") 표를 만든다. 긴 접두가 먼저 오도록 정렬.
pub fn volume_table() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let wide: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = vec![0u16; 512];
        let n = unsafe { QueryDosDeviceW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 {
            continue;
        }
        // 결과는 NUL 로 끝나는 문자열 목록. 첫 항목만 쓴다.
        let first: Vec<u16> = buf.iter().copied().take_while(|c| *c != 0).collect();
        let nt = String::from_utf16_lossy(&first);
        if nt.starts_with("\\Device\\") {
            out.push((nt, drive));
        }
    }
    out.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    out
}

pub fn to_win32(volumes: &[(String, String)], path: &str) -> String {
    for (nt, drive) in volumes {
        if let Some(rest) = strip_prefix_ci(path, nt) {
            if rest.is_empty() || rest.starts_with('\\') {
                return long_path(&format!("{drive}{rest}"));
            }
        }
    }
    // \SystemRoot\… 는 Windows 디렉터리. 드라이브는 모르므로 C: 로 가정하지 않고 그대로 둔다.
    long_path(path)
}

/// 8.3 짧은 이름(RUNNER~1)을 긴 이름으로. Kernel-Process 는 실행한 그대로의 경로를 주고 Kernel-File 은
/// 긴 이름을 주므로(run-2 실측) 통일하지 않으면 같은 파일이 다른 노드가 된다. 파일이 없으면 그대로.
pub fn long_path(path: &str) -> String {
    if !path.contains('~') {
        return path.to_string();
    }
    // Linux 단위 테스트(host-check)에서는 Win32 를 호출하지 않는다
    #[cfg(not(windows))]
    {
        return path.to_string();
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::GetLongPathNameW;
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = vec![0u16; 1024];
        let n =
            unsafe { GetLongPathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n == 0 || n >= buf.len() {
            return path.to_string();
        }
        String::from_utf16_lossy(&buf[..n])
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maps_nt_volume_prefix() {
        let v = vec![
            ("\\Device\\HarddiskVolume3".to_string(), "C:".to_string()),
            ("\\Device\\HarddiskVolume30".to_string(), "D:".to_string()),
        ];
        let mut v = v;
        v.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        assert_eq!(
            to_win32(&v, "\\Device\\HarddiskVolume3\\Windows\\x.exe"),
            "C:\\Windows\\x.exe"
        );
        assert_eq!(
            to_win32(&v, "\\device\\harddiskvolume30\\a.exe"),
            "D:\\a.exe"
        );
        assert_eq!(
            to_win32(&v, "\\Device\\Mup\\srv\\s"),
            "\\Device\\Mup\\srv\\s"
        );
    }
}

/// 30차 Q3-b: 한 파일의 모든 하드링크 이름(Win32 경로). `path` 는 그중 하나(Win32).
/// FindFirstFileNameW 는 볼륨 루트 기준 경로(`\Users\…`)를 주므로 `path` 의 드라이브(`X:`)를 앞에 붙인다.
/// 실패하면(권한·이미 지워짐) 빈 목록 — 확인하지 못한 것은 사실로 남기지 않는다
pub fn hardlink_names(path: &str) -> Vec<String> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        FindClose, FindFirstFileNameW, FindNextFileNameW,
    };
    let drive: String = path.chars().take(2).collect();
    if drive.len() != 2 || !drive.ends_with(':') {
        return Vec::new();
    }
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut out = Vec::new();
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: 입력은 NUL 로 끝나는 UTF-16, 출력 버퍼와 길이를 넘긴다. 핸들은 아래에서 닫는다
    let h = unsafe { FindFirstFileNameW(wide.as_ptr(), 0, &mut len, buf.as_mut_ptr()) };
    if h == INVALID_HANDLE_VALUE {
        return out;
    }
    loop {
        let name = String::from_utf16_lossy(&buf[..buf.iter().position(|c| *c == 0).unwrap_or(0)]);
        if !name.is_empty() {
            out.push(format!("{drive}{name}"));
        }
        if out.len() >= 64 {
            break;
        }
        len = buf.len() as u32;
        // SAFETY: 같은 버퍼·길이, 유효한 찾기 핸들
        let ok = unsafe { FindNextFileNameW(h, &mut len, buf.as_mut_ptr()) };
        if ok == 0 {
            break;
        }
    }
    // SAFETY: FindFirstFileNameW 가 준 유효한 핸들
    unsafe { FindClose(h) };
    out
}
