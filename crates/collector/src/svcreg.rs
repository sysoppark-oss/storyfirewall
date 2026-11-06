//! 35차 Gemini Q3: 서비스 레지스트리 감시 — HKLM\SYSTEM\CurrentControlSet\Services 에 변경 알림(RegNotifyChangeKeyValue)을 걸고,
//! 알림이 오면 서비스 이름과 ImagePath 를 다시 읽어 비교한다. 새 이름 또는 ImagePath 가 바뀐 서비스를 "등록"으로 본다
//! (5초 목록 비교는 "만들고·시작하고·지우기"를 놓치고, 이름이 그대로인 ImagePath 바꿔치기는 못 본다).
//! 호출한 프로세스는 알려 주지 않는다 — 잇는 규칙은 graph::ledger::service_registered(관찰 대상 모두에 공동 추정).
//! 36차 Q3: ImagePath 만이 아니라 Parameters\ServiceDll(svchost 가 싣는 DLL)도 함께 비교한다 — 기존 svchost 서비스의
//! DLL 만 바꾸는 순서. 알림은 받자마자 다시 걸고 나서 읽는다(읽는 동안 생긴 변경도 다음 알림으로 잡힘).
//! 남는 틈: 다시 걸기 전 아주 짧은 사이에 만들고 지운 서비스(실행되지 않았다면 남는 것이 없고, 실행됐다면 프로세스
//! 시작·서비스 대조표로 보인다).
//! 드라이버 없음. 읽기만(KEY_READ | KEY_NOTIFY).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY,
    HKEY_LOCAL_MACHINE, KEY_NOTIFY, KEY_READ, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
    RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 하위 키의 문자열 값 하나(없으면 빈 문자열)
fn read_str(root: HKEY, sub: &str, value: &str) -> String {
    let mut buf = [0u16; 1024];
    let mut cb = (buf.len() * 2) as u32;
    let sub = wide(sub);
    let val = wide(value);
    // SAFETY: 출력 버퍼는 지역 배열
    let r = unsafe {
        RegGetValueW(
            root,
            sub.as_ptr(),
            val.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut _,
            &mut cb,
        )
    };
    if r == 0 {
        let k = (cb as usize / 2).saturating_sub(1).min(buf.len());
        String::from_utf16_lossy(&buf[..k])
    } else {
        String::new()
    }
}

/// 서비스 이름(레지스트리 그대로) → "ImagePath\u{1f}ServiceDll"(없는 값은 빈 문자열)
pub fn snapshot(root: HKEY) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut i = 0u32;
    loop {
        let mut name = [0u16; 260];
        let mut len = name.len() as u32;
        // SAFETY: 이름 버퍼와 길이는 지역 변수
        let r = unsafe {
            RegEnumKeyExW(
                root,
                i,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if r != 0 {
            break;
        }
        i += 1;
        let n = String::from_utf16_lossy(&name[..len as usize]);
        let image = read_str(root, &n, "ImagePath");
        let dll = read_str(root, &format!(r"{n}\Parameters"), "ServiceDll");
        let path = format!("{image}\u{1f}{dll}");
        out.insert(n, path);
        if out.len() > 8192 {
            break;
        }
    }
    out
}

/// 지난번과 지금 사이에 새로 생기거나 ImagePath·ServiceDll 이 바뀐 서비스 이름(순수 함수 — 시험 대상)
pub fn changed(prev: &HashMap<String, String>, cur: &HashMap<String, String>) -> Vec<String> {
    let mut v: Vec<String> = cur
        .iter()
        .filter(|(k, p)| match prev.get(*k) {
            None => true,
            Some(old) => !old.eq_ignore_ascii_case(p),
        })
        .map(|(k, _)| k.clone())
        .collect();
    v.sort();
    v
}

/// 감시 스레드 몸통. 바뀐 이름마다 `on_change(name)` 을 부른다. stop 이 서면 1초 안에 끝난다
pub fn watch(stop: Arc<AtomicBool>, mut on_change: impl FnMut(&str)) {
    let mut key: HKEY = std::ptr::null_mut();
    let sub = wide(SERVICES);
    // SAFETY: 출력 핸들은 지역 변수
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            sub.as_ptr(),
            0,
            KEY_READ | KEY_NOTIFY,
            &mut key,
        )
    } != 0
    {
        return;
    }
    // SAFETY: 이름 없는 자동 리셋 이벤트
    let ev = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
    if ev.is_null() {
        unsafe { RegCloseKey(key) };
        return;
    }
    let arm = || {
        // SAFETY: 열린 키·이벤트. 비동기 — 바뀌면 이벤트가 선다. 한 번 알리면 다시 걸어야 한다
        unsafe {
            RegNotifyChangeKeyValue(
                key,
                1,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                ev,
                1,
            )
        }
    };
    // 알림을 먼저 걸고 첫 사진을 찍는다(그 사이 변경도 알림으로 남는다)
    if arm() != 0 {
        unsafe {
            CloseHandle(ev);
            RegCloseKey(key);
        }
        return;
    }
    let mut prev = snapshot(key);
    while !stop.load(Ordering::Relaxed) {
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            // SAFETY: 이벤트 핸들
            if unsafe { WaitForSingleObject(ev, 1000) } == WAIT_OBJECT_0 {
                break;
            }
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
        // 36차 Q3: 읽기 전에 바로 다시 건다 — 기다리고 읽는 동안의 변경은 다음 알림이 된다
        if arm() != 0 {
            break;
        }
        // 한꺼번에 여러 값이 바뀌는 설치를 한 번에 읽게 잠깐 기다린다
        std::thread::sleep(std::time::Duration::from_millis(300));
        let cur = snapshot(key);
        for n in changed(&prev, &cur) {
            on_change(&n);
        }
        prev = cur;
    }
    // SAFETY: 위에서 연 핸들
    unsafe {
        CloseHandle(ev);
        RegCloseKey(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_names_and_image_path_swaps() {
        let mut a = HashMap::new();
        a.insert(
            "Fax".to_string(),
            r"%SystemRoot%\system32\fxssvc.exe".to_string(),
        );
        a.insert(
            "Spooler".to_string(),
            r"%SystemRoot%\System32\spoolsv.exe".to_string(),
        );
        let mut b = a.clone();
        b.insert("EvilSvc".to_string(), r"C:\p\x.exe".to_string());
        b.insert("Fax".to_string(), r"C:\p\fax.exe".to_string());
        // 대소문자만 다른 것은 바뀐 것으로 보지 않는다
        b.insert(
            "Spooler".to_string(),
            r"%SYSTEMROOT%\System32\spoolsv.exe".to_string(),
        );
        assert_eq!(
            changed(&a, &b),
            vec!["EvilSvc".to_string(), "Fax".to_string()]
        );
        // 36차 Q3: 같은 ImagePath 에 ServiceDll 만 바뀜
        let mut c = a.clone();
        c.insert(
            "Svc1".to_string(),
            "%SystemRoot%\\system32\\svchost.exe -k netsvcs\u{1f}C:\\Windows\\a.dll".to_string(),
        );
        let mut d = c.clone();
        d.insert(
            "Svc1".to_string(),
            "%SystemRoot%\\system32\\svchost.exe -k netsvcs\u{1f}C:\\p\\evil.dll".to_string(),
        );
        assert_eq!(changed(&c, &d), vec!["Svc1".to_string()]);
        // 지워진 것은 등록이 아니다
        b.remove("EvilSvc");
        assert_eq!(changed(&b, &a), vec!["Fax".to_string()]);
    }
}
