//! 말씀 언어 설정(docs/proposals/word/README.md "언어 선택"). 모든 안디옥 프로그램이 같은 값을 읽는다.
//! 읽기: `HKCU\SOFTWARE\Antioch` → `HKLM\SOFTWARE\Antioch` 의 `WordLang`(고르는 순서는 화면이 정한다).
//! 쓰기: 설정에서 바꾸면 `HKCU` 에만(일반 권한). 값은 내장 언어 목록과 글자 비교만 한다 — 경로나 명령으로 쓰지 않는다.

/// 말씀 자료가 내장된 언어(화면 ui/src/word.ts 의 WORD_LANGS 와 같아야 한다 — 화면 시험이 이 줄을 읽어 견준다)
pub const WORD_LANGS: &[&str] = &["ko", "en"];

const KEY: &str = r"SOFTWARE\Antioch";
const VALUE: &str = "WordLang";

#[cfg(windows)]
mod win {
    use windows_sys::Win32::System::Registry::{RegGetValueW, RegSetKeyValueW, HKEY, REG_SZ, RRF_RT_REG_SZ};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// 글자열 값. 없거나 글자열이 아니거나 길면 None
    pub fn get(hive: HKEY, key: &str, value: &str) -> Option<String> {
        let (k, v) = (wide(key), wide(value));
        let mut buf = [0u16; 64];
        let mut cb = (buf.len() * 2) as u32;
        let r = unsafe { RegGetValueW(hive, k.as_ptr(), v.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr() as *mut _, &mut cb) };
        if r != 0 {
            return None;
        }
        let n = (cb as usize / 2).min(buf.len());
        let s = String::from_utf16(&buf[..n]).ok()?;
        let s = s.trim_end_matches('\0').to_string();
        (!s.is_empty()).then_some(s)
    }

    /// 글자열 값을 쓴다(열쇠가 없으면 만든다)
    pub fn set(hive: HKEY, key: &str, value: &str, data: &str) -> bool {
        let (k, v, d) = (wide(key), wide(value), wide(data));
        let r = unsafe { RegSetKeyValueW(hive, k.as_ptr(), v.as_ptr(), REG_SZ, d.as_ptr() as *const _, (d.len() * 2) as u32) };
        r == 0
    }
}

/// 저장된 말씀 언어 값들(받은 그대로 — 목록에 있는지는 화면이 본다). `{ "hkcu": "en" | null, "hklm": "ko" | null }`
#[tauri::command]
pub fn word_lang_get() -> serde_json::Value {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        serde_json::json!({ "hkcu": win::get(HKEY_CURRENT_USER, KEY, VALUE), "hklm": win::get(HKEY_LOCAL_MACHINE, KEY, VALUE) })
    }
    #[cfg(not(windows))]
    {
        let _ = (KEY, VALUE);
        serde_json::json!({ "hkcu": null, "hklm": null })
    }
}

/// 설정에서 고른 말씀 언어를 `HKCU` 에 쓴다. 내장 목록에 없는 값은 받지 않는다
#[tauri::command]
pub fn word_lang_set(lang: String) -> Result<(), String> {
    if !WORD_LANGS.contains(&lang.as_str()) {
        return Err("말씀 자료가 없는 언어입니다".into());
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Registry::HKEY_CURRENT_USER;
        if win::set(HKEY_CURRENT_USER, KEY, VALUE, &lang) {
            Ok(())
        } else {
            Err("언어 설정을 저장하지 못했습니다".into())
        }
    }
    #[cfg(not(windows))]
    {
        Err("이 운영체제에서는 저장할 수 없습니다".into())
    }
}
