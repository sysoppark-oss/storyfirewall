//! 프로세스 명령줄 (이야기형 10판 5-9 (1), MITRE ATT&CK T1490)
//!
//! Kernel-Process 시작 이벤트(1)에는 명령줄이 없다(poc3 스키마 기록으로 확인: ProcessID·ParentProcessID·
//! ImageName·CreateTime·토큰·패키지 필드뿐).
//! - 1순위: 시스템 커널 공급자(EVENT_TRACE_FLAG_PROCESS) Process Start 의 CommandLine — 이벤트 안에 있어 경쟁이 없다.
//!   별도 커널 세션(Win8+ 시스템 로거 모드, 이름 있는 세션 — NT Kernel Logger 를 차지하지 않음).
//!   이 이벤트에는 CreateTime 이 없고 두 세션의 도착 순서도 정해지지 않아, PID 로 만나(Rendezvous) Kernel-Process 쪽
//!   생성 시각을 붙인다(같은 프로세스 노드에 붙게).
//! - 대비: 커널 세션을 못 열면 시작 이벤트를 받은 즉시 그 프로세스를 열어
//!   NtQueryInformationProcess(ProcessCommandLineInformation = 60, Windows 8.1+)로 읽는다.
//!   poc3 run-80·84 실측: 짧은 vssadmin·bcdedit 2건 모두 열기 실패, 오류 87(이미 끝남). 커널 세션은 2/2(run-84·89).
//! - 29차 Q1(이름 바꾼 복사본): 도구 판별은 파일 이름 **또는** 버전 리소스의 OriginalFileName(서명 범위 안 — 바꾸면 서명이 깨짐).
//!   커널 이벤트에는 짧은 이름(바뀐 이름)만 있으므로, 커널 쪽은 모든 프로세스의 명령줄을 **메모리에만 10초**(상한 RV_CAP) 들고
//!   Kernel-Process 시작(전체 경로)에서 도구로 판별된 것만 내보낸다. 나머지는 버려지고 DB 에 남지 않는다.
//!
//! - **복구 수단을 다루는 도구만** 읽는다(T1490_TOOLS). 명령줄에는 암호·토큰이 들어갈 수 있어(예: 스크립트 인자)
//!   모든 프로세스의 명령줄을 DB 에 남기지 않는다.
//! - PID 재사용 대비: 연 프로세스의 생성 시각(GetProcessTimes)이 이벤트의 CreateTime 과 같을 때만 쓴다.
//! - 한계: ETW 는 사후 통지라 아주 짧게 사는 프로세스는 읽기 전에 끝날 수 있다(누락 — Sysmon 정답지로 잰다).
//!   보호 프로세스는 열리지 않는다(이 도구들은 보호 프로세스가 아니다).

use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, UNICODE_STRING};
use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

/// 명령줄을 읽는 실행 파일 이름(소문자). judge::rules::t1490_kind 가 판별하는 도구와 같아야 한다(시험 cmdline_tools_match_judge)
pub const T1490_TOOLS: &[&str] = &["vssadmin.exe", "wmic.exe", "diskshadow.exe", "wbadmin.exe", "bcdedit.exe", "reagentc.exe"];

/// 이 이미지의 명령줄을 읽어야 하는가(파일 이름만 본다 — 위치는 판정이 실행 파일 서명·경로로 따로 본다)
pub fn wanted(image: &str) -> bool {
    let name = image.rsplit(['\\', '/']).next().unwrap_or(image).to_ascii_lowercase();
    T1490_TOOLS.contains(&name.as_str())
}

/// 버전 리소스 이름 → 비교용(소문자, ".mui" 꼬리 제거 — Windows 파일은 "VSSADMIN.EXE.MUI" 처럼 올 수 있다)
pub fn norm_original(name: &str) -> String {
    let n = name.trim().to_ascii_lowercase();
    n.strip_suffix(".mui").map(|x| x.to_string()).unwrap_or(n)
}

/// 도구 판별: (파일 이름이 도구) → Some(None), (이름은 다르지만 OriginalFileName 이 도구) → Some(Some(원래 이름)), 아니면 None.
/// OriginalFileName 은 (경로, 크기, 수정 시각)으로 캐시한다 — 같은 경로를 다른 파일로 바꿔치기해도 다시 읽는다
pub fn tool_of(image: &str, cache: &mut std::collections::HashMap<(String, u64, i64), Option<String>>) -> Option<Option<String>> {
    if wanted(image) {
        return Some(None);
    }
    let (size, mtime) = file_stamp(image)?;
    let key = (image.to_ascii_lowercase(), size, mtime);
    if cache.len() > 4096 {
        cache.clear();
    }
    let orig = cache.entry(key).or_insert_with(|| original_file_name(image).map(|n| norm_original(&n))).clone();
    orig.filter(|o| T1490_TOOLS.contains(&o.as_str())).map(Some)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// (크기, 마지막 쓰기 FILETIME)
fn file_stamp(path: &str) -> Option<(u64, i64)> {
    use windows_sys::Win32::Storage::FileSystem::{GetFileAttributesExW, GetFileExInfoStandard, WIN32_FILE_ATTRIBUTE_DATA};
    let w = wide(path);
    let mut d: WIN32_FILE_ATTRIBUTE_DATA = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileAttributesExW(w.as_ptr(), GetFileExInfoStandard, &mut d as *mut _ as *mut _) } != 0;
    ok.then(|| {
        let size = ((d.nFileSizeHigh as u64) << 32) | d.nFileSizeLow as u64;
        let mt = ((d.ftLastWriteTime.dwHighDateTime as i64) << 32) | d.ftLastWriteTime.dwLowDateTime as i64;
        (size, mt)
    })
}

/// 버전 리소스 StringFileInfo 의 OriginalFileName(첫 번역). 없으면 None
pub fn original_file_name(path: &str) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
    let w = wide(path);
    let mut handle = 0u32;
    let size = unsafe { GetFileVersionInfoSizeW(w.as_ptr(), &mut handle) };
    if size == 0 || size > 4 * 1024 * 1024 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoW(w.as_ptr(), 0, size, buf.as_mut_ptr() as *mut _) } == 0 {
        return None;
    }
    // 번역 표: (언어, 코드페이지) 쌍
    let mut p: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut len = 0u32;
    let tq = wide("\\VarFileInfo\\Translation");
    if unsafe { VerQueryValueW(buf.as_ptr() as *const _, tq.as_ptr(), &mut p, &mut len) } == 0 || len < 4 || p.is_null() {
        return None;
    }
    let lang = unsafe { *(p as *const u16) };
    let cp = unsafe { *(p as *const u16).add(1) };
    let q = wide(&format!("\\StringFileInfo\\{lang:04x}{cp:04x}\\OriginalFileName"));
    let mut v: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut vlen = 0u32;
    if unsafe { VerQueryValueW(buf.as_ptr() as *const _, q.as_ptr(), &mut v, &mut vlen) } == 0 || v.is_null() || vlen == 0 {
        return None;
    }
    // 버퍼 안을 가리키는지 확인하고 읽는다(vlen = 글자 수, 끝 NUL 포함일 수 있음)
    let base = buf.as_ptr() as usize;
    let start = v as usize;
    let n = vlen as usize;
    if start < base || start + n * 2 > base + buf.len() {
        return None;
    }
    let ws = unsafe { std::slice::from_raw_parts(v as *const u16, n) };
    let end = ws.iter().position(|c| *c == 0).unwrap_or(n);
    Some(String::from_utf16_lossy(&ws[..end]))
}

/// 결과: Ok(명령줄) / Err(사유 — 진단 카운터 이름)
pub fn read(pid: u32, create_time: Option<i64>) -> Result<String, &'static str> {
    // SAFETY: 핸들은 아래에서 닫는다. 실패 시 null
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        // 87 ERROR_INVALID_PARAMETER = 그 PID 의 프로세스가 없음(이미 끝남), 5 = 접근 거부
        return Err(match unsafe { windows_sys::Win32::Foundation::GetLastError() } {
            87 => "cmdline_open_failed_gone",
            5 => "cmdline_open_failed_denied",
            _ => "cmdline_open_failed_other",
        });
    }
    let out = (|| {
        if let Some(ct) = create_time {
            let (mut c, mut e, mut k, mut u): (FILETIME, FILETIME, FILETIME, FILETIME) = unsafe { std::mem::zeroed() };
            if unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) } == 0 {
                return Err("cmdline_times_failed");
            }
            let got = ((c.dwHighDateTime as i64) << 32) | c.dwLowDateTime as i64;
            if got != ct {
                return Err("cmdline_pid_reused");
            }
        }
        // 첫 호출로 필요한 크기를 받는다(STATUS_INFO_LENGTH_MISMATCH). 상한 64KB(UNICODE_STRING 최대 길이)
        let mut need = 0u32;
        unsafe { NtQueryInformationProcess(h, ProcessCommandLineInformation, std::ptr::null_mut(), 0, &mut need) };
        let size = (need as usize).clamp(std::mem::size_of::<UNICODE_STRING>(), 70_000);
        // UNICODE_STRING 정렬을 맞추려고 u64 버퍼
        let mut buf = vec![0u64; size.div_ceil(8)];
        let st = unsafe {
            NtQueryInformationProcess(h, ProcessCommandLineInformation, buf.as_mut_ptr() as *mut _, (buf.len() * 8) as u32, &mut need)
        };
        if st < 0 {
            return Err("cmdline_query_failed");
        }
        let us = unsafe { &*(buf.as_ptr() as *const UNICODE_STRING) };
        if us.Buffer.is_null() || us.Length == 0 {
            return Err("cmdline_empty");
        }
        // 버퍼는 우리 할당 안(UNICODE_STRING 바로 뒤)을 가리킨다 — 범위를 확인하고 읽는다
        let base = buf.as_ptr() as usize;
        let end = base + buf.len() * 8;
        let p = us.Buffer as usize;
        let len = us.Length as usize;
        if p < base || p + len > end || !len.is_multiple_of(2) {
            return Err("cmdline_bad_buffer");
        }
        let w = unsafe { std::slice::from_raw_parts(us.Buffer, len / 2) };
        Ok(String::from_utf16_lossy(w))
    })();
    unsafe { CloseHandle(h) };
    out
}

/// 두 세션의 만남 장소. 늦게 온 쪽이 꺼내 간다. 오래된 것(10초)은 버린다.
/// 커널 쪽 명령줄은 모든 프로세스 것(이름 바꾼 복사본을 위해)이지만 메모리에만 있고, 도구로 판별된 것만 나간다
#[derive(Default)]
pub struct Rendezvous {
    /// 커널 쪽이 먼저: pid → (이벤트 시각, 명령줄)
    cmds: std::collections::HashMap<u32, (i64, String)>,
    /// Kernel-Process 쪽(도구로 판별됨)이 먼저: pid → (이벤트 시각, 생성 시각, 원래 도구 이름)
    starts: std::collections::HashMap<u32, (i64, Option<i64>, Option<String>)>,
    /// 29차 Q3: 도구로 판별된 시작인데 10초 안에 커널 명령줄이 오지 않아 버린 수(진단 "짝 못 지음")
    pub unmatched: u64,
}

/// 100ns 단위 10초
const RV_TTL: i64 = 10 * 10_000_000;
/// 기다리는 명령줄 상한(프로세스가 쏟아질 때 메모리 상한). 넘으면 가장 오래된 것부터 버린다
pub const RV_CAP: usize = 4096;

impl Rendezvous {
    fn prune(&mut self, now: i64) {
        self.cmds.retain(|_, (t, _)| now - *t < RV_TTL);
        let before = self.starts.len();
        self.starts.retain(|_, (t, _, _)| now - *t < RV_TTL);
        self.unmatched += (before - self.starts.len()) as u64;
        if self.cmds.len() > RV_CAP {
            let mut v: Vec<(u32, i64)> = self.cmds.iter().map(|(p, (t, _))| (*p, *t)).collect();
            v.sort_by_key(|x| x.1);
            for (p, _) in v.into_iter().take(self.cmds.len() - RV_CAP) {
                self.cmds.remove(&p);
            }
        }
    }
    /// 도구로 판별된 Kernel-Process 시작: 기다리던 명령줄이 있으면 돌려주고, 없으면 시작을 남긴다
    pub fn on_start(&mut self, pid: u32, ts: i64, create_time: Option<i64>, tool: Option<String>) -> Option<String> {
        self.prune(ts);
        if let Some((_, c)) = self.cmds.remove(&pid) {
            return Some(c);
        }
        self.starts.insert(pid, (ts, create_time, tool));
        None
    }
    /// 도구가 아닌 프로세스의 시작: 기다리던 명령줄을 버린다
    pub fn discard(&mut self, pid: u32) {
        self.cmds.remove(&pid);
    }
    /// 커널 Process Start 의 명령줄: 기다리던 시작이 있으면 (생성 시각, 원래 도구 이름)을 돌려주고, 없으면 명령줄을 남긴다
    pub fn on_cmd(&mut self, pid: u32, ts: i64, cmdline: String) -> Option<(Option<i64>, Option<String>)> {
        self.prune(ts);
        if let Some((_, ct, tool)) = self.starts.remove(&pid) {
            return Some((ct, tool));
        }
        self.cmds.insert(pid, (ts, cmdline));
        None
    }
    /// 대비 경로(직접 읽기)로 이미 보냈으면 기다리던 시작을 지운다(커널 쪽이 나중에 와도 두 번 보내지 않게)
    pub fn done(&mut self, pid: u32) {
        self.starts.remove(&pid);
    }
}

#[cfg(test)]
mod tests {
    use super::{norm_original, Rendezvous, RV_CAP};

    #[test]
    fn rendezvous_either_order_and_ttl() {
        let mut r = Rendezvous::default();
        // 시작이 먼저
        assert_eq!(r.on_start(10, 0, Some(5), None), None);
        assert_eq!(r.on_cmd(10, 1, "vssadmin delete shadows".into()), Some((Some(5), None)));
        // 명령줄이 먼저
        assert_eq!(r.on_cmd(11, 2, "bcdedit /enum".into()), None);
        assert_eq!(r.on_start(11, 3, Some(7), None).as_deref(), Some("bcdedit /enum"));
        // 10초 넘게 지난 것은 짝짓지 않는다(PID 재사용)
        assert_eq!(r.on_cmd(12, 0, "x".into()), None);
        assert_eq!(r.on_start(12, 11 * 10_000_000, Some(9), None), None);
        // 10·11 은 짝지어졌고, 12 의 시작은 아직 기다리는 중 — 21초에 버려지며 센다
        assert_eq!(r.unmatched, 0);
        // 도구가 아닌 프로세스의 명령줄은 버린다
        assert_eq!(r.on_cmd(13, 20 * 10_000_000, "notepad secret.txt".into()), None);
        r.discard(13);
        assert_eq!(r.on_start(13, 20 * 10_000_000, Some(1), None), None);
        // 이름 바꾼 복사본: 원래 이름이 실려 나온다
        assert_eq!(r.on_start(14, 21 * 10_000_000, Some(2), Some("vssadmin.exe".into())), None);
        assert_eq!(r.on_cmd(14, 21 * 10_000_000, "x.exe delete shadows".into()), Some((Some(2), Some("vssadmin.exe".into()))));
        assert!(r.unmatched >= 1, "짝 못 지은 시작(12) 이 세어짐");
    }

    #[test]
    fn rendezvous_memory_cap() {
        let mut r = Rendezvous::default();
        for p in 0..(RV_CAP as u32 + 100) {
            r.on_cmd(p, p as i64, format!("c{p}"));
        }
        r.on_cmd(999_999, RV_CAP as i64 + 100, "last".into());
        assert!(r.cmds.len() <= RV_CAP + 1);
        assert!(r.cmds.contains_key(&999_999));
    }

    #[test]
    fn original_name_normalized() {
        assert_eq!(norm_original("VSSADMIN.EXE.MUI"), "vssadmin.exe");
        assert_eq!(norm_original(" bcdedit.exe "), "bcdedit.exe");
    }
}
