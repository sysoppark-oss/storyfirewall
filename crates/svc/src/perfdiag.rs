//! 판정이 왜 느렸는지 가르는 진단 값(55차 Q7). 모두 읽기 전용 조회이며 실패하면 그 값만 빠진다.
//!
//! diag-253: 같은 입력에 판정 CPU 시간이 2.1초와 5.1초로 갈렸다. 후보를 가르는 세 가지:
//! - 커널 CPU 시간이 는다 → 파일 읽기 쪽(실시간 검사 드라이버, 페이지 폴트)
//! - 사용자 CPU 시간만 는다 + 효율 코어에서 돌았다 → 코어 배정(성능 코어/효율 코어)
//! - 페이지 폴트가 는다 → 메모리에서 밀려났다가 다시 읽어 옴

use std::time::Duration;

/// 지금 스레드의 (커널, 사용자) CPU 시간
#[cfg(windows)]
pub fn thread_cpu_split() -> Option<(Duration, Duration)> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, GetThreadTimes};
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: GetCurrentThread 는 닫을 필요 없는 가짜 핸들이고, 네 포인터는 모두 이 함수의 지역 변수를 가리킨다.
    let ok = unsafe {
        GetThreadTimes(
            GetCurrentThread(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    };
    if ok == 0 {
        return None;
    }
    // FILETIME 은 100ns 단위
    let d = |f: &FILETIME| {
        let ticks = ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64;
        Duration::from_nanos(ticks.saturating_mul(100))
    };
    Some((d(&kernel), d(&user)))
}

/// Linux(작업 환경·시험): /proc/thread-self/stat 의 utime(14번째)·stime(15번째), 단위는 1/100초로 본다.
#[cfg(not(windows))]
pub fn thread_cpu_split() -> Option<(Duration, Duration)> {
    let s = std::fs::read_to_string("/proc/thread-self/stat").ok()?;
    // 이름 칸에 공백·괄호가 있을 수 있어 마지막 ')' 뒤부터 센다
    let rest = &s[s.rfind(')')? + 1..];
    let mut it = rest.split_whitespace();
    let utime: u64 = it.nth(11)?.parse().ok()?;
    let stime: u64 = it.next()?.parse().ok()?;
    Some((
        Duration::from_millis(stime * 10),
        Duration::from_millis(utime * 10),
    ))
}

/// `GetSystemCpuSetInformation` 이 채운 바이트에서 (그룹, 논리 프로세서 번호, 효율 등급)을 꺼낸다.
/// 항목마다 길이(Size)가 앞에 있고 길이는 Windows 판에 따라 다를 수 있어, 구조체 크기가 아니라 Size 로 건너뛴다.
/// 칸 위치(문서의 SYSTEM_CPU_SET_INFORMATION): Size u32 @0, Type u32 @4, Group u16 @12, LogicalProcessorIndex u8 @14, EfficiencyClass u8 @18.
pub fn parse_cpu_sets(buf: &[u8]) -> Vec<(u16, u8, u8)> {
    const NEED: usize = 19;
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 8 <= buf.len() {
        let size = u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]) as usize;
        let kind = u32::from_le_bytes([buf[at + 4], buf[at + 5], buf[at + 6], buf[at + 7]]);
        // 길이가 말이 안 되면 멈춘다(끝없이 돌거나 버퍼 밖을 읽지 않게)
        if size < NEED || at + size > buf.len() {
            break;
        }
        // Type 0 = CpuSetInformation. 모르는 종류는 건너뛴다
        if kind == 0 {
            let group = u16::from_le_bytes([buf[at + 12], buf[at + 13]]);
            out.push((group, buf[at + 14], buf[at + 18]));
        }
        at += size;
    }
    out
}

/// 지금 이 스레드가 올라 있는 코어의 효율 등급과, 이 PC 에서 가장 높은 등급.
/// 등급이 높을수록 성능 코어다. 모든 코어가 같은 PC(구분 없음)에서는 둘 다 0.
#[cfg(windows)]
pub fn core_class_now() -> Option<(u8, u8)> {
    use std::sync::OnceLock;
    use windows_sys::Win32::System::Kernel::PROCESSOR_NUMBER;
    use windows_sys::Win32::System::SystemInformation::GetSystemCpuSetInformation;
    use windows_sys::Win32::System::Threading::GetCurrentProcessorNumberEx;
    // 코어 구성은 켜져 있는 동안 바뀌지 않는다고 보고 한 번만 읽는다
    static SETS: OnceLock<Vec<(u16, u8, u8)>> = OnceLock::new();
    let sets = SETS.get_or_init(|| {
        // u64 로 잡아 구조체 정렬을 맞춘다. 64 KiB = 논리 프로세서 2000개 분량
        let mut buf = vec![0u64; 8192];
        let bytes = (buf.len() * 8) as u32;
        let mut got = 0u32;
        // SAFETY: 버퍼 주소와 그 바이트 길이를 정확히 넘긴다. process 는 null(= 이 프로세스), flags 는 0 이어야 한다.
        let ok = unsafe {
            GetSystemCpuSetInformation(
                buf.as_mut_ptr().cast(),
                bytes,
                &mut got,
                std::ptr::null_mut(),
                0,
            )
        };
        if ok == 0 || got > bytes {
            return Vec::new();
        }
        // SAFETY: buf 는 bytes 바이트가 살아 있고 got <= bytes
        let raw = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), got as usize) };
        parse_cpu_sets(raw)
    });
    let max = sets.iter().map(|s| s.2).max()?;
    let mut pn = PROCESSOR_NUMBER {
        Group: 0,
        Number: 0,
        Reserved: 0,
    };
    // SAFETY: 지역 변수 하나를 채운다
    unsafe { GetCurrentProcessorNumberEx(&mut pn) };
    let class = sets.iter().find(|s| s.0 == pn.Group && s.1 == pn.Number)?.2;
    Some((class, max))
}

#[cfg(not(windows))]
pub fn core_class_now() -> Option<(u8, u8)> {
    None
}

/// 이 프로세스의 누적 페이지 폴트 수(32비트 — 넘치면 0 부터 다시 센다. 차이는 wrapping_sub 로)
#[cfg(windows)]
pub fn page_faults() -> Option<u32> {
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    // SAFETY: 0 으로 채워도 유효한 평범한 C 구조체
    let mut c: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    let cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    c.cb = cb;
    // SAFETY: GetCurrentProcess 는 닫을 필요 없는 가짜 핸들, 포인터와 길이는 위 지역 변수의 것
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, cb) };
    (ok != 0).then_some(c.PageFaultCount)
}

#[cfg(not(windows))]
pub fn page_faults() -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(size: u32, kind: u32, group: u16, lp: u8, class: u8) -> Vec<u8> {
        let mut v = vec![0u8; size as usize];
        v[0..4].copy_from_slice(&size.to_le_bytes());
        v[4..8].copy_from_slice(&kind.to_le_bytes());
        v[12..14].copy_from_slice(&group.to_le_bytes());
        v[14] = lp;
        v[18] = class;
        v
    }

    #[test]
    fn parse_cpu_sets_walks_by_size_and_skips_unknown() {
        let mut buf = entry(32, 0, 0, 0, 1);
        buf.extend(entry(40, 0, 0, 1, 0)); // 길이가 다른 항목(새 Windows 판)
        buf.extend(entry(32, 7, 0, 2, 1)); // 모르는 종류 — 건너뛴다
        buf.extend(entry(32, 0, 1, 3, 1)); // 두 번째 프로세서 그룹
        assert_eq!(parse_cpu_sets(&buf), vec![(0, 0, 1), (0, 1, 0), (1, 3, 1)]);
    }

    #[test]
    fn parse_cpu_sets_stops_on_bad_length() {
        // 길이 0(끝없이 돌 수 있음), 버퍼를 넘는 길이, 잘린 머리 — 모두 읽은 데까지만 돌려준다
        let mut zero = entry(32, 0, 0, 0, 1);
        zero.extend([0u8; 32]);
        assert_eq!(parse_cpu_sets(&zero), vec![(0, 0, 1)]);
        let mut over = entry(32, 0, 0, 0, 1);
        over.extend(entry(32, 0, 0, 1, 1));
        let n = over.len();
        over[32..36].copy_from_slice(&64u32.to_le_bytes());
        assert_eq!(parse_cpu_sets(&over[..n]), vec![(0, 0, 1)]);
        assert_eq!(parse_cpu_sets(&[1, 2, 3]), vec![]);
        assert_eq!(parse_cpu_sets(&[]), vec![]);
    }

    #[test]
    fn thread_cpu_split_reads_both_parts() {
        let Some((k0, u0)) = thread_cpu_split() else {
            return;
        };
        let mut x = 0u64;
        let t = std::time::Instant::now();
        while t.elapsed() < Duration::from_millis(80) {
            x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(7));
        }
        let (k1, u1) = thread_cpu_split().unwrap();
        // 계산만 했으니 는 것은 사용자 시간이다
        assert!(
            u1 >= u0 + Duration::from_millis(20),
            "사용자 시간: {:?}",
            u1 - u0
        );
        assert!(k1 >= k0);
    }
}
