//! 로컬 시각 (12차·13차: 스케줄·요일은 로컬 기준)

use windows_sys::Win32::System::Time::{
    GetDynamicTimeZoneInformation, DYNAMIC_TIME_ZONE_INFORMATION,
};

const TIME_ZONE_ID_INVALID: u32 = 0xFFFF_FFFF;
const TIME_ZONE_ID_DAYLIGHT: u32 = 2;

/// UTC 대비 분 단위 오프셋 (로컬 = UTC + offset). 서머타임 적용 중이면 DaylightBias 포함.
pub fn local_offset_minutes() -> i32 {
    let mut tz: DYNAMIC_TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
    let id = unsafe { GetDynamicTimeZoneInformation(&mut tz) };
    if id == TIME_ZONE_ID_INVALID {
        return 0;
    }
    // Bias 는 "UTC = 로컬 + Bias" (분). 한국 = -540
    let mut bias = tz.Bias;
    if id == TIME_ZONE_ID_DAYLIGHT {
        bias += tz.DaylightBias;
    } else {
        bias += tz.StandardBias;
    }
    -bias
}

/// engine::Clock 구현: wall 은 UTC unix 초, local 은 UTC + 시간대(스케줄용), mono 는 Instant
pub struct WinClock {
    start: std::time::Instant,
}
impl Default for WinClock {
    fn default() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }
}
impl engine::Clock for WinClock {
    fn wall(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
    fn local(&self) -> i64 {
        self.wall() + local_offset_minutes() as i64 * 60
    }
    fn mono(&self) -> i64 {
        self.start.elapsed().as_secs() as i64
    }
}
