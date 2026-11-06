//! 시계: 단조 시계(타이머·백오프)와 벽시계(스케줄 경계·만료)를 분리한다 (10차 Q2).
//!
//! A22 정정(접점 결함): 예전에는 `wall()` 이 **로컬 시각의 unix 초**였다. 그 값이 그대로 UI 의 확인 시한·사건 시각으로 나가고,
//! svc 가 FILETIME(UTC, ETW·그래프)과 비교하는 데도 쓰였다. 러너는 UTC 라 드러나지 않았지만 한국(UTC+9) PC 에서는
//! 60초 확인 카운트다운이 9시간으로 보이고, 연결 목록 "최근 5분"이 미래 구간이 되어 비었을 것이다.
//! 이제 `wall()` 은 **UTC unix 초**(모든 기록·비교·UI), `local()` 은 스케줄의 요일·분 계산에만 쓴다.

use std::cell::Cell;

pub trait Clock {
    /// UTC unix 초 (기록·비교·UI 로 나가는 모든 시각)
    fn wall(&self) -> i64;
    /// 단조 초
    fn mono(&self) -> i64;
    /// 로컬 벽시각을 unix 초처럼 센 값 (= UTC + 시간대 오프셋). **스케줄의 요일·분 계산에만** 쓴다.
    fn local(&self) -> i64 {
        self.wall()
    }
}

/// 테스트용: 둘 다 마음대로 움직인다
pub struct FakeClock {
    pub wall: Cell<i64>,
    pub mono: Cell<i64>,
    /// 로컬 = UTC + offset (초)
    pub offset: Cell<i64>,
}
impl FakeClock {
    pub fn new(wall: i64) -> Self {
        Self {
            wall: Cell::new(wall),
            mono: Cell::new(0),
            offset: Cell::new(0),
        }
    }
    /// 시간대 오프셋 (예: 한국 9*3600)
    pub fn with_offset(wall: i64, offset: i64) -> Self {
        Self {
            wall: Cell::new(wall),
            mono: Cell::new(0),
            offset: Cell::new(offset),
        }
    }
    /// 둘 다 전진
    pub fn advance(&self, secs: i64) {
        self.wall.set(self.wall.get() + secs);
        self.mono.set(self.mono.get() + secs);
    }
    /// 벽시계만 뛴다 (사용자가 시각을 바꿈)
    pub fn jump_wall(&self, secs: i64) {
        self.wall.set(self.wall.get() + secs);
    }
}
impl Clock for FakeClock {
    fn wall(&self) -> i64 {
        self.wall.get()
    }
    fn mono(&self) -> i64 {
        self.mono.get()
    }
    fn local(&self) -> i64 {
        self.wall.get() + self.offset.get()
    }
}

/// 실제 시계 (Linux 개발용, 로컬 = UTC). Windows 는 svc::win::time::WinClock.
pub struct SystemClock {
    start: std::time::Instant,
}
impl Default for SystemClock {
    fn default() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }
}
impl Clock for SystemClock {
    fn wall(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
    fn mono(&self) -> i64 {
        self.start.elapsed().as_secs() as i64
    }
}
