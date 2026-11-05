//! ETW 콜백과 폴링 스레드가 공유하는 상태

use graph::event::{Event, EventKind};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Mutex;

use crate::filering::FileRing;
use crate::origin::OriginJob;
use std::time::{Duration, Instant};

/// 용량 집계 키. 연결 하나 = (pid, 프로토콜, 원격 ip, 원격 포트). 명세 4판 2-2: 용량 이벤트는
/// 채널로 보내지 않고 여기 누적만 한다.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub pid: u32,
    pub proto: &'static str,
    pub raddr: String,
    pub rport: u16,
}

#[derive(Default, Clone, Copy, Debug)]
pub struct Bytes {
    pub sent: u64,
    pub recv: u64,
}

/// PID 당 초당 허용 이벤트 (연결·DNS·파일). 넘치면 버린다. 실기기 B10 에서 조정.
pub const PER_PID_PER_SEC: u32 = 2_000;

fn rate_limited_pid(ev: &Event) -> Option<u32> {
    match &ev.kind {
        EventKind::Connect { proc, .. }
        | EventKind::DnsQuery { proc, .. }
        | EventKind::FileWrite { proc, .. }
        | EventKind::FileOpen { proc, .. } => Some(proc.pid),
        _ => None,
    }
}

pub struct Ctx {
    pub tx: SyncSender<Event>,
    /// PID 별 (초, 그 초의 건수)
    pub rate: Mutex<HashMap<u32, (i64, u32)>>,
    /// 상한을 넘겨 버린 이벤트 수
    pub rate_limited: AtomicU64,
    /// 채널이 꽉 차서 버린 이벤트 수 (목표 0)
    pub dropped: AtomicU64,
    /// 필드가 없어 버린 이벤트 수 (OS 빌드별 스키마 차이 감지)
    pub missing_fields: AtomicU64,
    /// 콜백에 들어온 이벤트 총수 (공급자별)
    pub counts: Mutex<HashMap<&'static str, u64>>,
    /// 연결별 송수신 바이트 (아직 flush 안 된 증분)
    pub bytes: Mutex<HashMap<ConnKey, Bytes>>,
    /// (공급자, 이벤트 id) 별 첫 이벤트의 스키마 JSON. meta 에 기록 (명세 4판 2-2)
    pub schema_notes: Mutex<HashMap<(String, u16), String>>,
    /// 실험 공급자(P6) 이벤트 덤프: (공급자, id) 별 최대 N건
    pub exp_dumps: Mutex<Vec<String>>,
    /// 실험 공급자 (공급자, id) 별 받은 수 (덤프 상한용)
    pub exp_counts: Mutex<HashMap<(String, u16), usize>>,
    /// ETW 가 본 아웃바운드 연결 (pid, raddr, rport). 연결 테이블 폴링이 누락 대조에 쓴다
    pub seen_connects: Mutex<HashSet<(u32, String, u16)>>,
    /// 최근 UDP 송신 (pid, raddr, rport) → 마지막 시각. 같은 목적지 1초 안 반복은 Connect 로 안 보냄
    pub recent_udp: Mutex<HashMap<(u32, String, u16), i64>>,
    /// 파일 생성·이름 변경 링 버퍼 (명세 4판 2-2)
    pub files: Mutex<FileRing>,
    /// ETW QPC 원시 시각 → 벽시계 변환 (qpc.rs, 23차 Q2)
    pub clock: Mutex<crate::qpc::QpcClock>,
    /// NT 경로 → Win32 경로 치환표 ("\Device\HarddiskVolume3" → "C:")
    pub volumes: Vec<(String, String)>,
    /// DNS 3020 에 ClientPID 가 없어 버린 수 (Windows 2022 빌드)
    pub skipped_no_client_pid: AtomicU64,
    /// Kernel-File 11 NameDelete: FileKey → (시각, 옛 경로). 2초 창 안에서만 RenamePath 와 짝짓는다
    pub deleted_names: Mutex<HashMap<u64, (i64, String)>>,
    /// rename 옛 경로를 어떤 방법으로 얻었는지 집계 ("filekey" / "guess")
    pub rename_methods: Mutex<HashMap<&'static str, u64>>,
    /// 진단: ProcessStart 에서 파일 사슬을 찾은 횟수, 새 프로세스 이미지 경로
    pub chains_found: AtomicU64,
    pub new_images: Mutex<Vec<String>>,
    /// 출신 성분 작업 큐 (MOTW 읽기·서명 검증), 저우선 스레드가 소비
    pub origin_tx: Mutex<Option<SyncSender<OriginJob>>>,
    /// 10판 5-9 (1): 커널 Process Start(명령줄) ↔ Kernel-Process 시작(생성 시각) 만남 장소
    pub cmd_rv: Mutex<crate::cmdline::Rendezvous>,
    /// 29차 Q1: (경로, 크기, 수정 시각) → OriginalFileName(정규화). 이름 바꾼 복구 도구 판별용
    pub orig_names: Mutex<HashMap<(String, u64, i64), Option<String>>>,
    /// CAPI2 정규화 건수
    pub capi2_chains: AtomicU64,
    pub capi2_fetches: AtomicU64,
    /// A20: 해시한 파일 수
    pub hashes: AtomicU64,
    /// 17판 23-2 ②: Kernel-File 열기(12) 받은 총수(부하 진단 — 대부분 거르기에서 버려진다)
    pub file_opens_seen: AtomicU64,
    /// 17판 23-2 ②: 최근 보낸 감시 경로 열기 (pid, 소문자 경로) → 시각. 60초 안 반복은 보내지 않는다
    pub recent_opens: Mutex<HashMap<(u32, String), i64>>,
}

impl Ctx {
    pub fn new(tx: SyncSender<Event>, volumes: Vec<(String, String)>) -> Self {
        Self {
            tx,
            rate: Mutex::new(HashMap::new()),
            rate_limited: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            missing_fields: AtomicU64::new(0),
            counts: Mutex::new(HashMap::new()),
            bytes: Mutex::new(HashMap::new()),
            schema_notes: Mutex::new(HashMap::new()),
            exp_dumps: Mutex::new(Vec::new()),
            exp_counts: Mutex::new(HashMap::new()),
            seen_connects: Mutex::new(HashSet::new()),
            recent_udp: Mutex::new(HashMap::new()),
            files: Mutex::new(FileRing::new(600 * 10_000_000)), // 10분
            clock: Mutex::new(crate::qpc::QpcClock::new(qpc_freq())),
            volumes,
            skipped_no_client_pid: AtomicU64::new(0),
            deleted_names: Mutex::new(HashMap::new()),
            rename_methods: Mutex::new(HashMap::new()),
            chains_found: AtomicU64::new(0),
            new_images: Mutex::new(Vec::new()),
            origin_tx: Mutex::new(None),
            cmd_rv: Mutex::new(crate::cmdline::Rendezvous::default()),
            orig_names: Mutex::new(HashMap::new()),
            capi2_chains: AtomicU64::new(0),
            capi2_fetches: AtomicU64::new(0),
            hashes: AtomicU64::new(0),
            file_opens_seen: AtomicU64::new(0),
            recent_opens: Mutex::new(HashMap::new()),
        }
    }

    /// 출신 성분 작업 등록. delay 뒤에 처리된다.
    pub fn enqueue_origin(&self, path: &str, delay: Duration, motw: bool, sign: bool) {
        if let Some(tx) = self.origin_tx.lock().unwrap().as_ref() {
            let _ = tx.try_send(OriginJob {
                path: path.to_string(),
                due: Instant::now() + delay,
                motw,
                sign,
                retried: false,
            });
        }
    }

    /// ETW 사건 시각(QPC 원시 값, 세션을 RAW_TIMESTAMP 로 연다)을 벽시계 FILETIME 으로 바꾼다.
    /// 모든 ETW 사건 시각은 이것을 거친다
    pub fn ts(&self, raw_qpc: i64) -> i64 {
        let mut c = self.clock.lock().unwrap();
        if c.needs_pair(qpc_now()) {
            let (q, f) = sample_pair();
            c.add_pair(q, f);
        }
        c.to_filetime(raw_qpc)
            .unwrap_or_else(crate::pipeline::now_filetime)
    }

    /// (QPC, 벽시계) 쌍을 1초마다 잡는다 (폴링 스레드). 사건이 뜸할 때 시각 변경 뒤 첫 사건이 옛 기준으로 바뀌는 것을 막는다
    pub fn sample_clock(&self) {
        let (q, f) = sample_pair();
        self.clock.lock().unwrap().add_pair(q, f);
    }

    pub fn count(&self, provider: &'static str) {
        *self.counts.lock().unwrap().entry(provider).or_insert(0) += 1;
    }

    /// 채널로 보낸다. 꽉 차 있으면 버리고 센다 (프로세스·연결·DNS·파일만 오므로 보통 비지 않는다).
    ///
    /// 로컬 DoS 완화(13차 Q2, 제안 5①): 한 PID 가 1초에 `PER_PID_PER_SEC` 건을 넘기면 그 초의 나머지
    /// Connect·DnsQuery·FileWrite 는 버리고 PID 별로 센다. 초가 바뀌면 "요약 1건"(DnsQuery 가 아니라 별도 종류가 없으므로
    /// 지금은 `rate_limited` 카운터로만, 사건 생성은 svc 가 카운터를 읽어 한다). ProcessStart/Stop·스냅샷·서명·CAPI2 는 제한하지 않는다
    /// (프로세스 사슬이 끊기면 안 되므로).
    pub fn emit(&self, ev: Event) {
        if let Some(pid) = rate_limited_pid(&ev) {
            let sec = ev.ts / 10_000_000;
            let mut rl = self.rate.lock().unwrap();
            let e = rl.entry(pid).or_insert((sec, 0));
            if e.0 != sec {
                *e = (sec, 0);
            }
            e.1 += 1;
            if e.1 > PER_PID_PER_SEC {
                self.rate_limited.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        match self.tx.try_send(ev) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    pub fn add_bytes(&self, key: ConnKey, sent: u64, recv: u64) {
        let mut m = self.bytes.lock().unwrap();
        let b = m.entry(key).or_default();
        b.sent += sent;
        b.recv += recv;
    }

    /// 누적분을 꺼내고 비운다 (1초 flush)
    pub fn take_bytes(&self) -> HashMap<ConnKey, Bytes> {
        std::mem::take(&mut *self.bytes.lock().unwrap())
    }

    /// NT 경로를 Win32 경로로. 모르는 볼륨이면 그대로.
    pub fn win32_path(&self, nt: &str) -> String {
        crate::paths::to_win32(&self.volumes, nt)
    }
}

fn qpc_freq() -> i64 {
    let mut f = 0i64;
    // SAFETY: 출력 포인터 하나. XP 이후 실패하지 않는다(문서)
    unsafe { windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut f) };
    if f > 0 {
        f
    } else {
        10_000_000
    }
}

fn qpc_now() -> i64 {
    let mut q = 0i64;
    // SAFETY: 출력 포인터 하나
    unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut q) };
    q
}

/// (QPC, FILETIME) 한 쌍. 벽시계를 QPC 두 번 사이에 읽고 그 가운데 QPC 와 짝짓는다
fn sample_pair() -> (i64, i64) {
    let q1 = qpc_now();
    let mut ft = windows_sys::Win32::Foundation::FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: 출력 포인터 하나
    unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime(&mut ft)
    };
    let q2 = qpc_now();
    (
        q1 + (q2 - q1) / 2,
        ((ft.dwHighDateTime as i64) << 32) | ft.dwLowDateTime as i64,
    )
}
