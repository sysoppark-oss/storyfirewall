//! SCM 서비스: 등록·해제, 서비스 본체 진입(StartServiceCtrlDispatcherW), 제어 코드 수신. 명세 7판 2-8장.
//!
//! - 등록: `SERVICE_WIN32_OWN_PROCESS`, 기본 `SERVICE_DEMAND_START`(PoC). 제품은 AUTO_START + 지연 시작으로 바꾼다.
//! - 제어 코드: STOP·SHUTDOWN 은 종료, POWEREVENT(재개) 는 `Command::Resume`, TIMECHANGE 는 `Command::TimeChanged`
//!   로 이어진다. 핸들러는 SCM 스레드에서 불리므로 채널에 넣기만 하고 바로 돌아온다.
//! - 서비스 main 은 C 콜백(컨텍스트 없음)이라 송신기는 프로세스 전역 `OnceLock` 에 둔다. 서비스는 프로세스당 하나.

use std::ptr::{null, null_mut};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Mutex, OnceLock};

use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{GetLastError, NO_ERROR};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, QueryServiceStatus, RegisterServiceCtrlHandlerExW, SetServiceStatus,
    StartServiceCtrlDispatcherW, StartServiceW, SC_MANAGER_ALL_ACCESS, SERVICE_ACCEPT_POWEREVENT,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_ACCEPT_TIMECHANGE, SERVICE_ALL_ACCESS,
    SERVICE_CONTROL_POWEREVENT, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
    SERVICE_CONTROL_TIMECHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED,
    SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

use super::wide;

/// 제품 서비스 이름 (레지스트리 키 이름). 표시 이름은 등록 시 따로 준다.
pub const SERVICE_NAME: &str = "StoryFirewall";

/// 전원 이벤트 종류 (WinUser.h PBT_*). windows-sys 의 Win32_System_Power feature 를 켜지 않으려고 직접 정의.
const PBT_APMRESUMESUSPEND: u32 = 0x0007;
const PBT_APMRESUMEAUTOMATIC: u32 = 0x0012;
const PBT_APMSUSPEND: u32 = 0x0004;
/// 핸들러가 아직 지원하지 않는 제어 코드에 돌려주는 값
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

/// SCM 이 보낸 제어를 서비스 본체에 전하는 이벤트
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceEvent {
    Stop,
    Shutdown,
    /// 절전 진입 (PBT_APMSUSPEND)
    Suspend,
    /// 절전 해제 (PBT_APMRESUMEAUTOMATIC / PBT_APMRESUMESUSPEND) → engine `on_resume`
    Resume,
    /// 시스템 시각 변경 → engine `on_time_changed`
    TimeChanged,
    Other {
        control: u32,
        event_type: u32,
    },
}

struct Global {
    name: Vec<u16>,
    tx: Mutex<Option<Sender<ServiceEvent>>>,
    status: Mutex<usize>, // SERVICE_STATUS_HANDLE (포인터를 usize 로)
    body: Mutex<Option<Box<dyn FnOnce(Receiver<ServiceEvent>) + Send>>>,
}
static GLOBAL: OnceLock<Global> = OnceLock::new();

fn err(what: &str) -> String {
    format!("{what} 실패 {:#x}", unsafe { GetLastError() })
}

// ---- 등록·해제·시작·중지 (관리자 콘솔에서) ----

struct ScHandle(*mut core::ffi::c_void);
impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

fn open_scm() -> Result<ScHandle, String> {
    let h = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ALL_ACCESS) };
    if h.is_null() {
        return Err(err("OpenSCManagerW"));
    }
    Ok(ScHandle(h))
}

fn open_service(scm: &ScHandle, name: &str) -> Result<ScHandle, String> {
    let h = unsafe { OpenServiceW(scm.0, wide(name).as_ptr(), SERVICE_ALL_ACCESS) };
    if h.is_null() {
        return Err(err("OpenServiceW"));
    }
    Ok(ScHandle(h))
}

/// 서비스를 등록한다. `binary` 는 따옴표를 포함한 전체 명령줄 (예: `"C:\...\svc.exe" service`).
pub fn install(name: &str, display: &str, binary: &str) -> Result<(), String> {
    let scm = open_scm()?;
    let h = unsafe {
        CreateServiceW(
            scm.0,
            wide(name).as_ptr(),
            wide(display).as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            wide(binary).as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        )
    };
    if h.is_null() {
        return Err(err("CreateServiceW"));
    }
    drop(ScHandle(h));
    Ok(())
}

/// 제품 서비스 등록 (A26): 자동 시작, 설명, 실패 시 5초 뒤 재시작(3번, 하루 지나면 횟수 초기화).
/// 이미 있으면(업그레이드, ERROR_SERVICE_EXISTS) 실행 경로·시작 유형·표시 이름을 고쳐 쓴다 — 제거하지 않는다:
/// 제거(uninstall)는 WFP 필터를 지우므로 업그레이드 사이에 보호가 빈다(A28). 반환: true = 새로 등록, false = 기존 것 갱신.
pub fn install_auto(
    name: &str,
    display: &str,
    binary: &str,
    description: &str,
) -> Result<bool, String> {
    use windows_sys::Win32::System::Services::{
        ChangeServiceConfig2W, ChangeServiceConfigW, SC_ACTION, SC_ACTION_RESTART,
        SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS,
        SERVICE_DESCRIPTIONW, SERVICE_FAILURE_ACTIONSW,
    };
    const ERROR_SERVICE_EXISTS: u32 = 1073;
    let scm = open_scm()?;
    let h = unsafe {
        CreateServiceW(
            scm.0,
            wide(name).as_ptr(),
            wide(display).as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            wide(binary).as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        )
    };
    let (svc, created) = if h.is_null() {
        if unsafe { windows_sys::Win32::Foundation::GetLastError() } != ERROR_SERVICE_EXISTS {
            return Err(err("CreateServiceW"));
        }
        let svc = open_service(&scm, name)?;
        // SERVICE_NO_CHANGE(0xffffffff) = 그대로. 형식은 그대로, 시작 유형·오류 제어·경로·표시 이름만
        const NO_CHANGE: u32 = 0xffff_ffff;
        if unsafe {
            ChangeServiceConfigW(
                svc.0,
                NO_CHANGE,
                SERVICE_AUTO_START,
                NO_CHANGE,
                wide(binary).as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
                wide(display).as_ptr(),
            )
        } == 0
        {
            return Err(err("ChangeServiceConfigW"));
        }
        (svc, false)
    } else {
        (ScHandle(h), true)
    };
    let mut desc = wide(description);
    let d = SERVICE_DESCRIPTIONW {
        lpDescription: desc.as_mut_ptr(),
    };
    unsafe {
        ChangeServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_DESCRIPTION,
            &d as *const _ as *const _,
        )
    };
    let mut actions = [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5_000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5_000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 30_000,
        },
    ];
    let fa = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 86_400,
        lpRebootMsg: null_mut(),
        lpCommand: null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    if unsafe {
        ChangeServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            &fa as *const _ as *const _,
        )
    } == 0
    {
        return Err(err("ChangeServiceConfig2W(FAILURE_ACTIONS)"));
    }
    Ok(created)
}

pub fn uninstall(name: &str) -> Result<(), String> {
    let scm = open_scm()?;
    let svc = open_service(&scm, name)?;
    if unsafe { DeleteService(svc.0) } == 0 {
        return Err(err("DeleteService"));
    }
    Ok(())
}

pub fn start(name: &str) -> Result<(), String> {
    let scm = open_scm()?;
    let svc = open_service(&scm, name)?;
    if unsafe { StartServiceW(svc.0, 0, null()) } == 0 {
        return Err(err("StartServiceW"));
    }
    Ok(())
}

pub fn stop(name: &str) -> Result<(), String> {
    let scm = open_scm()?;
    let svc = open_service(&scm, name)?;
    let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    if unsafe { ControlService(svc.0, SERVICE_CONTROL_STOP, &mut st) } == 0 {
        return Err(err("ControlService(STOP)"));
    }
    Ok(())
}

/// 현재 상태 (SERVICE_RUNNING=4, SERVICE_STOPPED=1 …)
pub fn query_state(name: &str) -> Result<u32, String> {
    let scm = open_scm()?;
    let svc = open_service(&scm, name)?;
    let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    if unsafe { QueryServiceStatus(svc.0, &mut st) } == 0 {
        return Err(err("QueryServiceStatus"));
    }
    Ok(st.dwCurrentState)
}

// ---- 서비스 본체 ----

fn set_status(handle: SERVICE_STATUS_HANDLE, state: u32, accepted: u32, wait_hint_ms: u32) {
    let st = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: NO_ERROR,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint_ms,
    };
    unsafe { SetServiceStatus(handle, &st) };
}

unsafe extern "system" fn handler(
    control: u32,
    event_type: u32,
    _data: *mut core::ffi::c_void,
    _ctx: *mut core::ffi::c_void,
) -> u32 {
    let Some(g) = GLOBAL.get() else {
        return ERROR_CALL_NOT_IMPLEMENTED;
    };
    let ev = match control {
        SERVICE_CONTROL_STOP => ServiceEvent::Stop,
        SERVICE_CONTROL_SHUTDOWN => ServiceEvent::Shutdown,
        SERVICE_CONTROL_POWEREVENT => match event_type {
            PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND => ServiceEvent::Resume,
            PBT_APMSUSPEND => ServiceEvent::Suspend,
            _ => ServiceEvent::Other {
                control,
                event_type,
            },
        },
        SERVICE_CONTROL_TIMECHANGE => ServiceEvent::TimeChanged,
        // SERVICE_CONTROL_INTERROGATE(4) 등: 상태만 유지
        _ => ServiceEvent::Other {
            control,
            event_type,
        },
    };
    if matches!(ev, ServiceEvent::Stop | ServiceEvent::Shutdown) {
        let h = *g.status.lock().unwrap() as SERVICE_STATUS_HANDLE;
        set_status(h, SERVICE_STOP_PENDING, 0, 10_000);
    }
    if let Some(tx) = g.tx.lock().unwrap().as_ref() {
        let _ = tx.send(ev);
    }
    NO_ERROR
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let Some(g) = GLOBAL.get() else { return };
    let h = unsafe { RegisterServiceCtrlHandlerExW(g.name.as_ptr(), Some(handler), null()) };
    if h.is_null() {
        return;
    }
    *g.status.lock().unwrap() = h as usize;
    set_status(h, SERVICE_START_PENDING, 0, 5_000);
    let (tx, rx) = mpsc::channel();
    *g.tx.lock().unwrap() = Some(tx);
    set_status(
        h,
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP
            | SERVICE_ACCEPT_SHUTDOWN
            | SERVICE_ACCEPT_POWEREVENT
            | SERVICE_ACCEPT_TIMECHANGE,
        0,
    );
    // 본체 실행 (Stop/Shutdown 을 받으면 돌아온다)
    if let Some(body) = g.body.lock().unwrap().take() {
        body(rx);
    }
    *g.tx.lock().unwrap() = None;
    set_status(h, SERVICE_STOPPED, 0, 0);
}

/// SCM 이 이 프로세스를 서비스로 띄웠을 때 부른다. `body` 는 서비스 본체(제어 이벤트 수신기를 받는다).
/// 성공하면 서비스가 멈출 때 돌아온다. 콘솔에서 직접 실행하면 ERROR_FAILED_SERVICE_CONTROLLER_CONNECT(0x427) 로 실패한다.
pub fn run(name: &str, body: Box<dyn FnOnce(Receiver<ServiceEvent>) + Send>) -> Result<(), String> {
    let g = Global {
        name: wide(name),
        tx: Mutex::new(None),
        status: Mutex::new(0),
        body: Mutex::new(Some(body)),
    };
    if GLOBAL.set(g).is_err() {
        return Err("서비스는 프로세스당 하나".into());
    }
    let mut name_w = wide(name);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name_w.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(err("StartServiceCtrlDispatcherW"));
    }
    Ok(())
}

/// 서비스 SID 유형이 Unrestricted(1)·Restricted(3) 인가 — 서비스 SID 로 WFP 조건을 걸어도 그 서비스 트래픽이 맞는가.
/// None(0)이면 토큰에 서비스 SID 가 없어 조건이 맞지 않는다(Windows 방화벽 서비스 규칙과 같은 제약). 읽기만(QUERY_CONFIG).
pub fn service_sid_usable(name: &str) -> bool {
    use windows_sys::Win32::System::Services::{
        QueryServiceConfig2W, SC_MANAGER_CONNECT, SERVICE_CONFIG_SERVICE_SID_INFO,
        SERVICE_QUERY_CONFIG, SERVICE_SID_INFO,
    };
    let scm = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        return false;
    }
    let scm = ScHandle(scm);
    let h = unsafe { OpenServiceW(scm.0, wide(name).as_ptr(), SERVICE_QUERY_CONFIG) };
    if h.is_null() {
        return false;
    }
    let h = ScHandle(h);
    let mut info: SERVICE_SID_INFO = unsafe { std::mem::zeroed() };
    let mut need: u32 = 0;
    // SAFETY: 출력 버퍼는 SERVICE_SID_INFO 한 개(고정 크기, DWORD 하나)
    let ok = unsafe {
        QueryServiceConfig2W(
            h.0,
            SERVICE_CONFIG_SERVICE_SID_INFO,
            &mut info as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_SID_INFO>() as u32,
            &mut need,
        )
    };
    ok != 0 && matches!(info.dwServiceSidType, 1 | 3)
}
