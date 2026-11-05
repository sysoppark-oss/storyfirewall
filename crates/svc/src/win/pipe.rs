//! 네임드 파이프 서버 (메시지 모드, overlapped). 명세 7판 2-8장.
//!
//! - `\\.\pipe\story-firewall`, `FILE_FLAG_FIRST_PIPE_INSTANCE`(가로채기 방지), `PIPE_REJECT_REMOTE_CLIENTS`.
//! - ACL(SDDL): Authenticated Users = 읽기 + 데이터 쓰기 + 속성 쓰기(0x12018b), Administrators·SYSTEM 전체.
//!   (A25 정정) 예전 `GRGW` 는 파이프에서 FILE_GENERIC_WRITE 라 FILE_APPEND_DATA = **FILE_CREATE_PIPE_INSTANCE** 를 포함했다 →
//!   서비스가 떠 있는 동안에도 일반 사용자가 같은 이름의 서버 인스턴스를 더 만들어 연결을 가로챌 수 있었다(Microsoft 문서
//!   "Named Pipe Security and Access Rights": FILE_GENERIC_WRITE 대신 개별 권한을 쓰라).
//! - 읽기는 overlapped + 이벤트로 시간 제한(`Transport::read_line(timeout)`), 쓰기는 overlapped 뒤 완료 대기.
//! - 한 메시지 = 한 줄 JSON(개행 포함). 메시지 경계는 파이프가 주고, 개행은 디버깅·스트림 파서 호환용(9차).

use std::ptr::{null, null_mut};
use std::time::Duration;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_IO_PENDING, ERROR_MORE_DATA, ERROR_PIPE_CONNECTED,
    HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, DisconnectNamedPipe, GetNamedPipeClientProcessId, SetNamedPipeHandleState,
    PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use super::wide;
use crate::handler::{Read, Transport};

pub const PIPE_NAME: &str = r"\\.\pipe\story-firewall";
/// FILE_GENERIC_READ(0x120089) | FILE_WRITE_DATA(0x2) | FILE_WRITE_ATTRIBUTES(0x100) = 0x12018b. 인스턴스 만들기(0x4) 없음.
pub const SDDL: &str = "D:P(A;;0x12018b;;;AU)(A;;GA;;;BA)(A;;GA;;;SY)";
/// A24 까지의 SDDL — poc4 에서 차이를 실측하려고만 남긴다
pub const SDDL_LEGACY: &str = "D:P(A;;GRGW;;;AU)(A;;GA;;;BA)(A;;GA;;;SY)";
/// 요청 1MB 상한(api) + 여유
const BUF: usize = 1024 * 1024 + 4096;

pub struct PipeServer {
    h: HANDLE,
    ev_read: HANDLE,
    ev_write: HANDLE,
    buf: Vec<u8>,
    /// 메시지 하나가 여러 ReadFile 로 올 때 이어 붙이는 자리
    pending: Vec<u8>,
}

unsafe impl Send for PipeServer {}

fn last_err() -> u32 {
    unsafe { GetLastError() }
}

impl PipeServer {
    /// 파이프 인스턴스를 만든다 (연결마다 하나). `first` 는 첫 인스턴스에만 FIRST_PIPE_INSTANCE 를 건다.
    pub fn create(name: &str, first: bool) -> Result<Self, String> {
        Self::create_with_sddl(name, first, SDDL)
    }

    pub fn create_with_sddl(name: &str, first: bool, sddl: &str) -> Result<Self, String> {
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let ok: BOOL = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!("SDDL 변환 실패 {:#x}", last_err()));
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let h = unsafe {
            CreateNamedPipeW_(
                wide(name).as_ptr(),
                open_mode,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                BUF as u32,
                BUF as u32,
                0,
                &sa,
            )
        };
        let e = last_err();
        unsafe { LocalFree(sd as _) };
        if h == INVALID_HANDLE_VALUE {
            return Err(format!("CreateNamedPipeW 실패 {e:#x}"));
        }
        let ev_read = unsafe { CreateEventW(null(), 1, 0, null()) };
        let ev_write = unsafe { CreateEventW(null(), 1, 0, null()) };
        Ok(Self {
            h,
            ev_read,
            ev_write,
            buf: vec![0u8; BUF],
            pending: Vec::new(),
        })
    }

    /// 클라이언트 연결 대기 (블로킹)
    pub fn wait_client(&mut self) -> Result<(), String> {
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = self.ev_read;
        let ok = unsafe { ConnectNamedPipe(self.h, &mut ov) };
        if ok == 0 {
            match last_err() {
                ERROR_IO_PENDING => {
                    unsafe { WaitForSingleObject(self.ev_read, INFINITE) };
                    let mut n = 0u32;
                    if unsafe { GetOverlappedResult(self.h, &ov, &mut n, 0) } == 0 {
                        return Err(format!("ConnectNamedPipe 완료 실패 {:#x}", last_err()));
                    }
                }
                ERROR_PIPE_CONNECTED => {}
                e => return Err(format!("ConnectNamedPipe 실패 {e:#x}")),
            }
        }
        Ok(())
    }

    pub fn raw(&self) -> HANDLE {
        self.h
    }

    pub fn disconnect(&mut self) {
        unsafe { DisconnectNamedPipe(self.h) };
    }
}

// windows-sys 의 CreateNamedPipeW 는 SECURITY_ATTRIBUTES 포인터를 받는다. 이름 충돌 없이 쓰려고 얇게 감싼다.
#[allow(non_snake_case)]
unsafe fn CreateNamedPipeW_(
    name: *const u16,
    open_mode: u32,
    pipe_mode: u32,
    max: u32,
    out_sz: u32,
    in_sz: u32,
    timeout: u32,
    sa: *const SECURITY_ATTRIBUTES,
) -> HANDLE {
    windows_sys::Win32::System::Pipes::CreateNamedPipeW(
        name, open_mode, pipe_mode, max, out_sz, in_sz, timeout, sa,
    )
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.ev_read);
            CloseHandle(self.ev_write);
            CloseHandle(self.h);
        }
    }
}

impl Transport for PipeServer {
    fn read_line(&mut self, timeout: Duration) -> Read {
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = self.ev_read;
        let mut n = 0u32;
        let ok = unsafe {
            ReadFile(
                self.h,
                self.buf.as_mut_ptr(),
                self.buf.len() as u32,
                &mut n,
                &mut ov,
            )
        };
        let mut more = false;
        if ok == 0 {
            match last_err() {
                ERROR_IO_PENDING => {
                    let w =
                        unsafe { WaitForSingleObject(self.ev_read, timeout.as_millis() as u32) };
                    if w == WAIT_TIMEOUT {
                        unsafe { CancelIoEx(self.h, &ov) };
                        // 취소 완료를 기다려 버퍼가 다시 쓰이지 않게 한다.
                        // A24 결함: 대기 시간이 끝난 직후·취소 직전에 읽기가 **완료**될 수 있다(경쟁). 예전 코드는 그 메시지를
                        // pending 에 넣고 Timeout 을 돌려줘, 다음 메시지가 올 때까지 요청이 묻혔다(UI 는 응답을 못 받아 멈춤 —
                        // poc5 에서 간헐적으로 이야기 화면·needs_ack 대화상자가 안 뜸). 완료됐으면 정상 읽기로 처리한다.
                        let done = unsafe { GetOverlappedResult(self.h, &ov, &mut n, 1) } != 0;
                        let err = if done { 0 } else { last_err() };
                        if done {
                            // 메시지 하나를 다 읽었다 → 아래에서 Line 으로
                        } else if err == ERROR_MORE_DATA {
                            more = true;
                        } else {
                            // 정말 취소됨(ERROR_OPERATION_ABORTED): 읽은 것 없음
                            if n > 0 {
                                self.pending.extend_from_slice(&self.buf[..n as usize]);
                            }
                            return Read::Timeout;
                        }
                    } else if w != WAIT_OBJECT_0 {
                        return Read::Closed;
                    } else if unsafe { GetOverlappedResult(self.h, &ov, &mut n, 0) } == 0 {
                        if last_err() == ERROR_MORE_DATA {
                            more = true;
                        } else {
                            return Read::Closed;
                        }
                    }
                }
                ERROR_MORE_DATA => more = true,
                _ => return Read::Closed,
            }
        }
        self.pending.extend_from_slice(&self.buf[..n as usize]);
        if more {
            // 메시지의 나머지를 계속 읽는다 (1MB 상한은 api 가 검사)
            return self.read_line(timeout);
        }
        let msg = std::mem::take(&mut self.pending);
        let s = String::from_utf8_lossy(&msg)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        Read::Line(s)
    }

    fn write_line(&mut self, line: &str) -> bool {
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = self.ev_write;
        let bytes = line.as_bytes();
        let mut n = 0u32;
        let ok = unsafe { WriteFile(self.h, bytes.as_ptr(), bytes.len() as u32, &mut n, &mut ov) };
        if ok == 0 {
            if last_err() != ERROR_IO_PENDING {
                return false;
            }
            unsafe { WaitForSingleObject(self.ev_write, 5_000) };
            if unsafe { GetOverlappedResult(self.h, &ov, &mut n, 0) } == 0 {
                return false;
            }
        }
        n as usize == bytes.len()
    }

    fn client_pid(&self) -> u32 {
        let mut pid = 0u32;
        unsafe { GetNamedPipeClientProcessId(self.h, &mut pid) };
        pid
    }
    /// A30: 클라이언트 세션. 실패하면 Some(u32::MAX) — "모름"을 범위 제한 없음(None)으로 두지 않는다(실패 시 닫힘):
    /// 어떤 세션과도 맞지 않아 일반 사용자는 시스템(0) 것만 본다
    fn client_session(&self) -> Option<u32> {
        let mut s = 0u32;
        if unsafe { windows_sys::Win32::System::Pipes::GetNamedPipeClientSessionId(self.h, &mut s) }
            != 0
        {
            Some(s)
        } else {
            Some(u32::MAX)
        }
    }
}

/// 테스트·UI 측 클라이언트 (동기). 한 줄 보내고 한 줄 받는다.
pub struct PipeClient {
    h: HANDLE,
    buf: Vec<u8>,
}
impl PipeClient {
    pub fn connect(name: &str) -> Result<Self, String> {
        // GENERIC_WRITE 대신 개별 권한 (서버 SDDL 이 인스턴스 만들기를 주지 않으므로), 식별 수준 SQOS (A23 UI 클라이언트와 같게)
        let h = unsafe {
            CreateFileW(
                wide(name).as_ptr(),
                super::pipe_name::CLIENT_ACCESS,
                FILE_SHARE_NONE,
                null(),
                OPEN_EXISTING,
                windows_sys::Win32::Storage::FileSystem::SECURITY_SQOS_PRESENT
                    | windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION,
                null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(format!("CreateFileW 실패 {:#x}", last_err()));
        }
        let mut mode = PIPE_READMODE_MESSAGE;
        if unsafe { SetNamedPipeHandleState(h, &mut mode, null(), null()) } == 0 {
            return Err(format!("SetNamedPipeHandleState 실패 {:#x}", last_err()));
        }
        Ok(Self {
            h,
            buf: vec![0u8; BUF],
        })
    }
    /// 서버 (PID, session) — 파이프 핸들에서
    pub fn server(&self) -> (u32, Option<u32>) {
        super::pipe_name::server_of(self.h)
    }
    pub fn send(&mut self, line: &str) -> bool {
        let mut n = 0u32;
        unsafe {
            WriteFile(self.h, line.as_ptr(), line.len() as u32, &mut n, null_mut()) != 0
                && n as usize == line.len()
        }
    }
    pub fn recv(&mut self) -> Option<String> {
        let mut n = 0u32;
        let ok = unsafe {
            ReadFile(
                self.h,
                self.buf.as_mut_ptr(),
                self.buf.len() as u32,
                &mut n,
                null_mut(),
            )
        };
        if ok == 0 && last_err() != ERROR_MORE_DATA {
            return None;
        }
        Some(
            String::from_utf8_lossy(&self.buf[..n as usize])
                .trim_end_matches(['\r', '\n'])
                .to_string(),
        )
    }
}
impl Drop for PipeClient {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.h) };
    }
}
