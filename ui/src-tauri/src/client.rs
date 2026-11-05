//! 서비스 클라이언트: 한 줄 JSON-RPC. Windows = 네임드 파이프(메시지 모드, overlapped), 그 외·개발 = TCP 루프백.
//! 읽기 스레드 하나가 응답(id 있음)은 대기자에게, 알림(id 없음)은 콜백으로 넘긴다.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const PIPE_NAME: &str = r"\\.\pipe\story-firewall";

/// 서비스로 가는 바이트 스트림 (읽기·쓰기 반쪽)
trait Line: Send {
    fn read_line(&mut self) -> std::io::Result<Option<String>>;
}
trait Sink: Send {
    fn write_line(&mut self, s: &str) -> std::io::Result<()>;
}

struct TcpLine(BufReader<std::net::TcpStream>);
impl Line for TcpLine {
    fn read_line(&mut self) -> std::io::Result<Option<String>> {
        let mut l = String::new();
        let n = self.0.read_line(&mut l)?;
        Ok(if n == 0 { None } else { Some(l) })
    }
}
struct TcpSink(std::net::TcpStream);
impl Sink for TcpSink {
    fn write_line(&mut self, s: &str) -> std::io::Result<()> {
        self.0.write_all(s.as_bytes())?;
        self.0.flush()
    }
}
impl Drop for TcpSink {
    fn drop(&mut self) {
        // 읽기 스레드를 깨워 끝내고 서버가 끊김을 보게
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

#[cfg(windows)]
pub mod pipe {
    //! A22 러너에서 찾은 결함: 동기(비 overlapped) 핸들을 읽기·쓰기 두 스레드가 나눠 쓰면, 같은 파일 객체의 동기 I/O 는
    //! **직렬화**되어 읽기 스레드의 대기 중인 ReadFile 이 요청 WriteFile 을 막는다(교착). hello 는 경쟁으로 우연히 통과하고
    //! 그다음 요청부터 멈췄다. → FILE_FLAG_OVERLAPPED 로 열고 읽기·쓰기를 각자의 이벤트로 기다린다.
    use super::{Line, Sink};
    use std::sync::Arc;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_IO_PENDING, ERROR_MORE_DATA, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_SHARE_NONE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT};
    use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, GetNamedPipeServerSessionId, SetNamedPipeHandleState, WaitNamedPipeW, PIPE_READMODE_MESSAGE};
    use windows_sys::Win32::System::Threading::CreateEventW;
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

    const ERROR_PIPE_BUSY: i32 = 231;

    /// 파이프 핸들 (읽기·쓰기 반쪽이 함께 쥔다. 마지막이 놓을 때 닫음)
    pub struct Handle(HANDLE);
    unsafe impl Send for Handle {}
    unsafe impl Sync for Handle {}
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    /// 서비스가 공개한 파이프 이름 (A25): HKLM\SOFTWARE\StoryFirewall\PipeName. 형식이 맞을 때만 쓰고, 없으면 고정 이름(시험 서버).
    /// 서비스는 시작마다 무작위 이름으로 첫 인스턴스를 만든 **뒤** 공개하므로, 이름을 미리 알고 선점할 수 없다.
    pub fn resolve_name() -> String {
        use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
        const PREFIX: &str = r"\\.\pipe\story-firewall-";
        let key: Vec<u16> = r"SOFTWARE\StoryFirewall".encode_utf16().chain(std::iter::once(0)).collect();
        let val: Vec<u16> = "PipeName".encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = [0u16; 128];
        let mut cb = (buf.len() * 2) as u32;
        let r = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), val.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr() as *mut _, &mut cb) };
        if r == 0 {
            let n = (cb as usize / 2).saturating_sub(1).min(buf.len());
            let s = String::from_utf16_lossy(&buf[..n]);
            if s.strip_prefix(PREFIX).is_some_and(|h| h.len() == 32 && h.bytes().all(|c| c.is_ascii_hexdigit())) {
                return s;
            }
        }
        super::PIPE_NAME.to_string()
    }

    /// 마지막으로 붙은 파이프 서버 (PID, session) — 시험 기록용
    pub static SERVER_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    pub static SERVER_SESSION: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(u32::MAX);

    /// 서버의 빈 인스턴스가 잠시 없으면(ERROR_PIPE_BUSY) 최대 3번, 2초씩 기다린다.
    ///
    /// 파이프 가로채기(squatting) 대비 (A23): 서비스보다 먼저 같은 이름의 파이프를 만든 일반 권한 악성코드가 서버 행세를 하면
    /// ① 보기 모드 UI 에 가짜 이야기를 보여 주고 ② 승격된 승인 도우미의 토큰을 가장(impersonate)할 수 있다.
    /// → SQOS 를 **식별 수준**으로 걸어 서버가 우리 토큰으로 행동하지 못하게 하고(서비스의 관리자 검사는 식별 수준이면 된다),
    /// 서버 프로세스가 session 0(서비스)인지 확인한다. 일반 사용자 프로세스는 session 0 에서 돌 수 없다.
    /// 시험 빌드(e2e-cdp)는 러너에서 서버를 콘솔로 띄우므로 session 을 기록만 한다.
    pub fn open(name: &str) -> std::io::Result<Arc<Handle>> {
        let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut tries = 0;
        let h = loop {
            // GENERIC_WRITE 대신 개별 권한 (A25): 서버 DACL 이 인스턴스 만들기(FILE_CREATE_PIPE_INSTANCE)를 주지 않으므로
            // 읽기 + 데이터 쓰기 + 속성 쓰기(SetNamedPipeHandleState)만 요청한다
            let access = FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES;
            let h = unsafe { CreateFileW(w.as_ptr(), access, FILE_SHARE_NONE, std::ptr::null(), OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, std::ptr::null_mut()) };
            if h != INVALID_HANDLE_VALUE {
                break h;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_PIPE_BUSY) && tries < 3 {
                tries += 1;
                unsafe { WaitNamedPipeW(w.as_ptr(), 2000) };
                continue;
            }
            return Err(err);
        };
        let handle = Arc::new(Handle(h));
        let mut spid = 0u32;
        if unsafe { GetNamedPipeServerProcessId(h, &mut spid) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // 세션은 파이프 핸들에서 바로 얻는다 (A25 실측: 일반 사용자는 LocalSystem 서비스 프로세스를 열 수 없어
        // ProcessIdToSessionId 가 접근 거부 → 예전 코드는 배포 빌드의 보기 모드 UI 가 진짜 서비스까지 거부했을 것)
        let mut sess = u32::MAX;
        let known = unsafe { GetNamedPipeServerSessionId(h, &mut sess) } != 0;
        SERVER_PID.store(spid, std::sync::atomic::Ordering::SeqCst);
        SERVER_SESSION.store(if known { sess } else { u32::MAX }, std::sync::atomic::Ordering::SeqCst);
        if !(known && sess == 0) && !cfg!(feature = "e2e-cdp") {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("파이프 서버(PID {spid})가 서비스(session 0)가 아닙니다 — 가로채기 의심")));
        }
        let mut mode = PIPE_READMODE_MESSAGE;
        if unsafe { SetNamedPipeHandleState(h, &mut mode, std::ptr::null(), std::ptr::null()) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(handle)
    }

    struct Event(HANDLE);
    unsafe impl Send for Event {}
    impl Event {
        fn new() -> std::io::Result<Self> {
            let e = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if e.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Event(e))
        }
    }
    impl Drop for Event {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    /// overlapped 한 번: (전송 바이트, 메시지 남음)
    fn wait(h: HANDLE, ov: &mut OVERLAPPED, started_ok: bool, n: &mut u32) -> std::io::Result<bool> {
        if !started_ok {
            let e = unsafe { GetLastError() };
            if e == ERROR_MORE_DATA {
                return Ok(true);
            }
            if e != ERROR_IO_PENDING {
                return Err(std::io::Error::from_raw_os_error(e as i32));
            }
        }
        if unsafe { GetOverlappedResult(h, ov, n, 1) } == 0 {
            let e = unsafe { GetLastError() };
            if e == ERROR_MORE_DATA {
                return Ok(true);
            }
            return Err(std::io::Error::from_raw_os_error(e as i32));
        }
        Ok(false)
    }

    pub struct PipeLine {
        h: Arc<Handle>,
        ev: Event,
        buf: Vec<u8>,
    }
    impl PipeLine {
        pub fn new(h: Arc<Handle>) -> std::io::Result<Self> {
            Ok(Self { h, ev: Event::new()?, buf: vec![0u8; 1024 * 1024 + 4096] })
        }
    }
    impl Line for PipeLine {
        fn read_line(&mut self) -> std::io::Result<Option<String>> {
            // 메시지 모드: 메시지 하나를 다 받을 때까지(ERROR_MORE_DATA 면 이어 읽기)
            let mut out = Vec::new();
            loop {
                let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
                ov.hEvent = self.ev.0;
                let mut n = 0u32;
                let ok = unsafe { ReadFile(self.h.0, self.buf.as_mut_ptr(), self.buf.len() as u32, &mut n, &mut ov) } != 0;
                match wait(self.h.0, &mut ov, ok, &mut n) {
                    Ok(more) => {
                        out.extend_from_slice(&self.buf[..n as usize]);
                        if !more {
                            return Ok(if out.is_empty() { None } else { Some(String::from_utf8_lossy(&out).into_owned()) });
                        }
                    }
                    // 끊김(109)·취소(995) = 끝
                    Err(e) if matches!(e.raw_os_error(), Some(109) | Some(995)) => return Ok(None),
                    Err(e) => return Err(e),
                }
            }
        }
    }

    pub struct PipeSink {
        h: Arc<Handle>,
        ev: Event,
    }
    impl PipeSink {
        pub fn new(h: Arc<Handle>) -> std::io::Result<Self> {
            Ok(Self { h, ev: Event::new()? })
        }
    }
    impl Sink for PipeSink {
        fn write_line(&mut self, s: &str) -> std::io::Result<()> {
            let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
            ov.hEvent = self.ev.0;
            let mut n = 0u32;
            let ok = unsafe { WriteFile(self.h.0, s.as_ptr(), s.len() as u32, &mut n, &mut ov) } != 0;
            wait(self.h.0, &mut ov, ok, &mut n)?;
            if n as usize != s.len() {
                return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "짧은 쓰기"));
            }
            Ok(())
        }
    }
    impl Drop for PipeSink {
        fn drop(&mut self) {
            // 읽기 스레드의 대기 중인 ReadFile 을 취소해 스레드가 끝나고 핸들이 닫히게 한다 (서버가 끊김을 본다)
            unsafe { CancelIoEx(self.h.0, std::ptr::null()) };
        }
    }
}

pub struct Client {
    sink: Mutex<Box<dyn Sink>>,
    next_id: Mutex<i64>,
    waiters: Arc<Mutex<HashMap<i64, Sender<serde_json::Value>>>>,
    pub endpoint: String,
    /// 우리가 놓는 중 (다시 연결) — 읽기 스레드가 끊김 알림을 내지 않게
    closing: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for Client {
    fn drop(&mut self) {
        // 필드(sink)는 이 함수 뒤에 놓인다 → 깃발이 CancelIoEx 보다 먼저 선다
        self.closing.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Client {
    /// `endpoint`: "pipe" 또는 "tcp:127.0.0.1:7878". 알림은 `on_notify` 로.
    pub fn connect(endpoint: &str, on_notify: Box<dyn Fn(serde_json::Value) + Send>) -> std::io::Result<Client> {
        let (line, sink): (Box<dyn Line>, Box<dyn Sink>) = if let Some(addr) = endpoint.strip_prefix("tcp:") {
            let s = std::net::TcpStream::connect_timeout(&addr.parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "주소"))?, Duration::from_secs(3))?;
            (Box::new(TcpLine(BufReader::new(s.try_clone()?))), Box::new(TcpSink(s)))
        } else {
            #[cfg(windows)]
            {
                let h = pipe::open(&pipe::resolve_name())?;
                (Box::new(pipe::PipeLine::new(h.clone())?), Box::new(pipe::PipeSink::new(h)?))
            }
            #[cfg(not(windows))]
            {
                return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "이 OS 에서는 tcp: 끝점만"));
            }
        };
        let waiters: Arc<Mutex<HashMap<i64, Sender<serde_json::Value>>>> = Arc::new(Mutex::new(HashMap::new()));
        let w = waiters.clone();
        let closing = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let closing2 = closing.clone();
        std::thread::spawn(move || {
            let mut line = line;
            let reason = loop {
                match line.read_line() {
                    Ok(Some(l)) => {
                        let Ok(v) = serde_json::from_str::<serde_json::Value>(l.trim()) else { continue };
                        match v.get("id").and_then(|i| i.as_i64()) {
                            Some(id) => {
                                if let Some(tx) = w.lock().unwrap().remove(&id) {
                                    let _ = tx.send(v);
                                }
                            }
                            None => on_notify(v),
                        }
                    }
                    Ok(None) => break "eof".to_string(),
                    Err(e) => break format!("read error: {e}"),
                }
            };
            // 연결 끊김: 대기자 전부 깨우고, 화면에 사유를 알린다 (A24: 원인 불명 끊김 진단용).
            // 우리가 놓아서(다시 연결) 끊긴 경우는 알리지 않는다 — Client::drop 이 closing 을 먼저 세운다
            w.lock().unwrap().clear();
            if !closing2.load(std::sync::atomic::Ordering::SeqCst) {
                on_notify(serde_json::json!({"jsonrpc": "2.0", "method": "client.disconnected", "params": {"reason": reason}}));
            }
        });
        Ok(Client { sink: Mutex::new(sink), next_id: Mutex::new(1), waiters, endpoint: endpoint.to_string(), closing })
    }

    pub fn call(&self, method: &str, params: serde_json::Value, timeout: Duration) -> Result<serde_json::Value, String> {
        let id = {
            let mut n = self.next_id.lock().unwrap();
            let id = *n;
            *n += 1;
            id
        };
        let (tx, rx): (Sender<serde_json::Value>, Receiver<serde_json::Value>) = mpsc::channel();
        self.waiters.lock().unwrap().insert(id, tx);
        let req = serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let mut line = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        line.push('\n');
        self.sink.lock().unwrap().write_line(&line).map_err(|e| format!("send: {e}"))?;
        match rx.recv_timeout(timeout) {
            Ok(v) => Ok(v),
            Err(_) => {
                self.waiters.lock().unwrap().remove(&id);
                Err("timeout".into())
            }
        }
    }
}
