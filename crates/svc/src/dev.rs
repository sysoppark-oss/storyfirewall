//! 개발용 가짜 서비스 (A15): TCP 루프백 Transport + 모두 통과하는 Authn. Linux 에서 UI 를 개발·시연할 때 쓴다.
//! 배포 빌드에는 들어가지 않는다 (`dev-server` feature). 프로토콜은 파이프와 같다: 한 줄 JSON, 개행 종료.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::handler::{Authn, Read, Transport};

pub struct TcpTransport {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl TcpTransport {
    pub fn new(stream: TcpStream) -> std::io::Result<Self> {
        let writer = stream.try_clone()?;
        Ok(Self {
            reader: BufReader::new(stream),
            writer,
        })
    }
}

impl Transport for TcpTransport {
    fn read_line(&mut self, timeout: Duration) -> Read {
        let _ = self.reader.get_ref().set_read_timeout(Some(timeout));
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Read::Closed,
            Ok(_) => Read::Line(line.trim_end_matches(['\r', '\n']).to_string()),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Read::Timeout
            }
            Err(_) => Read::Closed,
        }
    }
    fn write_line(&mut self, line: &str) -> bool {
        let mut s = line.to_string();
        if !s.ends_with('\n') {
            s.push('\n');
        }
        self.writer.write_all(s.as_bytes()).is_ok() && self.writer.flush().is_ok()
    }
    fn client_pid(&self) -> u32 {
        // TCP 에서는 클라이언트 PID 를 모른다. 개발용이므로 고정값
        1
    }
}

/// 개발용: 서명·관리자 검사를 모두 통과시킨다. `admin=false` 로 비관리자 화면을 시험할 수 있다.
pub struct DevAuthn {
    pub admin: bool,
}

impl Authn for DevAuthn {
    fn client_image(&self, _pid: u32) -> Option<String> {
        Some("dev-ui".into())
    }
    fn signature_ok(&self, _pid: u32) -> bool {
        true
    }
    fn is_admin(&self, _pid: u32) -> bool {
        self.admin
    }
}

/// 개발용 호스트: 그럴듯한 리스닝 포트 몇 개, 종료는 기록만
pub struct DevHost;
impl crate::host::Host for DevHost {
    fn listeners(&self) -> Result<Vec<crate::host::Listener>, String> {
        let l = |proto: &str, laddr: &str, lport: u16, pid: u32| crate::host::Listener {
            proto: proto.into(),
            laddr: laddr.into(),
            lport,
            pid,
            any_addr: laddr == "0.0.0.0" || laddr == "::",
        };
        Ok(vec![
            l("tcp", "0.0.0.0", 135, 900),
            l("tcp", "0.0.0.0", 445, 4),
            l("tcp", "127.0.0.1", 7878, 1),
            l("udp", "0.0.0.0", 5353, 1500),
            l("tcp", "0.0.0.0", 4444, 2200),
        ])
    }
    fn terminate(&self, pid: u32, create_ft: Option<i64>) -> String {
        format!("dev: pid {pid} (create {create_ft:?}) 종료한 것으로 침")
    }
}
