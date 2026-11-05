//! PoC 1: 프로세스별 연결 목록 수집기
//!
//! 목적: GetExtendedTcpTable / GetExtendedUdpTable 로 TCP·UDP(IPv4·IPv6) 연결을
//!       소유 PID 와 함께 읽고, 1초 간격으로 변화(신규·종료)를 출력한다.
//!
//! 통과 기준(명세 5장 P1):
//!   - 브라우저·메신저·Windows Update 동시 실행 시 연결과 PID 가 일치
//!   - CPU 사용률 2% 이하 (작업 관리자에서 확인)
//!
//! 실행: cargo run --release
//!   관리자 권한으로 실행해야 다른 사용자·시스템 프로세스의 실행 파일 경로를 읽을 수 있다.
//!   일반 권한이면 해당 행의 프로세스 이름이 <access denied> 로 표시된다.
//!
//! 주의: 이 PoC 는 송수신 바이트를 세지 않는다. 그것은 ETW(Kernel-Network) 로 하는 P1-b 과제다.

#![cfg(windows)]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// 연결 한 건. HashSet 키로 쓰기 위해 Eq/Hash 를 구현한다.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Conn {
    proto: &'static str, // "TCP" | "UDP"
    local: IpAddr,
    local_port: u16,
    remote: Option<IpAddr>, // UDP 는 원격 주소가 없다
    remote_port: u16,
    state: Option<u32>, // TCP 상태 코드, UDP 는 None
    pid: u32,
}

/// MIB_TCP_STATE 코드를 사람이 읽는 이름으로
fn tcp_state_name(code: u32) -> &'static str {
    match code {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTAB",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "?",
    }
}

/// 포트: 구조체의 하위 16비트가 네트워크 바이트 순서로 들어 있다.
#[inline]
fn port(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

/// IPv4: dwXxxAddr 는 메모리상 네트워크 순서이므로 바이트 그대로 쓴다.
#[inline]
fn v4(raw: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()))
}

#[inline]
fn v6(raw: [u8; 16]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(raw))
}

/// 테이블 API 공통 패턴: 크기 질의 → 버퍼 확보 → 재호출.
/// 호출 사이에 연결 수가 늘어 ERROR_INSUFFICIENT_BUFFER 가 반복될 수 있어 최대 8회 재시도한다.
fn fetch_table<F>(mut call: F) -> Result<Vec<u8>, u32>
where
    F: FnMut(*mut u8, &mut u32) -> u32,
{
    let mut size: u32 = 0;
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..8 {
        let rc = call(buf.as_mut_ptr(), &mut size);
        if rc == NO_ERROR {
            // 버퍼보다 큰 길이를 보고하면(비정상) 빈 결과로 처리해 UB 를 피한다
            if (size as usize) > buf.capacity() {
                return Ok(Vec::new());
            }
            // 실제 채워진 길이만큼으로 자른다(버퍼가 size 보다 클 수 있음)
            unsafe { buf.set_len(size as usize) };
            return Ok(buf);
        }
        if rc != ERROR_INSUFFICIENT_BUFFER {
            return Err(rc);
        }
        buf = Vec::with_capacity(size as usize);
    }
    Err(ERROR_INSUFFICIENT_BUFFER)
}

/// 테이블 버퍼에서 행 배열을 안전하게 꺼낸다.
/// MS 문서: dwNumEntries 와 table[0] 사이에 패딩이 있을 수 있으므로 offset 으로 접근한다.
unsafe fn rows<'a, T, R>(buf: &'a [u8], first_row_offset: usize, count: u32) -> &'a [R] {
    let _ = std::mem::size_of::<T>(); // 타입 매개변수 문서화 용도
    let ptr = buf.as_ptr().add(first_row_offset) as *const R;
    std::slice::from_raw_parts(ptr, count as usize)
}

fn collect_tcp4(out: &mut Vec<Conn>) -> Result<(), u32> {
    let buf = fetch_table(|p, size| unsafe {
        GetExtendedTcpTable(p as _, size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    })?;
    if buf.is_empty() {
        return Ok(());
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let off = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
    let list: &[MIB_TCPROW_OWNER_PID] =
        unsafe { rows::<MIB_TCPTABLE_OWNER_PID, _>(&buf, off, table.dwNumEntries) };
    for r in list {
        out.push(Conn {
            proto: "TCP",
            local: v4(r.dwLocalAddr),
            local_port: port(r.dwLocalPort),
            remote: Some(v4(r.dwRemoteAddr)),
            remote_port: port(r.dwRemotePort),
            state: Some(r.dwState),
            pid: r.dwOwningPid,
        });
    }
    Ok(())
}

fn collect_tcp6(out: &mut Vec<Conn>) -> Result<(), u32> {
    let buf = fetch_table(|p, size| unsafe {
        GetExtendedTcpTable(p as _, size, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    })?;
    if buf.is_empty() {
        return Ok(());
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
    let off = std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
    let list: &[MIB_TCP6ROW_OWNER_PID] =
        unsafe { rows::<MIB_TCP6TABLE_OWNER_PID, _>(&buf, off, table.dwNumEntries) };
    for r in list {
        out.push(Conn {
            proto: "TCP",
            local: v6(r.ucLocalAddr),
            local_port: port(r.dwLocalPort),
            remote: Some(v6(r.ucRemoteAddr)),
            remote_port: port(r.dwRemotePort),
            state: Some(r.dwState),
            pid: r.dwOwningPid,
        });
    }
    Ok(())
}

fn collect_udp4(out: &mut Vec<Conn>) -> Result<(), u32> {
    let buf = fetch_table(|p, size| unsafe {
        GetExtendedUdpTable(p as _, size, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
    })?;
    if buf.is_empty() {
        return Ok(());
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let off = std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table);
    let list: &[MIB_UDPROW_OWNER_PID] =
        unsafe { rows::<MIB_UDPTABLE_OWNER_PID, _>(&buf, off, table.dwNumEntries) };
    for r in list {
        out.push(Conn {
            proto: "UDP",
            local: v4(r.dwLocalAddr),
            local_port: port(r.dwLocalPort),
            remote: None,
            remote_port: 0,
            state: None,
            pid: r.dwOwningPid,
        });
    }
    Ok(())
}

fn collect_udp6(out: &mut Vec<Conn>) -> Result<(), u32> {
    let buf = fetch_table(|p, size| unsafe {
        GetExtendedUdpTable(p as _, size, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
    })?;
    if buf.is_empty() {
        return Ok(());
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
    let off = std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table);
    let list: &[MIB_UDP6ROW_OWNER_PID] =
        unsafe { rows::<MIB_UDP6TABLE_OWNER_PID, _>(&buf, off, table.dwNumEntries) };
    for r in list {
        out.push(Conn {
            proto: "UDP",
            local: v6(r.ucLocalAddr),
            local_port: port(r.dwLocalPort),
            remote: None,
            remote_port: 0,
            state: None,
            pid: r.dwOwningPid,
        });
    }
    Ok(())
}

/// 모든 테이블을 한 번 읽어 연결 목록을 만든다.
fn snapshot() -> Vec<Conn> {
    let mut v = Vec::with_capacity(512);
    for (name, res) in [
        ("tcp4", collect_tcp4(&mut v)),
        ("tcp6", collect_tcp6(&mut v)),
        ("udp4", collect_udp4(&mut v)),
        ("udp6", collect_udp6(&mut v)),
    ] {
        if let Err(code) = res {
            eprintln!("[warn] {name} 테이블 읽기 실패, Win32 오류 {code}");
        }
    }
    v
}

/// PID → 실행 파일 전체 경로. 실패 시 None.
/// PROCESS_QUERY_LIMITED_INFORMATION 은 보호 프로세스에도 대체로 허용되지만,
/// 일반 권한에서는 다른 사용자 프로세스에 거부될 수 있다.
fn process_path(pid: u32) -> Option<String> {
    if pid == 0 {
        return Some("[System Idle]".into());
    }
    if pid == 4 {
        return Some("[System]".into());
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// 프로세스 이름 캐시. PID 재사용 대비로 60초마다 비운다.
struct ProcCache {
    map: HashMap<u32, String>,
    born: Instant,
}

impl ProcCache {
    fn new() -> Self {
        Self { map: HashMap::new(), born: Instant::now() }
    }
    fn name(&mut self, pid: u32) -> String {
        if self.born.elapsed() > Duration::from_secs(60) {
            self.map.clear();
            self.born = Instant::now();
        }
        self.map
            .entry(pid)
            .or_insert_with(|| {
                process_path(pid)
                    .map(|p| {
                        // 경로에서 파일 이름만 표시, 전체 경로는 2단계 DB 에 저장
                        p.rsplit(['\\', '/']).next().unwrap_or(&p).to_string()
                    })
                    .unwrap_or_else(|| "<access denied>".into())
            })
            .clone()
    }
}

fn fmt_conn(c: &Conn, cache: &mut ProcCache) -> String {
    let remote = match c.remote {
        Some(ip) => format!("{}:{}", ip, c.remote_port),
        None => "*".to_string(),
    };
    let state = c.state.map(tcp_state_name).unwrap_or("-");
    format!(
        "{:<4} {:<40} {:<40} {:<10} {:>6} {}",
        c.proto,
        format!("{}:{}", c.local, c.local_port),
        remote,
        state,
        c.pid,
        cache.name(c.pid)
    )
}

fn main() {
    println!("PoC 1 — 프로세스별 연결 수집기 (Ctrl+C 로 종료)");
    println!("{:<4} {:<40} {:<40} {:<10} {:>6} {}", "PROTO", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS");
    println!("{}", "-".repeat(120));

    let mut cache = ProcCache::new();
    let mut prev: HashSet<Conn> = HashSet::new();
    let mut first = true;

    loop {
        let t0 = Instant::now();
        let now: HashSet<Conn> = snapshot().into_iter().collect();

        if first {
            // 첫 스냅샷은 전체 출력
            let mut all: Vec<&Conn> = now.iter().collect();
            all.sort_by_key(|c| (c.pid, c.proto, c.local_port));
            for c in all {
                println!("      {}", fmt_conn(c, &mut cache));
            }
            first = false;
        } else {
            // 이후에는 변화분만 출력: NEW(신규) / END(종료)
            let mut added: Vec<&Conn> = now.difference(&prev).collect();
            let mut gone: Vec<&Conn> = prev.difference(&now).collect();
            added.sort_by_key(|c| (c.pid, c.proto, c.local_port));
            gone.sort_by_key(|c| (c.pid, c.proto, c.local_port));
            for c in gone {
                println!("END   {}", fmt_conn(c, &mut cache));
            }
            for c in added {
                println!("NEW   {}", fmt_conn(c, &mut cache));
            }
        }

        let elapsed = t0.elapsed();
        // 1초 주기 통계: 수집에 걸린 시간을 찍어 CPU 부담을 가늠한다
        eprintln!(
            "[stat] connections={} collect_ms={:.1}",
            now.len(),
            elapsed.as_secs_f64() * 1000.0
        );

        prev = now;
        if elapsed < Duration::from_secs(1) {
            thread::sleep(Duration::from_secs(1) - elapsed);
        }
    }
}
