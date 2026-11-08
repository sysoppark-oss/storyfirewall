//! 연결 테이블 1초 폴링 (ETW 누락 대조 + 리스닝 포트). PoC 1 코드를 옮겨 왔다.
//!
//! ETW 가 못 본 ESTABLISHED 아웃바운드 연결이 테이블에 있으면 `conntable` 출처의 Connect 로 보충하고
//! 누락 수를 센다. 리스닝 포트는 1초 스냅샷으로 유지한다 (F4).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, SetTcpEntry, MIB_TCP6ROW_OWNER_PID,
    MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, MIB_TCP_STATE_DELETE_TCB, MIB_UDP6ROW_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TcpConn {
    pub local: IpAddr,
    pub lport: u16,
    pub remote: IpAddr,
    pub rport: u16,
    pub state: u32,
    pub pid: u32,
}

pub const MIB_TCP_STATE_ESTAB: u32 = 5;
pub const MIB_TCP_STATE_LISTEN: u32 = 2;

/// 리스닝 소켓 하나 (F4). UDP 는 상태가 없어 바인드된 소켓 전부가 "듣는 중"이다.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Listener {
    pub proto: &'static str,
    pub local: IpAddr,
    pub lport: u16,
    pub pid: u32,
}

/// TCP LISTEN + UDP 바인드 (IPv4·IPv6)
pub fn listeners() -> Result<Vec<Listener>, u32> {
    let mut out: Vec<Listener> = tcp_connections()?
        .into_iter()
        .filter(|c| c.state == MIB_TCP_STATE_LISTEN)
        .map(|c| Listener {
            proto: "tcp",
            local: c.local,
            lport: c.lport,
            pid: c.pid,
        })
        .collect();
    let buf = fetch_table(|p, size| unsafe {
        GetExtendedUdpTable(p as _, size, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
    })?;
    if !buf.is_empty() {
        let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let off = std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table);
        let rows: &[MIB_UDPROW_OWNER_PID] = unsafe {
            std::slice::from_raw_parts(
                buf.as_ptr().add(off) as *const MIB_UDPROW_OWNER_PID,
                table.dwNumEntries as usize,
            )
        };
        for r in rows {
            out.push(Listener {
                proto: "udp",
                local: IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),
                lport: port(r.dwLocalPort),
                pid: r.dwOwningPid,
            });
        }
    }
    let buf = fetch_table(|p, size| unsafe {
        GetExtendedUdpTable(p as _, size, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
    })?;
    if !buf.is_empty() {
        let table = unsafe { &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
        let off = std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table);
        let rows: &[MIB_UDP6ROW_OWNER_PID] = unsafe {
            std::slice::from_raw_parts(
                buf.as_ptr().add(off) as *const MIB_UDP6ROW_OWNER_PID,
                table.dwNumEntries as usize,
            )
        };
        for r in rows {
            out.push(Listener {
                proto: "udp",
                local: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                lport: port(r.dwLocalPort),
                pid: r.dwOwningPid,
            });
        }
    }
    Ok(out)
}

#[inline]
fn port(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

fn fetch_table<F>(mut call: F) -> Result<Vec<u8>, u32>
where
    F: FnMut(*mut u8, &mut u32) -> u32,
{
    let mut size: u32 = 0;
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..8 {
        let rc = call(buf.as_mut_ptr(), &mut size);
        if rc == NO_ERROR {
            if (size as usize) > buf.capacity() {
                return Ok(Vec::new());
            }
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

pub fn tcp_connections() -> Result<Vec<TcpConn>, u32> {
    let mut out = Vec::new();
    // IPv4
    let buf = fetch_table(|p, size| unsafe {
        GetExtendedTcpTable(p as _, size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    })?;
    if !buf.is_empty() {
        let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let off = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
        let rows: &[MIB_TCPROW_OWNER_PID] = unsafe {
            std::slice::from_raw_parts(
                buf.as_ptr().add(off) as *const MIB_TCPROW_OWNER_PID,
                table.dwNumEntries as usize,
            )
        };
        for r in rows {
            out.push(TcpConn {
                local: IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes())),
                lport: port(r.dwLocalPort),
                remote: IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes())),
                rport: port(r.dwRemotePort),
                state: r.dwState,
                pid: r.dwOwningPid,
            });
        }
    }
    // IPv6
    let buf = fetch_table(|p, size| unsafe {
        GetExtendedTcpTable(p as _, size, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    })?;
    if !buf.is_empty() {
        let table = unsafe { &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        let off = std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
        let rows: &[MIB_TCP6ROW_OWNER_PID] = unsafe {
            std::slice::from_raw_parts(
                buf.as_ptr().add(off) as *const MIB_TCP6ROW_OWNER_PID,
                table.dwNumEntries as usize,
            )
        };
        for r in rows {
            out.push(TcpConn {
                local: IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                lport: port(r.dwLocalPort),
                remote: IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)),
                rport: port(r.dwRemotePort),
                state: r.dwState,
                pid: r.dwOwningPid,
            });
        }
    }
    Ok(out)
}

/// 이번 폴링에서 새로 본 ESTABLISHED 연결 중 ETW 가 못 본 것
pub fn missed_by_etw(
    conns: &[TcpConn],
    seen_by_etw: &HashSet<(u32, String, u16)>,
    already_reported: &mut HashSet<(u32, String, u16)>,
) -> Vec<TcpConn> {
    let mut out = Vec::new();
    for c in conns {
        if c.state != MIB_TCP_STATE_ESTAB || c.pid == 0 || c.remote.is_loopback() {
            continue;
        }
        let key = (c.pid, c.remote.to_string(), c.rport);
        if seen_by_etw.contains(&key) || already_reported.contains(&key) {
            continue;
        }
        already_reported.insert(key);
        out.push(c.clone());
    }
    out
}

/// IPv4 TCP 연결 하나 끊기(UI 명세 4판 3-4). SetTcpEntry 에 MIB_TCP_STATE_DELETE_TCB 를 주면 그 연결이 RST 로 끝난다.
/// 관리자 권한 필요(Microsoft Learn: SetTcpEntry — 바꿀 수 있는 상태는 DELETE_TCB 하나, IPv6 판 없음).
/// 주소는 네트워크 바이트 순서(읽을 때와 같은 표현: 주소는 octets 그대로, 포트는 아래 16비트 big-endian)
pub fn kill_tcp_v4(local: Ipv4Addr, lport: u16, remote: Ipv4Addr, rport: u16) -> Result<(), u32> {
    let row = MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 {
            dwState: MIB_TCP_STATE_DELETE_TCB as u32,
        },
        dwLocalAddr: u32::from_ne_bytes(local.octets()),
        dwLocalPort: lport.to_be() as u32,
        dwRemoteAddr: u32::from_ne_bytes(remote.octets()),
        dwRemotePort: rport.to_be() as u32,
    };
    let r = unsafe { SetTcpEntry(&row) };
    if r == NO_ERROR {
        Ok(())
    } else {
        Err(r)
    }
}
