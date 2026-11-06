//! ACL 정책 관리(2026-11-06): 네트워크 인터페이스 목록 — 정책 화면의 "인터페이스 선택"용.
//! GetIfTable2(별칭·설명·상태) + GetUnicastIpAddressTable(이 PC 주소). 읽기만.
//! 필터 가상 인터페이스("…-WFP Native MAC Layer LightWeight Filter-0000" 등)와 루프백은 뺀다.
//! 정책에는 별칭을 저장하고, 적용할 때 policy::wfp 가 LUID 로 바꾼다(재부팅 뒤에도 별칭은 그대로).

use std::net::{Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, GetUnicastIpAddressTable, MIB_IF_TABLE2, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

/// 인터페이스 종류 번호(IANA ifType)
const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
/// MIB_IF_ROW2.InterfaceAndOperStatusFlags 의 FilterInterface 비트
const FLAG_FILTER: u8 = 0b10;
/// IfOperStatusUp
const OPER_UP: i32 = 1;

fn utf16z(buf: &[u16]) -> String {
    let n = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..n])
}

pub fn interfaces() -> Result<Vec<crate::host::NetIf>, String> {
    let mut t: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: 출력 포인터는 지역 변수, 끝에 FreeMibTable
    let rc = unsafe { GetIfTable2(&mut t) };
    if rc != 0 || t.is_null() {
        return Err(format!("GetIfTable2 {rc}"));
    }
    let mut out: Vec<(u64, crate::host::NetIf)> = Vec::new();
    // SAFETY: NumEntries 개의 행이 Table 에서 이어진다
    unsafe {
        let n = (*t).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*t).Table.as_ptr(), n);
        for r in rows {
            if r.Type == IF_TYPE_SOFTWARE_LOOPBACK
                || (r.InterfaceAndOperStatusFlags._bitfield & FLAG_FILTER) != 0
            {
                continue;
            }
            let alias = utf16z(&r.Alias);
            if alias.is_empty() {
                continue;
            }
            out.push((
                r.InterfaceLuid.Value,
                crate::host::NetIf {
                    alias,
                    description: utf16z(&r.Description),
                    up: r.OperStatus == OPER_UP,
                    addrs: Vec::new(),
                },
            ));
        }
        FreeMibTable(t as *const _);
    }
    // 이 PC 주소를 인터페이스에 붙인다
    let mut a: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: 위와 같음
    let rc = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut a) };
    if rc == 0 && !a.is_null() {
        // SAFETY: NumEntries 개의 행. 주소 union 은 si_family 로 가른다
        unsafe {
            let n = (*a).NumEntries as usize;
            let rows = std::slice::from_raw_parts((*a).Table.as_ptr(), n);
            for r in rows {
                let luid = r.InterfaceLuid.Value;
                let fam = r.Address.si_family;
                let text = if fam == AF_INET {
                    Ipv4Addr::from(u32::from_be(r.Address.Ipv4.sin_addr.S_un.S_addr)).to_string()
                } else if fam == AF_INET6 {
                    Ipv6Addr::from(r.Address.Ipv6.sin6_addr.u.Byte).to_string()
                } else {
                    continue;
                };
                if let Some((_, i)) = out.iter_mut().find(|(l, _)| *l == luid) {
                    i.addrs.push(format!("{text}/{}", r.OnLinkPrefixLength));
                }
            }
            FreeMibTable(a as *const _);
        }
    }
    let mut v: Vec<crate::host::NetIf> = out.into_iter().map(|(_, i)| i).collect();
    // 켜진 것 먼저, 그다음 이름순
    v.sort_by(|x, y| y.up.cmp(&x.up).then(x.alias.cmp(&y.alias)));
    v.truncate(64);
    Ok(v)
}
