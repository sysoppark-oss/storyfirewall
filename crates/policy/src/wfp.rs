//! WFP 사용자 모드 래퍼 (fwpuclnt). 차단 필터만.
//!
//! 세션은 비동적(기본)이라 프로세스가 끝나도 필터가 남는다. 영구 플래그로 재부팅도 넘긴다.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{FILETIME, FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use crate::spec::{Action, BlockSpec, Direction};
use crate::{PolicyError, Result};

/// 고정 GUID (제품 식별자). 바꾸면 이전 설치의 필터를 못 찾는다.
pub const PROVIDER_KEY: GUID = GUID::from_u128(0x5f1a2b3c_4d5e_4f60_8172_839405a6b7c8);
pub const SUBLAYER_KEY: GUID = GUID::from_u128(0x5f1a2b3c_4d5e_4f60_8172_839405a6b7c9);
/// Sublayer weight: Defender(0x2000~0x7FFF 추정)보다 높게. 차단은 어느 Sublayer 든 이기므로 값 자체는 결정적이지 않다.
pub const SUBLAYER_WEIGHT: u16 = 0x8000;
/// 우리가 쓰는 계층. 열거·구독 템플릿은 layerKey 가 필수(run-1: 비우면 FWP_E_LAYER_NOT_FOUND)라 계층마다 돈다.
pub const LAYERS: [GUID; 4] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
];

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check(rc: u32, what: &'static str) -> Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(PolicyError::Wfp(rc, what))
    }
}

#[derive(Clone, Copy)]
enum SubKind {
    Filter,
    SubLayer,
    Provider,
}

pub struct Engine {
    h: HANDLE,
    subs: Vec<(SubKind, HANDLE)>,
}

/// 삭제 알림 (콜백 → 메인). 콜백은 BFE 스레드에서 오므로 전역 큐에 넣는다.
static DELETED_FILTERS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static SUBLAYER_DELETED: AtomicBool = AtomicBool::new(false);
static PROVIDER_DELETED: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn on_filter_change(_ctx: *mut core::ffi::c_void, change: *const FWPM_FILTER_CHANGE0) {
    if change.is_null() {
        return;
    }
    if (*change).changeType == FWPM_CHANGE_DELETE {
        DELETED_FILTERS.lock().unwrap().push((*change).filterId);
    }
}
unsafe extern "system" fn on_sublayer_change(_ctx: *mut core::ffi::c_void, change: *const FWPM_SUBLAYER_CHANGE0) {
    if !change.is_null() && (*change).changeType == FWPM_CHANGE_DELETE {
        SUBLAYER_DELETED.store(true, Ordering::Relaxed);
    }
}
unsafe extern "system" fn on_provider_change(_ctx: *mut core::ffi::c_void, change: *const FWPM_PROVIDER_CHANGE0) {
    if !change.is_null() && (*change).changeType == FWPM_CHANGE_DELETE {
        PROVIDER_DELETED.store(true, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
pub struct DropEvent {
    pub ts: i64,
    pub filter_id: u64,
    pub layer_id: u16,
    pub protocol: u8,
    pub remote_v4: Option<std::net::Ipv4Addr>,
    pub remote_port: u16,
    pub app_id: String,
}

impl Engine {
    /// 비동적 세션으로 연다 (영구 객체를 만들려면 필수)
    pub fn open() -> Result<Self> {
        let mut h: HANDLE = std::ptr::null_mut();
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.txnWaitTimeoutInMSec = 5_000;
        let name = wide("StoryFirewall policy");
        session.displayData.name = name.as_ptr() as *mut u16;
        let rc = unsafe { FwpmEngineOpen0(std::ptr::null(), RPC_C_AUTHN_WINNT, std::ptr::null(), &session, &mut h) };
        check(rc, "FwpmEngineOpen0")?;
        Ok(Self { h, subs: Vec::new() })
    }

    /// Provider·Sublayer 가 없으면 만든다 (영구). 이미 있으면 FWP_E_ALREADY_EXISTS 를 무시.
    pub fn ensure_provider_sublayer(&self) -> Result<()> {
        let pname = wide("StoryFirewall");
        let pdesc = wide("Story Firewall block-only provider");
        let mut p: FWPM_PROVIDER0 = unsafe { std::mem::zeroed() };
        p.providerKey = PROVIDER_KEY;
        p.displayData.name = pname.as_ptr() as *mut u16;
        p.displayData.description = pdesc.as_ptr() as *mut u16;
        p.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        let rc = unsafe { FwpmProviderAdd0(self.h, &p, std::ptr::null_mut()) };
        if rc != 0 && rc != FWP_E_ALREADY_EXISTS as u32 {
            return Err(PolicyError::Wfp(rc, "FwpmProviderAdd0"));
        }
        let sname = wide("StoryFirewall block sublayer");
        let mut s: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        s.subLayerKey = SUBLAYER_KEY;
        s.displayData.name = sname.as_ptr() as *mut u16;
        s.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        let mut pk = PROVIDER_KEY;
        s.providerKey = &mut pk;
        s.weight = SUBLAYER_WEIGHT;
        let rc = unsafe { FwpmSubLayerAdd0(self.h, &s, std::ptr::null_mut()) };
        if rc != 0 && rc != FWP_E_ALREADY_EXISTS as u32 {
            return Err(PolicyError::Wfp(rc, "FwpmSubLayerAdd0"));
        }
        Ok(())
    }

    /// 명세 하나를 한 계층의 필터로. 같은 필드의 조건 여러 개는 OR (6차 검증 Q1). 트랜잭션 안에서 호출된다.
    fn add_one(&self, spec: &BlockSpec, layer: GUID, v6: bool) -> Result<u64> {
        // 조건 재료는 호출이 끝날 때까지 살아 있어야 한다
        let mut conds: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
        let mut app_blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        let mut ranges: Vec<Box<FWP_RANGE0>> = Vec::new();
        let mut v6masks: Vec<Box<FWP_V6_ADDR_AND_MASK>> = Vec::new();
        if let Some(app) = &spec.app_path {
            let w = wide(app);
            let rc = unsafe { FwpmGetAppIdFromFileName0(w.as_ptr(), &mut app_blob) };
            check(rc, "FwpmGetAppIdFromFileName0")?;
            let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
            c.fieldKey = FWPM_CONDITION_ALE_APP_ID;
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
            c.conditionValue.Anonymous.byteBlob = app_blob;
            conds.push(c);
        }
        if !v6 {
            for r in &spec.remote_v4 {
                let mut rg: Box<FWP_RANGE0> = Box::new(unsafe { std::mem::zeroed() });
                rg.valueLow.r#type = FWP_UINT32;
                rg.valueLow.Anonymous.uint32 = u32::from(r.lo);
                rg.valueHigh.r#type = FWP_UINT32;
                rg.valueHigh.Anonymous.uint32 = u32::from(r.hi);
                let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
                c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                c.matchType = FWP_MATCH_RANGE;
                c.conditionValue.r#type = FWP_RANGE_TYPE;
                c.conditionValue.Anonymous.rangeValue = &mut *rg;
                conds.push(c);
                ranges.push(rg);
            }
        } else {
            for p in &spec.remote_v6 {
                let mut m: Box<FWP_V6_ADDR_AND_MASK> = Box::new(unsafe { std::mem::zeroed() });
                m.addr = p.addr.octets();
                m.prefixLength = p.prefix;
                let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
                c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                c.matchType = FWP_MATCH_EQUAL;
                c.conditionValue.r#type = FWP_V6_ADDR_MASK;
                c.conditionValue.Anonymous.v6AddrMask = &mut *m;
                conds.push(c);
                v6masks.push(m);
            }
        }
        let port_cond = |field: GUID, pr: &crate::spec::PortRange, conds: &mut Vec<FWPM_FILTER_CONDITION0>, ranges: &mut Vec<Box<FWP_RANGE0>>| {
            let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
            c.fieldKey = field;
            if pr.lo == pr.hi {
                c.matchType = FWP_MATCH_EQUAL;
                c.conditionValue.r#type = FWP_UINT16;
                c.conditionValue.Anonymous.uint16 = pr.lo;
            } else {
                let mut rg: Box<FWP_RANGE0> = Box::new(unsafe { std::mem::zeroed() });
                rg.valueLow.r#type = FWP_UINT16;
                rg.valueLow.Anonymous.uint16 = pr.lo;
                rg.valueHigh.r#type = FWP_UINT16;
                rg.valueHigh.Anonymous.uint16 = pr.hi;
                c.matchType = FWP_MATCH_RANGE;
                c.conditionValue.r#type = FWP_RANGE_TYPE;
                c.conditionValue.Anonymous.rangeValue = &mut *rg;
                ranges.push(rg);
            }
            conds.push(c);
        };
        for pr in &spec.remote_ports {
            port_cond(FWPM_CONDITION_IP_REMOTE_PORT, pr, &mut conds, &mut ranges);
        }
        for pr in &spec.local_ports {
            port_cond(FWPM_CONDITION_IP_LOCAL_PORT, pr, &mut conds, &mut ranges);
        }
        for proto in &spec.protocols {
            let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
            c.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue.r#type = FWP_UINT8;
            c.conditionValue.Anonymous.uint8 = *proto;
            conds.push(c);
        }
        let name = wide(&format!("StoryFirewall {}: {}", if spec.action == Action::Permit { "permit" } else { "block" }, spec.name));
        let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        f.displayData.name = name.as_ptr() as *mut u16;
        f.flags = FWPM_FILTER_FLAG_PERSISTENT;
        let mut pk = PROVIDER_KEY;
        f.providerKey = &mut pk;
        f.layerKey = layer;
        f.subLayerKey = SUBLAYER_KEY;
        // permit 은 같은 Sublayer 의 block 보다 높은 weight 가 필요하다 (6차 검증 Q2). block 은 BFE 자동.
        let mut weight_box: Box<u64> = Box::new(0);
        match (spec.action, spec.weight) {
            (Action::Permit, w) => {
                *weight_box = w.unwrap_or(0xF000_0000_0000_0000);
                f.weight.r#type = FWP_UINT64;
                f.weight.Anonymous.uint64 = &mut *weight_box;
            }
            (Action::Block, Some(w)) => {
                *weight_box = w;
                f.weight.r#type = FWP_UINT64;
                f.weight.Anonymous.uint64 = &mut *weight_box;
            }
            (Action::Block, None) => f.weight.r#type = FWP_EMPTY,
        }
        f.numFilterConditions = conds.len() as u32;
        f.filterCondition = conds.as_mut_ptr();
        f.action.r#type = if spec.action == Action::Permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK };
        let mut id: u64 = 0;
        let rc = unsafe { FwpmFilterAdd0(self.h, &f, std::ptr::null_mut(), &mut id) };
        if !app_blob.is_null() {
            unsafe { FwpmFreeMemory0(&mut app_blob as *mut _ as *mut *mut core::ffi::c_void) };
        }
        drop(ranges);
        drop(v6masks);
        check(rc, "FwpmFilterAdd0")?;
        Ok(id)
    }

    /// 정책 1건 = 트랜잭션 1건. 돌려주는 ID 들은 호출자가 저장한다.
    pub fn apply(&self, specs: &[BlockSpec]) -> Result<Vec<(u64, BlockSpec)>> {
        check(unsafe { FwpmTransactionBegin0(self.h, 0) }, "FwpmTransactionBegin0")?;
        let mut out = Vec::new();
        let result: Result<()> = (|| {
            for s in specs {
                let (l4, l6) = match s.direction {
                    Direction::Out => (FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6),
                    Direction::In => (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6),
                };
                if s.wants_v4() {
                    out.push((self.add_one(s, l4, false)?, s.clone()));
                }
                if s.wants_v6() {
                    out.push((self.add_one(s, l6, true)?, s.clone()));
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                check(unsafe { FwpmTransactionCommit0(self.h) }, "FwpmTransactionCommit0")?;
                Ok(out)
            }
            Err(e) => {
                unsafe { FwpmTransactionAbort0(self.h) };
                Err(e)
            }
        }
    }

    /// 한 트랜잭션에서 `remove` 를 지우고 `add` 를 넣는다 (11차 Q1, engine::WfpBackend::replace 의 Windows 구현).
    /// 실패하면 abort — 지운 것도 넣은 것도 남지 않는다. 명세 하나가 V4·V6 두 필터가 될 수 있으므로
    /// 돌려주는 목록은 (필터 ID, 명세) 쌍이다.
    pub fn replace(&self, remove: &[u64], add: &[BlockSpec]) -> Result<Vec<(u64, BlockSpec)>> {
        check(unsafe { FwpmTransactionBegin0(self.h, 0) }, "FwpmTransactionBegin0")?;
        let result: Result<Vec<(u64, BlockSpec)>> = (|| {
            for id in remove {
                let rc = unsafe { FwpmFilterDeleteById0(self.h, *id) };
                if rc != 0 && rc != FWP_E_FILTER_NOT_FOUND as u32 {
                    return Err(PolicyError::Wfp(rc, "FwpmFilterDeleteById0"));
                }
            }
            let mut out = Vec::new();
            for s in add {
                let (l4, l6) = match s.direction {
                    Direction::Out => (FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6),
                    Direction::In => (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6),
                };
                if s.wants_v4() {
                    out.push((self.add_one(s, l4, false)?, s.clone()));
                }
                if s.wants_v6() {
                    out.push((self.add_one(s, l6, true)?, s.clone()));
                }
            }
            Ok(out)
        })();
        match result {
            Ok(out) => {
                check(unsafe { FwpmTransactionCommit0(self.h) }, "FwpmTransactionCommit0")?;
                Ok(out)
            }
            Err(e) => {
                unsafe { FwpmTransactionAbort0(self.h) };
                Err(e)
            }
        }
    }

    pub fn delete(&self, ids: &[u64]) -> Result<()> {
        check(unsafe { FwpmTransactionBegin0(self.h, 0) }, "FwpmTransactionBegin0")?;
        for id in ids {
            let rc = unsafe { FwpmFilterDeleteById0(self.h, *id) };
            if rc != 0 && rc != FWP_E_FILTER_NOT_FOUND as u32 {
                unsafe { FwpmTransactionAbort0(self.h) };
                return Err(PolicyError::Wfp(rc, "FwpmFilterDeleteById0"));
            }
        }
        check(unsafe { FwpmTransactionCommit0(self.h) }, "FwpmTransactionCommit0")
    }

    /// 우리 Provider 소속 필터 (id, 이름, 계층) — 4개 계층을 차례로 열거
    pub fn list_ours(&self) -> Result<Vec<(u64, String, GUID)>> {
        Ok(self.list_full()?.into_iter().map(|(id, name, layer, _)| (id, name, layer)).collect())
    }

    /// 우리 필터의 (id, filterKey). filterKey 는 넣을 때 0 으로 두어 BFE 가 만든 GUID — 영구 필터와 함께 저장된다.
    /// id 는 문서상 "runtime identifier" 라 BFE 재시작·재부팅 뒤 바뀔 수 있다(추측) — 재시작 대조는 키로 한다
    pub fn list_keys(&self) -> Result<Vec<(u64, String)>> {
        Ok(self.list_full()?.into_iter().map(|(id, _, _, key)| (id, guid_text(&key))).collect())
    }

    fn list_full(&self) -> Result<Vec<(u64, String, GUID, GUID)>> {
        let mut out = Vec::new();
        for layer in LAYERS {
            self.list_layer(layer, &mut out)?;
        }
        Ok(out)
    }

    fn list_layer(&self, layer: GUID, out: &mut Vec<(u64, String, GUID, GUID)>) -> Result<()> {
        let mut tmpl: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        let mut pk = PROVIDER_KEY;
        tmpl.providerKey = &mut pk;
        tmpl.layerKey = layer;
        tmpl.enumType = FWP_FILTER_ENUM_OVERLAPPING;
        tmpl.actionMask = 0xFFFF_FFFF;
        let mut eh: HANDLE = std::ptr::null_mut();
        check(unsafe { FwpmFilterCreateEnumHandle0(self.h, &tmpl, &mut eh) }, "FwpmFilterCreateEnumHandle0")?;
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut n: u32 = 0;
            let rc = unsafe { FwpmFilterEnum0(self.h, eh, 100, &mut entries, &mut n) };
            if rc != 0 || n == 0 {
                break;
            }
            for i in 0..n as usize {
                let f = unsafe { &**entries.add(i) };
                let name = if f.displayData.name.is_null() {
                    String::new()
                } else {
                    let mut len = 0;
                    unsafe {
                        while *f.displayData.name.add(len) != 0 {
                            len += 1;
                        }
                        String::from_utf16_lossy(std::slice::from_raw_parts(f.displayData.name, len))
                    }
                };
                out.push((f.filterId, name, f.layerKey, f.filterKey));
            }
            unsafe { FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut core::ffi::c_void) };
            if n < 100 {
                break;
            }
        }
        unsafe { FwpmFilterDestroyEnumHandle0(self.h, eh) };
        Ok(())
    }

    /// 필터·Sublayer·Provider 삭제 구독 (자가 치유). 필터 구독은 계층마다 하나.
    pub fn subscribe_deletes(&mut self) -> Result<()> {
        for layer in LAYERS {
            let mut tmpl: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
            let mut pk = PROVIDER_KEY;
            tmpl.providerKey = &mut pk;
            tmpl.layerKey = layer;
            tmpl.enumType = FWP_FILTER_ENUM_OVERLAPPING;
            tmpl.actionMask = 0xFFFF_FFFF;
            let mut sub: FWPM_FILTER_SUBSCRIPTION0 = unsafe { std::mem::zeroed() };
            sub.enumTemplate = &mut tmpl;
            sub.flags = FWPM_SUBSCRIPTION_FLAG_NOTIFY_ON_DELETE;
            let mut ch: HANDLE = std::ptr::null_mut();
            check(unsafe { FwpmFilterSubscribeChanges0(self.h, &sub, Some(on_filter_change), std::ptr::null(), &mut ch) }, "FwpmFilterSubscribeChanges0")?;
            self.subs.push((SubKind::Filter, ch));
        }

        let mut st: FWPM_SUBLAYER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        let mut pk2 = PROVIDER_KEY;
        st.providerKey = &mut pk2;
        let mut ssub: FWPM_SUBLAYER_SUBSCRIPTION0 = unsafe { std::mem::zeroed() };
        ssub.enumTemplate = &mut st;
        ssub.flags = FWPM_SUBSCRIPTION_FLAG_NOTIFY_ON_DELETE;
        let mut ch2: HANDLE = std::ptr::null_mut();
        check(unsafe { FwpmSubLayerSubscribeChanges0(self.h, &ssub, Some(on_sublayer_change), std::ptr::null(), &mut ch2) }, "FwpmSubLayerSubscribeChanges0")?;
        self.subs.push((SubKind::SubLayer, ch2));

        let mut pt: FWPM_PROVIDER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        let mut psub: FWPM_PROVIDER_SUBSCRIPTION0 = unsafe { std::mem::zeroed() };
        psub.enumTemplate = &mut pt;
        psub.flags = FWPM_SUBSCRIPTION_FLAG_NOTIFY_ON_DELETE;
        let mut ch3: HANDLE = std::ptr::null_mut();
        check(unsafe { FwpmProviderSubscribeChanges0(self.h, &psub, Some(on_provider_change), std::ptr::null(), &mut ch3) }, "FwpmProviderSubscribeChanges0")?;
        self.subs.push((SubKind::Provider, ch3));
        Ok(())
    }

    /// 콜백이 모아 둔 삭제 알림을 꺼낸다
    pub fn take_deleted(&self) -> (Vec<u64>, bool, bool) {
        let ids = std::mem::take(&mut *DELETED_FILTERS.lock().unwrap());
        (ids, SUBLAYER_DELETED.swap(false, Ordering::Relaxed), PROVIDER_DELETED.swap(false, Ordering::Relaxed))
    }

    /// 차단 이벤트 수집 켜기 (F23)
    pub fn enable_net_events(&self) -> Result<()> {
        let mut v: FWP_VALUE0 = unsafe { std::mem::zeroed() };
        v.r#type = FWP_UINT32;
        v.Anonymous.uint32 = 1;
        check(unsafe { FwpmEngineSetOption0(self.h, FWPM_ENGINE_COLLECT_NET_EVENTS, &v) }, "FwpmEngineSetOption0")
    }

    /// since(FILETIME) 이후의 CLASSIFY_DROP 이벤트, 최대 200건 (5차 검증 Q5)
    pub fn drops_since(&self, since: i64) -> Result<Vec<DropEvent>> {
        let mut tmpl: FWPM_NET_EVENT_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        tmpl.startTime = FILETIME { dwLowDateTime: since as u32, dwHighDateTime: (since >> 32) as u32 };
        let end = i64::MAX;
        tmpl.endTime = FILETIME { dwLowDateTime: end as u32, dwHighDateTime: (end >> 32) as u32 };
        let mut eh: HANDLE = std::ptr::null_mut();
        check(unsafe { FwpmNetEventCreateEnumHandle0(self.h, &tmpl, &mut eh) }, "FwpmNetEventCreateEnumHandle0")?;
        let mut entries: *mut *mut FWPM_NET_EVENT1 = std::ptr::null_mut();
        let mut n: u32 = 0;
        let rc = unsafe { FwpmNetEventEnum1(self.h, eh, 200, &mut entries, &mut n) };
        let mut out = Vec::new();
        if rc == 0 {
            for i in 0..n as usize {
                let e = unsafe { &**entries.add(i) };
                if e.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
                    continue;
                }
                let d = unsafe { &*e.Anonymous.classifyDrop };
                let h = &e.header;
                let ts = ((h.timeStamp.dwHighDateTime as i64) << 32) | h.timeStamp.dwLowDateTime as i64;
                let remote_v4 = if h.ipVersion == FWP_IP_VERSION_V4 {
                    Some(std::net::Ipv4Addr::from(unsafe { h.Anonymous2.remoteAddrV4 }))
                } else {
                    None
                };
                let app_id = if h.appId.size >= 2 && !h.appId.data.is_null() {
                    let u16s = unsafe { std::slice::from_raw_parts(h.appId.data as *const u16, (h.appId.size / 2) as usize) };
                    String::from_utf16_lossy(u16s).trim_end_matches('\0').to_string()
                } else {
                    String::new()
                };
                out.push(DropEvent { ts, filter_id: d.filterId, layer_id: d.layerId, protocol: h.ipProtocol, remote_v4, remote_port: h.remotePort, app_id });
            }
            unsafe { FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut core::ffi::c_void) };
        }
        unsafe { FwpmNetEventDestroyEnumHandle0(self.h, eh) };
        if rc != 0 {
            return Err(PolicyError::Wfp(rc, "FwpmNetEventEnum1"));
        }
        Ok(out)
    }

    /// 모든 우리 필터 → Sublayer → Provider 삭제 (제거/정리)
    pub fn remove_all(&self) -> Result<usize> {
        let ours = self.list_ours()?;
        let ids: Vec<u64> = ours.iter().map(|(id, _, _)| *id).collect();
        if !ids.is_empty() {
            self.delete(&ids)?;
        }
        let rc = unsafe { FwpmSubLayerDeleteByKey0(self.h, &SUBLAYER_KEY) };
        if rc != 0 && rc != FWP_E_SUBLAYER_NOT_FOUND as u32 {
            return Err(PolicyError::Wfp(rc, "FwpmSubLayerDeleteByKey0"));
        }
        let rc = unsafe { FwpmProviderDeleteByKey0(self.h, &PROVIDER_KEY) };
        if rc != 0 && rc != FWP_E_PROVIDER_NOT_FOUND as u32 {
            return Err(PolicyError::Wfp(rc, "FwpmProviderDeleteByKey0"));
        }
        Ok(ids.len())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        for (k, s) in self.subs.drain(..) {
            unsafe {
                match k {
                    SubKind::Filter => FwpmFilterUnsubscribeChanges0(self.h, s),
                    SubKind::SubLayer => FwpmSubLayerUnsubscribeChanges0(self.h, s),
                    SubKind::Provider => FwpmProviderUnsubscribeChanges0(self.h, s),
                }
            };
        }
        unsafe { FwpmEngineClose0(self.h) };
    }
}

/// (id → 명세) 보관 — 재등록용
pub type FilterMap = HashMap<u64, BlockSpec>;

/// GUID → "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"(소문자)
pub fn guid_text(g: &GUID) -> String {
    let d = g.data4;
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1, g.data2, g.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}
