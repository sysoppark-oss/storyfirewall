//! ETW 세션 통계 (명세 4판 2-2 / 자체 재검토 D)
//!
//! ferrisetw 는 EventsLost 를 노출하지 않으므로 `ControlTraceW(EVENT_TRACE_CONTROL_QUERY)` 로 직접 읽는다.
//! 실시간 세션에서 소비가 느리면 RealTimeBuffersLost·EventsLost 가 올라간다. 둘 다 0 이어야 F2 ±5% 를 주장할 수 있다.

use windows_sys::Win32::System::Diagnostics::Etw::{
    ControlTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_PROPERTIES,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct SessionStats {
    pub events_lost: u32,
    pub realtime_buffers_lost: u32,
    pub log_buffers_lost: u32,
    pub buffers_written: u32,
    pub number_of_buffers: u32,
    pub free_buffers: u32,
}

const NAME_CHARS: usize = 1024;

pub fn query(session_name: &str) -> Result<SessionStats, u32> {
    // EVENT_TRACE_PROPERTIES 뒤에 로거 이름·로그 파일 이름 버퍼가 따라붙는 가변 구조
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total = props_size + NAME_CHARS * 2 * 2;
    let mut buf = vec![0u8; total];
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*props).Wnode.BufferSize = total as u32;
        (*props).LoggerNameOffset = props_size as u32;
        (*props).LogFileNameOffset = (props_size + NAME_CHARS * 2) as u32;
    }
    let wide: Vec<u16> = session_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let rc = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            wide.as_ptr(),
            props,
            EVENT_TRACE_CONTROL_QUERY,
        )
    };
    if rc != 0 {
        return Err(rc);
    }
    let p = unsafe { &*props };
    Ok(SessionStats {
        events_lost: p.EventsLost,
        realtime_buffers_lost: p.RealTimeBuffersLost,
        log_buffers_lost: p.LogBuffersLost,
        buffers_written: p.BuffersWritten,
        number_of_buffers: p.NumberOfBuffers,
        free_buffers: p.FreeBuffers,
    })
}
