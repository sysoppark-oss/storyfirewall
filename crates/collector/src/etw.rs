//! ETW 공급자 구독과 콜백 → 정규화 Event (명세 4판 2-2)
//!
//! - Kernel-Process (keyword 0x50): 1 생성 / 2 종료. CreateTime 필드를 프로세스 키로.
//! - Kernel-Network: 12/28 TCP 연결, 15/31 수락, 42/58 UDP 송신 → Connect. 10/26·11/27·42/58·43/59 의
//!   size 는 용량 카운터에만 누적 (채널로 보내지 않음).
//! - DNS-Client: 3006/3008/3020 → DnsQuery. 3020 은 ClientPID.
//! - Kernel-File (keyword CREATE_NEW_FILE 0x1000 | RENAME_SETLINK_PATH 0x800): 30 새 파일, 27 이름 변경 경로
//!   → 링 버퍼. 필드명은 실측으로 확정 (첫 이벤트 스키마를 meta 에 기록).
//! - 실험(P6): RPC·WinHttp·CAPI2 는 (공급자, id) 별 처음 20건을 JSON 으로 덤프만 한다.
//!
//! 필드명은 P1-b run-2 실측: Kernel-Network `PID/saddr/sport/daddr/dport/size`(포트 네트워크 순서,
//! 헤더 PID 0), DNS 3020 `ClientPID`. 필드가 없으면 버리고 missing_fields 를 센다.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::ser::{EventSerializer, EventSerializerOptions};
use ferrisetw::EventRecord;
use graph::event::{Direction, Event, EventKind, ProcRef, Proto};

use crate::ctx::{ConnKey, Ctx};
use crate::filering::FileEvent;

pub const KERNEL_PROCESS: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
pub const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
pub const DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
pub const KERNEL_FILE: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
// 실험 공급자 (P6). RPC 공급자는 run-3 에서 이벤트 0건이라 뺐다.
pub const WINHTTP: &str = "7d44233d-3055-4b9c-ba64-0d47ca40a232";
pub const CAPI2: &str = "5bbca4a8-b209-48dc-a8c7-b23d3e5216fb";

/// Kernel-File 키워드 (명세 4판 2-2: CreateNewFile·Rename 만)
const KF_KEYWORD_FILENAME: u64 = 0x10;
const KF_KEYWORD_RENAME_SETLINK_PATH: u64 = 0x800;
const KF_KEYWORD_CREATE_NEW_FILE: u64 = 0x1000;
/// 17판 23-2 ② 브라우저 금고 경비: 파일 열기(IRP_MJ_CREATE) — 이벤트 12 "Create".
/// 추측: 키워드 0x80(KERNEL_FILE_KEYWORD_CREATE)·이벤트 12·필드 FileName 은 공급자 매니페스트 공개 자료 기준이며 이 저장소에서
/// 실측하지 않았다. 러너 확인 절차: collector-poc 실행 중 Chrome 프로필의 Login Data 를 type 등으로 한 번 열고
/// meta 의 스키마 기록(file, 12)에 FileName 이 있는지, 진단 카운터 vault_open 이 1 이상인지 본다
const KF_KEYWORD_CREATE: u64 = 0x80;
/// Kernel-File Create(열기) 이벤트 id
const KF_EVENT_CREATE: u16 = 12;
/// 30차 Q3-b: 하드링크 만들기 — 이벤트 28 SetLinkPath (러너 실측 2026-11-06, poc-hardlink-etw: fsutil·mklink /H 마다 1건,
/// FilePath = 새 링크 경로(NT), InfoClass = 11 FileLinkInformation, FileKey = 원본 파일). 키워드 0x800 으로 이미 켜져 있다
const KF_EVENT_SETLINK: u16 = 28;
/// 같은 (PID, 경로) 열기를 다시 보내지 않는 시간 창 (60초). SQLite 는 같은 파일을 여러 번 연다
const OPEN_DEDUP_WINDOW: i64 = 60 * 10_000_000;
/// NameDelete(11) FileKey 를 RenamePath(27) 와 잇는 시간 창 (2초). FileKey 는 재사용되므로 창 밖은 버린다.
const RENAME_KEY_WINDOW: i64 = 2 * 10_000_000;
/// 스키마 기록용 (프로세스 이름을 파일 이름과 짝지을 때 필요하면 FILENAME 0x10 추가 검토)
const KP_KEYWORD_PROCESS_IMAGE: u64 = 0x50;

const EXP_DUMP_LIMIT: usize = 20;

fn note_schema(
    ctx: &Ctx,
    provider: &str,
    record: &EventRecord,
    schema: &ferrisetw::schema::Schema,
) {
    let key = (provider.to_string(), record.event_id());
    let mut notes = ctx.schema_notes.lock().unwrap();
    if notes.contains_key(&key) {
        return;
    }
    let opts = EventSerializerOptions {
        include_schema: true,
        include_header: false,
        include_extended_data: false,
        fail_unimplemented: false,
    };
    let js = serde_json::to_string(&EventSerializer::new(record, schema, opts))
        .unwrap_or_else(|e| format!("\"serialize error: {e}\""));
    notes.insert(key, js);
}

fn u32f(p: &Parser, name: &str) -> Option<u32> {
    p.try_parse::<u32>(name).ok()
}
fn s(p: &Parser, name: &str) -> Option<String> {
    p.try_parse::<String>(name).ok()
}
fn ipf(p: &Parser, name: &str) -> Option<String> {
    if let Ok(ip) = p.try_parse::<std::net::IpAddr>(name) {
        return Some(ip.to_string());
    }
    p.try_parse::<u32>(name)
        .ok()
        .map(|raw| std::net::Ipv4Addr::from(raw.to_ne_bytes()).to_string())
}
fn portf(p: &Parser, name: &str) -> Option<u16> {
    p.try_parse::<u16>(name).ok().map(u16::from_be)
}

fn missing(ctx: &Ctx) {
    ctx.missing_fields.fetch_add(1, Ordering::Relaxed);
}

pub fn process_provider(ctx: Arc<Ctx>) -> Provider {
    Provider::by_guid(KERNEL_PROCESS)
        .any(KP_KEYWORD_PROCESS_IMAGE)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let id = record.event_id();
            if id != 1 && id != 2 {
                return;
            }
            ctx.count("process");
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            note_schema(&ctx, "process", record, &schema);
            let p = Parser::create(record, &schema);
            let ts = ctx.ts(record.raw_timestamp());
            match id {
                1 => {
                    let (Some(pid), Some(ppid), Some(image)) = (
                        u32f(&p, "ProcessID"),
                        u32f(&p, "ParentProcessID"),
                        s(&p, "ImageName"),
                    ) else {
                        missing(&ctx);
                        return;
                    };
                    // CreateTime: FILETIME 8바이트. 없으면 None (Ingester 가 이벤트 시각 사용) — P8 에서 존재 확인
                    let create_time = p.try_parse::<i64>("CreateTime").ok();
                    let image = ctx.win32_path(&image);
                    // 10판 5-9 (1): 복구 수단 도구만 명령줄을 읽는다(시작 이벤트에 명령줄 없음 — poc3 스키마).
                    // 짧게 사는 프로세스를 놓치지 않게 다른 처리보다 먼저 읽고, 보내기는 ProcessStart 뒤에
                    // 커널 세션이 명령줄을 이미 보냈으면 그것(경쟁 없음). 아니면 직접 읽기를 시도하고, 실패하면 커널 쪽을 기다린다
                    // 직접 읽기는 만남 장소 잠금 안에서 한다 — 그 사이 커널 쪽이 와서 두 번 보내는 일이 없게(읽기는 μs 단위)
                    // 29차 Q1: 도구 판별 = 파일 이름 또는 OriginalFileName(이름 바꾼 복사본). tool = 바뀐 이름일 때의 원래 이름
                    let ident =
                        crate::cmdline::tool_of(&image, &mut ctx.orig_names.lock().unwrap());
                    if matches!(ident, Some(Some(_))) {
                        ctx.count("cmdline_renamed_tool");
                    }
                    let tool: Option<String> = ident.clone().flatten();
                    // 17판 23-2 ②: 브라우저 본체(이름 기준)도 명령줄을 읽되, 디버깅 스위치만 남겨 보낸다(graph::vault::debug_flags_only).
                    // 브라우저 명령줄에는 방문 주소·프로필 경로가 들 수 있다 — 디버깅 스위치가 없으면 아무것도 보내지 않는다
                    let browser = ident.is_none() && graph::vault::is_browser_main_name(&image);
                    let cmd = if ident.is_some() || browser {
                        let mut rv = ctx.cmd_rv.lock().unwrap();
                        match rv.on_start(pid, ts, create_time, tool.clone()) {
                            Some(c) => {
                                drop(rv);
                                ctx.count("cmdline_kernel");
                                Some(Ok(c))
                            }
                            None => {
                                let r = crate::cmdline::read(pid, create_time);
                                if r.is_ok() {
                                    rv.done(pid);
                                }
                                Some(r)
                            }
                        }
                    } else {
                        // 도구가 아니면 커널 쪽이 먼저 남긴 명령줄을 버린다(메모리에만 있던 것)
                        ctx.cmd_rv.lock().unwrap().discard(pid);
                        None
                    };
                    // 파일 링 버퍼에서 이 이미지로 이어지는 생성·이름 변경 사슬을 꺼내 먼저 기록 (명세 4판 2-2)
                    let chain = ctx.files.lock().unwrap().chain_for(&image);
                    if !chain.is_empty() {
                        ctx.chains_found.fetch_add(1, Ordering::Relaxed);
                    }
                    ctx.new_images.lock().unwrap().push(image.clone());
                    // 출신 성분: 실행 시점에 MOTW 재확인 + 서명 검증 (명세 5판 2-3)
                    ctx.enqueue_origin(&image, std::time::Duration::from_millis(0), true, true);
                    for f in chain {
                        // 이름 변경은 출처에 이전 경로를 남긴다 (A4 에서 rename 선으로 승격 검토)
                        let source = match &f.from {
                            Some(from) => format!("etw:file:rename:{from}"),
                            None => "etw:file".to_string(),
                        };
                        let mut ev = Event::new(
                            f.ts,
                            "etw:file",
                            EventKind::FileWrite {
                                proc: ProcRef::new(f.pid, None),
                                path: f.path.clone(),
                            },
                        );
                        ev.source = source;
                        ctx.emit(ev);
                    }
                    // A30: 로그온 세션 (Kernel-Process ProcessStart 의 SessionID). 노드 키와 같은 생성 시각으로 보낸다
                    let session = u32f(&p, "SessionID");
                    ctx.emit(Event::new(
                        ts,
                        "etw:process",
                        EventKind::ProcessStart {
                            pid,
                            ppid,
                            image,
                            create_time,
                        },
                    ));
                    if let Some(r) = cmd {
                        let r = match r {
                            Ok(c) if browser => match graph::vault::debug_flags_only(&c) {
                                Some(flags) => {
                                    ctx.count("cmdline_browser_debug");
                                    Ok(flags)
                                }
                                None => Err("cmdline_browser_plain"),
                            },
                            other => other,
                        };
                        match r {
                            Ok(cmdline) => {
                                ctx.count("cmdline_ok");
                                ctx.emit(Event::new(
                                    ts,
                                    "etw:process",
                                    EventKind::ProcessCommand {
                                        proc: ProcRef::new(pid, create_time),
                                        cmdline,
                                        tool: tool.clone(),
                                    },
                                ));
                            }
                            // 직접 읽기 실패: 커널 세션의 명령줄을 기다린다(kernel_process_provider 가 보낸다)
                            Err(why) => ctx.count(why),
                        }
                    }
                    if let Some(session) = session {
                        ctx.emit(Event::new(
                            ts,
                            "etw:process",
                            EventKind::ProcessSession {
                                pid,
                                create_time: create_time.unwrap_or(ts),
                                session,
                            },
                        ));
                    }
                }
                _ => {
                    let Some(pid) = u32f(&p, "ProcessID") else {
                        missing(&ctx);
                        return;
                    };
                    ctx.emit(Event::new(
                        ts,
                        "etw:process",
                        EventKind::ProcessStop { pid },
                    ));
                }
            }
        })
        .build()
}

/// 10판 5-9 (1): 시스템 커널 공급자의 Process Start(opcode 1) — CommandLine 이 이벤트 안에 있다.
/// 29차 Q1: 이벤트에는 짧은 이름(바뀐 이름일 수 있음)만 있어 여기서는 도구를 가리지 않는다 — 모든 명령줄을 만남 장소에
/// 메모리로만 10초 두고, Kernel-Process 시작(전체 경로·OriginalFileName)에서 도구로 판별된 것만 내보낸다. 나머지는 버려진다
pub fn kernel_process_provider(ctx: Arc<Ctx>) -> Provider {
    Provider::kernel(&ferrisetw::provider::kernel_providers::PROCESS_PROVIDER)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if record.opcode() != 1 {
                return;
            }
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let p = Parser::create(record, &schema);
            // ImageFileName: ANSI 짧은 이름(경로 없음). 진단 카운터·스키마 기록은 이름이 도구인 것만
            let name = p
                .try_parse::<String>("ImageFileName")
                .ok()
                .unwrap_or_default();
            if crate::cmdline::wanted(&name) {
                ctx.count("kernel_process_tool");
                note_schema(&ctx, "kproc", record, &schema);
            }
            let (Some(pid), Some(cmdline)) = (u32f(&p, "ProcessId"), s(&p, "CommandLine")) else {
                missing(&ctx);
                return;
            };
            let ts = ctx.ts(record.raw_timestamp());
            let met = ctx.cmd_rv.lock().unwrap().on_cmd(pid, ts, cmdline.clone());
            if let Some((create_time, tool)) = met {
                // 17판 23-2 ②: 만남 장소에 시작을 남기는 것은 복구 도구와 브라우저 본체뿐이다. 복구 도구(이름 또는 원래 이름)가 아니면
                // 브라우저로 보고 디버깅 스위치만 남긴다 — 그 밖의 명령줄이 원문 그대로 나가는 일이 없게(안전한 쪽)
                let cmdline = if tool.is_none() && !crate::cmdline::wanted(&name) {
                    match graph::vault::debug_flags_only(&cmdline) {
                        Some(flags) => {
                            ctx.count("cmdline_browser_debug");
                            flags
                        }
                        None => {
                            ctx.count("cmdline_browser_plain");
                            return;
                        }
                    }
                } else {
                    cmdline
                };
                ctx.count("cmdline_kernel");
                ctx.emit(Event::new(
                    ts,
                    "etw:kernel-process",
                    EventKind::ProcessCommand {
                        proc: ProcRef::new(pid, create_time),
                        cmdline,
                        tool,
                    },
                ));
            }
        })
        .build()
}

pub fn network_provider(ctx: Arc<Ctx>) -> Provider {
    Provider::by_guid(KERNEL_NETWORK)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let id = record.event_id();
            // (프로토콜, 방향 또는 용량 종류)
            let kind = match id {
                12 | 28 => "tcp_connect",
                15 | 31 => "tcp_accept",
                42 | 58 => "udp_send",
                10 | 26 => "tcp_bytes_sent",
                11 | 27 => "tcp_bytes_recv",
                43 | 59 => "udp_bytes_recv",
                _ => return,
            };
            ctx.count("network");
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            note_schema(&ctx, "network", record, &schema);
            let p = Parser::create(record, &schema);
            let (Some(pid), Some(daddr), Some(dport)) =
                (u32f(&p, "PID"), ipf(&p, "daddr"), portf(&p, "dport"))
            else {
                missing(&ctx);
                return;
            };
            let daddr = graph::ingest::normalize_ip(&daddr);
            let ts = ctx.ts(record.raw_timestamp());
            let size = u32f(&p, "size").unwrap_or(0) as u64;
            let proto: &'static str = if kind.starts_with("udp") {
                "udp"
            } else {
                "tcp"
            };
            match kind {
                "tcp_bytes_sent" => ctx.add_bytes(
                    ConnKey {
                        pid,
                        proto,
                        raddr: daddr,
                        rport: dport,
                    },
                    size,
                    0,
                ),
                "tcp_bytes_recv" | "udp_bytes_recv" => ctx.add_bytes(
                    ConnKey {
                        pid,
                        proto,
                        raddr: daddr,
                        rport: dport,
                    },
                    0,
                    size,
                ),
                _ => {
                    let saddr = ipf(&p, "saddr")
                        .map(|a| graph::ingest::normalize_ip(&a))
                        .unwrap_or_default();
                    let sport = portf(&p, "sport").unwrap_or(0);
                    if kind == "udp_send" {
                        // UDP 송신은 용량에도 더하고, 같은 목적지 1초 안 반복은 Connect 로 보내지 않는다
                        ctx.add_bytes(
                            ConnKey {
                                pid,
                                proto,
                                raddr: daddr.clone(),
                                rport: dport,
                            },
                            size,
                            0,
                        );
                        let mut recent = ctx.recent_udp.lock().unwrap();
                        let key = (pid, daddr.clone(), dport);
                        if let Some(last) = recent.get(&key) {
                            if ts - *last < 10_000_000 {
                                return;
                            }
                        }
                        recent.insert(key, ts);
                        if recent.len() > 4096 {
                            recent.retain(|_, t| ts - *t < 10_000_000);
                        }
                    }
                    // Kernel-Network 의 saddr/sport 는 늘 **로컬**, daddr/dport 는 늘 **원격**이다(방향과 무관).
                    // B2 실측 결함(2026-11-02 노트북): 받은 연결(15/31)을 거꾸로 적어, TeamViewer 서비스가 5939 에서 받은 연결이
                    // "로컬 55819 ← 원격 5939" 로 기록됐다 → 외부에서 들어온 공격의 원격 주소·포트가 틀리게 남을 뻔했다.
                    let direction = if kind == "tcp_accept" {
                        Direction::In
                    } else {
                        Direction::Out
                    };
                    let (laddr, lport, raddr, rport) = (saddr, sport, daddr.clone(), dport);
                    if direction == Direction::Out {
                        ctx.seen_connects
                            .lock()
                            .unwrap()
                            .insert((pid, raddr.clone(), rport));
                    }
                    ctx.emit(Event::new(
                        ts,
                        "etw:network",
                        EventKind::Connect {
                            proc: ProcRef::new(pid, None),
                            proto: if proto == "udp" {
                                Proto::Udp
                            } else {
                                Proto::Tcp
                            },
                            direction,
                            laddr,
                            lport,
                            raddr,
                            rport,
                        },
                    ));
                }
            }
        })
        .build()
}

pub fn dns_provider(ctx: Arc<Ctx>) -> Provider {
    Provider::by_guid(DNS_CLIENT)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let id = record.event_id();
            if id != 3006 && id != 3008 && id != 3020 {
                return;
            }
            ctx.count("dns");
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            note_schema(&ctx, "dns", record, &schema);
            let p = Parser::create(record, &schema);
            // 3020(캐시 응답)은 헤더 PID 가 DNS 서비스. ClientPID 필드는 Windows 2025 에는 있고 2022 에는 없다
            // (P8 실측). 없으면 요청자를 알 수 없으므로 버린다 (3006/3008 이 조회를 덮는다).
            let pid = if id == 3020 {
                match u32f(&p, "ClientPID") {
                    Some(v) => v,
                    None => {
                        ctx.skipped_no_client_pid.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }
            } else {
                record.process_id()
            };
            let Some(name) = s(&p, "QueryName") else {
                missing(&ctx);
                return;
            };
            // QueryResults: "type: 5 host;1.2.3.4;" 형식. type: 항목과 빈 칸 제거
            let results: Vec<String> = s(&p, "QueryResults")
                .unwrap_or_default()
                .split(';')
                .map(|x| x.trim())
                .filter(|x| !x.is_empty() && !x.starts_with("type:"))
                .map(|x| x.to_string())
                .collect();
            ctx.emit(Event::new(
                ctx.ts(record.raw_timestamp()),
                "etw:dns",
                EventKind::DnsQuery {
                    proc: ProcRef::new(pid, None),
                    name,
                    results,
                },
            ));
        })
        .build()
}

pub fn file_provider(ctx: Arc<Ctx>) -> Provider {
    Provider::by_guid(KERNEL_FILE)
        .any(
            KF_KEYWORD_CREATE_NEW_FILE
                | KF_KEYWORD_RENAME_SETLINK_PATH
                | KF_KEYWORD_FILENAME
                | KF_KEYWORD_CREATE,
        )
        .add_filter(EventFilter::ByEventIds(vec![
            11,
            27,
            30,
            KF_EVENT_CREATE,
            KF_EVENT_SETLINK,
        ]))
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let id = record.event_id();
            // 17판 23-2 ②: 열기(12)는 초당 수천 건일 수 있다 — 값싼 경로 거르기(graph::vault::watch_prefilter)를 통과한 것만
            // 스키마 기록·변환·정밀 검사(금고 파일 classify / 미끼 후보 decoy_candidate)를 한다. 다른 열기는 세기만 하고 버린다.
            // 추측(성능): 커널 쪽 경로 필터(EVENT_FILTER_TYPE_PAYLOAD)는 ferrisetw 가 지원하지 않아 쓰지 않았다 — 노트북 부하 측정 대상
            if id == KF_EVENT_CREATE {
                ctx.file_opens_seen.fetch_add(1, Ordering::Relaxed);
                let Ok(schema) = locator.event_schema(record) else {
                    return;
                };
                let p = Parser::create(record, &schema);
                let Some(raw) = s(&p, "FileName") else {
                    missing(&ctx);
                    return;
                };
                if !graph::vault::watch_prefilter(&raw.to_ascii_lowercase()) {
                    return;
                }
                note_schema(&ctx, "file", record, &schema);
                let path = ctx.win32_path(&raw);
                if graph::vault::classify(&path).is_none()
                    && graph::vault::decoy_candidate(&path).is_none()
                {
                    return;
                }
                let pid = record.process_id();
                let ts = ctx.ts(record.raw_timestamp());
                {
                    let mut m = ctx.recent_opens.lock().unwrap();
                    let key = (pid, path.to_ascii_lowercase());
                    if let Some(t) = m.get(&key) {
                        if ts >= *t && ts - *t < OPEN_DEDUP_WINDOW {
                            return;
                        }
                    }
                    if m.len() > 4096 {
                        m.retain(|_, t| ts - *t < OPEN_DEDUP_WINDOW);
                    }
                    m.insert(key, ts);
                }
                ctx.count("vault_open");
                ctx.emit(Event::new(
                    ts,
                    "etw:file:open",
                    EventKind::FileOpen {
                        proc: ProcRef::new(pid, None),
                        path,
                    },
                ));
                return;
            }
            // 30차 Q3-b: 금고(브라우저 저장소)·미끼 파일에 하드링크를 만들면 정규화로는 원래 이름이 안 나온다 →
            // 새 링크의 모든 이름(FindFirstFileNameW)을 보고 금고·미끼 파일이 있으면 그 파일을 "연 것"으로 보낸다
            // (하드링크를 만들려면 원본을 열어야 한다). 링크 만들기는 드물어 이 조회는 부하가 작다
            if id == KF_EVENT_SETLINK {
                ctx.count("file_link");
                let Ok(schema) = locator.event_schema(record) else {
                    return;
                };
                note_schema(&ctx, "file", record, &schema);
                let p = Parser::create(record, &schema);
                let Some(raw) = s(&p, "FilePath").or_else(|| s(&p, "FileName")) else {
                    missing(&ctx);
                    return;
                };
                let link = ctx.win32_path(&raw);
                let names = crate::paths::hardlink_names(&link);
                // 31차 Gemini Q2: 링크를 만들자마자 지우면(ETW 전달 지연 동안) 이름을 못 얻는다. FileKey 는 커널 객체 주소라
                // 사용자 모드에서 파일과 이을 수 없다 — 못 얻은 사실을 세어 진단에 남긴다(경쟁이 실제로 일어나는지 실측)
                if names.is_empty() {
                    ctx.count("file_link_unresolved");
                }
                let Some(target) = names.into_iter().find(|n| {
                    graph::vault::classify(n).is_some()
                        || graph::vault::decoy_candidate(n).is_some()
                }) else {
                    return;
                };
                ctx.count("vault_link");
                ctx.emit(Event::new(
                    ctx.ts(record.raw_timestamp()),
                    "etw:file:link",
                    EventKind::FileOpen {
                        proc: ProcRef::new(record.process_id(), None),
                        path: target,
                    },
                ));
                return;
            }
            // run-1·2 실측: 30 CreateNewFile 은 FileName(NT 전체 경로), 27 RenamePath 는 FilePath(새 경로)만 준다.
            // 옛 경로 (3차 검증 C3): ① 2초 안의 NameDelete(11) 와 FileKey 가 같으면 그것 (재사용 충돌은 창으로 회피),
            // ② 없으면 "같은 PID 가 같은 폴더에 최근 만들었고 지금은 없는 파일" 휴리스틱. 둘 다 '추정'으로 표시.
            let kind: &'static str = match id {
                30 => "create",
                27 => "rename",
                11 => "namedelete",
                _ => return,
            };
            ctx.count("file");
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            note_schema(&ctx, "file", record, &schema);
            let p = Parser::create(record, &schema);
            let path = s(&p, "FileName").or_else(|| s(&p, "FilePath"));
            let Some(path) = path else {
                missing(&ctx);
                return;
            };
            let path = ctx.win32_path(&path);
            let ts = ctx.ts(record.raw_timestamp());
            if kind == "namedelete" {
                if let Ok(k) = p.try_parse::<u64>("FileKey") {
                    let mut m = ctx.deleted_names.lock().unwrap();
                    if m.len() > 2048 {
                        m.retain(|_, (t, _)| ts - *t <= RENAME_KEY_WINDOW);
                    }
                    m.insert(k, (ts, path));
                }
                return;
            }
            // 시스템·Program Files 는 제외 (명세 4판 2-2)
            let lower = path.to_ascii_lowercase();
            if lower.contains(":\\windows\\") || lower.contains(":\\program files") {
                return;
            }
            let pid = record.process_id();
            // ADS 생성(`x:Zone.Identifier`) → 1초 뒤 본체의 MOTW 를 읽는다 (내용을 쓰기 전일 수 있음)
            if kind == "create" {
                if let Some(base) = path.strip_suffix(":Zone.Identifier") {
                    ctx.enqueue_origin(base, std::time::Duration::from_secs(1), true, false);
                    return;
                }
            }
            let (from, from_method) = if kind == "rename" {
                let by_key = p.try_parse::<u64>("FileKey").ok().and_then(|k| {
                    let mut m = ctx.deleted_names.lock().unwrap();
                    match m.remove(&k) {
                        Some((t, old))
                            if ts - t <= RENAME_KEY_WINDOW
                                && old.to_ascii_lowercase() != path.to_ascii_lowercase() =>
                        {
                            Some(old)
                        }
                        _ => None,
                    }
                });
                match by_key {
                    Some(old) => (Some(old), "filekey"),
                    None => (
                        ctx.files
                            .lock()
                            .unwrap()
                            .guess_rename_source(&path, pid, ts, |q| {
                                !std::path::Path::new(q).exists()
                            }),
                        "guess",
                    ),
                }
            } else {
                (None, "")
            };
            if kind == "rename" {
                *ctx.rename_methods
                    .lock()
                    .unwrap()
                    .entry(from_method)
                    .or_insert(0) += 1;
            }
            ctx.files.lock().unwrap().push(FileEvent {
                ts,
                pid,
                kind,
                path,
                from,
            });
        })
        .build()
}

/// XML 속성값 추출: `name="value"` 의 첫 번째 value
fn xml_attr(xml: &str, name: &str) -> Option<String> {
    xml_attrs(xml, name).into_iter().next()
}

/// `name="value"` 의 모든 value (순서대로, 중복 제거)
fn xml_attrs(xml: &str, name: &str) -> Vec<String> {
    let pat = format!("{name}=\"");
    let mut out: Vec<String> = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&pat) {
        rest = &rest[i + pat.len()..];
        let Some(j) = rest.find('"') else { break };
        let v = rest[..j].to_string();
        if !out.contains(&v) {
            out.push(v);
        }
        rest = &rest[j..];
    }
    out
}

/// CAPI2 (명세 5판 2-3): Build Chain Stop(11) → CertChain, Verify Revocation Stop(41) → RevocationFetch.
/// 커널 측 이벤트 ID 필터로 11·41 만 받는다. EventWriteData 는 XML 이며 첫 Certificate 가 리프다.
pub fn capi2_provider(ctx: Arc<Ctx>) -> Provider {
    Provider::by_guid(CAPI2)
        .add_filter(EventFilter::ByEventIds(vec![11, 41]))
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let id = record.event_id();
            if id != 11 && id != 41 {
                return;
            }
            ctx.count("capi2");
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            note_schema(&ctx, "capi2", record, &schema);
            let p = Parser::create(record, &schema);
            let Some(xml) = s(&p, "EventWriteData") else {
                missing(&ctx);
                return;
            };
            let Some(task_id) = xml_attr(&xml, "TaskId") else {
                missing(&ctx);
                return;
            };
            let ts = ctx.ts(record.raw_timestamp());
            let pid = record.process_id();
            if id == 11 {
                // 첫 Certificate 가 리프. 체인의 모든 fileRef(SHA-1 지문)가 41 과의 조인 키 (run-9: TaskId 는 서로 다름)
                let Some(subject) = xml_attr(&xml, "subjectName") else {
                    missing(&ctx);
                    return;
                };
                let chain_refs = xml_attrs(&xml, "fileRef");
                ctx.capi2_chains.fetch_add(1, Ordering::Relaxed);
                ctx.emit(Event::new(
                    ts,
                    "etw:capi2",
                    EventKind::CertChain {
                        pid,
                        subject,
                        task_id,
                        chain_refs,
                    },
                ));
            } else {
                let Some(url) = xml_attr(&xml, "url") else {
                    return; // 폐기 확인에 URL 이 없으면(캐시 적중) 외부 접속도 없다
                };
                let cert_ref = xml_attr(&xml, "fileRef");
                ctx.capi2_fetches.fetch_add(1, Ordering::Relaxed);
                ctx.emit(Event::new(
                    ts,
                    "etw:capi2",
                    EventKind::RevocationFetch {
                        pid,
                        task_id,
                        url,
                        cert_ref,
                    },
                ));
            }
        })
        .build()
}

/// 실험 공급자 (P6): 이벤트 전체 JSON 을 (공급자, id) 별 20건까지 덤프.
/// `only_ids` 가 있으면 세션 구독 시점에 이벤트 ID 필터(EVENT_FILTER_TYPE_EVENT_ID)를 걸어 커널에서
/// 거른다 — CAPI2 는 XML 페이로드라 콜백까지 오게 두면 안 된다 (3차 검증 C1).
pub fn experimental_provider(
    ctx: Arc<Ctx>,
    guid: &str,
    tag: &'static str,
    only_ids: Option<&[u16]>,
) -> Provider {
    let mut b = Provider::by_guid(guid);
    if let Some(ids) = only_ids {
        b = b.add_filter(EventFilter::ByEventIds(ids.to_vec()));
    }
    let ids_owned: Option<Vec<u16>> = only_ids.map(|v| v.to_vec());
    b.add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
        // 콜백 최상단에서 ID 부터 걸러 낸다 (커널 필터가 안 먹는 빌드 대비)
        if let Some(ids) = &ids_owned {
            if !ids.contains(&record.event_id()) {
                return;
            }
        }
        ctx.count(tag);
        let Ok(schema) = locator.event_schema(record) else {
            return;
        };
        let key = (tag.to_string(), record.event_id());
        {
            let mut counts = ctx.exp_counts.lock().unwrap();
            let n = counts.entry(key).or_insert(0);
            *n += 1;
            if *n > EXP_DUMP_LIMIT {
                return;
            }
        }
        note_schema(&ctx, tag, record, &schema);
        let opts = EventSerializerOptions {
            include_schema: false,
            include_header: true,
            include_extended_data: false,
            fail_unimplemented: false,
        };
        let js =
            serde_json::to_string(&EventSerializer::new(record, &schema, opts)).unwrap_or_default();
        let g = record.activity_id();
        let activity = format!("{:08x}-{:04x}-{:04x}", g.data1, g.data2, g.data3);
        ctx.exp_dumps.lock().unwrap().push(format!(
            "{tag} id={} ts={} pid={} tid={} activity={activity} {js}",
            record.event_id(),
            ctx.ts(record.raw_timestamp()),
            record.process_id(),
            record.thread_id()
        ));
    })
    .build()
}
