//! 연결 핸들러: 서명 검사 → rpc.hello 강제 → 요청마다 파싱·검증·권한 → 엔진 큐 → 응답.
//! 파이프·토큰·서명은 트레이트 뒤 (Windows 구현은 실기기 단계).

use std::sync::mpsc::{self, Sender};
use std::time::Duration;

use api::rpc::Id;
use api::{ErrorCode, Method, Request, Response, Role, RpcError};

use crate::dispatch::Caller;
use crate::runtime::Command;

/// 읽기 결과
pub enum Read {
    Line(String),
    Timeout,
    Closed,
}

/// 줄 단위 전송. Windows = 메시지 모드 파이프(overlapped I/O + 대기), 테스트 = 채널 쌍.
/// 핸들러는 요청과 알림을 번갈아 처리해야 하므로 읽기에 시간 제한을 둔다.
pub trait Transport {
    fn read_line(&mut self, timeout: Duration) -> Read;
    fn write_line(&mut self, line: &str) -> bool;
    fn client_pid(&self) -> u32;
    /// 클라이언트의 로그온 세션 (A30). 파이프 = GetNamedPipeClientSessionId. 모르면 None(개발용 TCP·시험 = 범위 제한 없음)
    fn client_session(&self) -> Option<u32> {
        None
    }
}

/// 알림을 흘리기 위한 읽기 대기 단위
pub const READ_SLICE: Duration = Duration::from_millis(200);
/// hello 를 기다리는 상한
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// 인증. Windows = WinVerifyTrust(우리 서명) + CheckTokenMembership(Administrators)
pub trait Authn {
    /// 클라이언트 이미지 경로와 서명 검사 결과
    fn client_image(&self, pid: u32) -> Option<String>;
    fn signature_ok(&self, pid: u32) -> bool;
    fn is_admin(&self, pid: u32) -> bool;
}

/// 엔진 큐 대기 상한 (12차 Q4: 5초 뒤 busy)
pub const QUEUE_WAIT: Duration = Duration::from_secs(5);

/// 연결 하나를 끝까지 처리한다. 반환: 끊은 이유
pub fn serve(
    conn_id: u64,
    t: &mut dyn Transport,
    auth: &dyn Authn,
    engine: &Sender<Command>,
) -> &'static str {
    let pid = t.client_pid();
    // 1) 서명 검사 실패 = 조회도 없이 끊음 (10차 Q5)
    if !auth.signature_ok(pid) {
        return "signature_failed";
    }
    let image = auth.client_image(pid).unwrap_or_default();
    // 2) 첫 메시지는 rpc.hello (13차 Q4)
    let first = match t.read_line(HELLO_TIMEOUT) {
        Read::Line(l) => l,
        _ => return "closed",
    };
    // 관리자 검사는 첫 읽기 뒤에 한다: ImpersonateNamedPipeClient 는 파이프에서 데이터를 읽기 전에는
    // ERROR_CANNOT_IMPERSONATE(0x558) 로 실패한다 (A17 러너 실측).
    let is_admin = auth.is_admin(pid);
    let session = t.client_session();
    let mut caller = Caller {
        pid,
        image,
        is_admin,
        session,
    };
    let req = match Request::parse_line(&first) {
        Ok(r) if r.method == "rpc.hello" => r,
        Ok(r) => {
            t.write_line(
                &Response::err(
                    Some(r.id),
                    RpcError::with(ErrorCode::InvalidRequest, "첫 메시지는 rpc.hello"),
                )
                .to_line(),
            );
            return "no_hello";
        }
        Err(e) => {
            t.write_line(&Response::err(None, e).to_line());
            return "bad_hello";
        }
    };
    let params = match api::methods::validate_params(Method::RpcHello, &req.params) {
        Ok(p) => p,
        Err(e) => {
            t.write_line(&Response::err(Some(req.id), e).to_line());
            return "bad_hello";
        }
    };
    // 구조 개선 A(2026-11-03): hello 는 엔진을 거치지 않고 여기서 답한다 — 엔진이 무거운 일을 하는 동안에도 연결은 선다(L040 "연결되지 않음").
    // 판 협상만 하고 상태를 바꾸지 않으므로 엔진 스레드가 필요 없다
    let resp = hello_reply(req.id, params);
    // L030: 전에는 hello 실패를 모두 "version_mismatch"로 적었다 — 엔진이 바빠 시간 초과된 것도 판 불일치로 보였다
    let why = match &resp.error {
        None => None,
        Some(e) if e.code == ErrorCode::VersionMismatch => Some("version_mismatch"),
        Some(_) => Some("hello_failed(engine busy or error)"),
    };
    t.write_line(&resp.to_line());
    if let Some(w) = why {
        return w;
    }
    // 3) 요청 루프
    let (sink_tx, sink_rx) = mpsc::channel::<String>();
    loop {
        // 밀린 알림 먼저
        while let Ok(n) = sink_rx.try_recv() {
            if !t.write_line(&n) {
                let _ = engine.send(Command::Unsubscribe { conn_id });
                // 끊긴 이유를 가른다 (A24: 러너에서 한 번 원인 불명으로 끊김 — 다음에 재현되면 어느 쪽인지 보이게)
                return "notify_write_failed";
            }
        }
        let line = match t.read_line(READ_SLICE) {
            Read::Line(l) => l,
            Read::Timeout => continue,
            Read::Closed => {
                let _ = engine.send(Command::Unsubscribe { conn_id });
                return "closed";
            }
        };
        let req = match Request::parse_line(&line) {
            Ok(r) => r,
            Err(e) => {
                t.write_line(&Response::err(None, e).to_line());
                continue;
            }
        };
        let id = req.id.clone();
        let method = match Method::parse(&req.method) {
            Ok(m) => m,
            Err(e) => {
                t.write_line(&Response::err(Some(id), e).to_line());
                continue;
            }
        };
        let params = match api::methods::validate_params(method, &req.params) {
            Ok(p) => p,
            Err(e) => {
                t.write_line(&Response::err(Some(id), e).to_line());
                continue;
            }
        };
        // 변경 메서드는 요청 때마다 관리자 여부를 다시 본다 (15차 Q2 원래 질문: 연결 중 그룹이 바뀌는 경우).
        // 연결 수명 동안 캐시하면 관리자 그룹에서 빠진 뒤에도 열린 연결로 계속 바꿀 수 있다. 가장(impersonation) 1번이라 비용은 작다.
        if method.role() == Role::Admin {
            caller.is_admin = auth.is_admin(pid);
        }
        if method.role() == Role::Admin && !caller.is_admin {
            t.write_line(
                &Response::err(
                    Some(id),
                    RpcError::with(ErrorCode::Unauthorized, "로컬 관리자 그룹만"),
                )
                .to_line(),
            );
            continue;
        }
        if method.is_subscription() {
            let kind = if method == Method::EventsSubscribe {
                "events"
            } else {
                "connections"
            };
            let _ = engine.send(Command::Subscribe {
                conn_id,
                kind: kind.into(),
                sink: sink_tx.clone(),
            });
        }
        // 27차 Gemini Q1: 연결 중 rpc.hello 도 엔진 밖에서 — UI 가 주기적으로 불러 엔진이 한 일에 묶여 있는지(engine_busy_ms) 본다
        let resp = if method == Method::RpcHello {
            hello_reply(id, params)
        } else {
            ask(engine, id, method, params, &caller)
        };
        if !t.write_line(&resp.to_line()) {
            let _ = engine.send(Command::Unsubscribe { conn_id });
            return "response_write_failed";
        }
    }
}

/// 엔진 큐에 넣고 응답을 기다린다. 5초 넘으면 busy.
/// rpc.hello 응답(판 협상 + 서버 판). 서버 판은 Runtime 시작 때 정한다(SERVER_VERSION)
fn hello_reply(id: api::rpc::Id, params: serde_json::Value) -> Response {
    let h: api::rpc::Hello = match serde_json::from_value(params) {
        Ok(h) => h,
        Err(e) => {
            return Response::err(
                Some(id),
                RpcError::with(ErrorCode::InvalidParams, e.to_string()),
            )
        }
    };
    if let Err(e) = api::rpc::negotiate(h.api) {
        return Response::err(Some(id), e);
    }
    let v = crate::runtime::SERVER_VERSION
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();
    let mut out = serde_json::to_value(api::rpc::HelloReply {
        server_version: v,
        api: api::API_VERSION,
    })
    .unwrap();
    // 27차 Gemini Q1: hello 가 엔진 밖에서 답하므로 엔진이 멈춰도 "연결됨"으로 보인다 — 지금 처리 중인 일이 얼마나 오래 걸리고 있는지 함께 준다
    out["engine_busy_ms"] = serde_json::json!(crate::runtime::engine_busy_ms());
    Response::ok(id, out)
}

fn ask(
    engine: &Sender<Command>,
    id: Id,
    method: Method,
    params: serde_json::Value,
    caller: &Caller,
) -> Response {
    let (reply_tx, reply_rx) = mpsc::channel();
    if engine
        .send(Command::Rpc {
            id: id.clone(),
            method,
            params,
            caller: caller.clone(),
            reply: reply_tx,
            queued: std::time::Instant::now(),
        })
        .is_err()
    {
        return Response::err(Some(id), RpcError::with(ErrorCode::Internal, "엔진 종료"));
    }
    match reply_rx.recv_timeout(QUEUE_WAIT) {
        Ok(r) => r,
        Err(_) => Response::err(
            Some(id),
            RpcError::with(ErrorCode::Busy, "엔진 대기 5초 초과"),
        ),
    }
}
