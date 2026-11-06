//! A12 통과 기준: 봉투 파싱·검증, 메서드 표·권한·멱등 키, 오류 코드 왕복, 페이지 상한, 판 협상, 알림 형식.

use api::methods::{validate_params, NOTIFY_EVENT};
use api::rpc::{negotiate, Hello, Id};
use api::{
    Cursor, ErrorCode, Method, Notification, Page, Request, Response, Role, RpcError, API_VERSION,
    MAX_REQUEST_BYTES, PAGE_MAX,
};

#[test]
fn request_envelope_parses_and_rejects_bad_shapes() {
    let r = Request::parse_line(r#"{"jsonrpc":"2.0","id":1,"method":"policy.list","params":{}}"#)
        .unwrap();
    assert_eq!(r.id, Id::Num(1));
    assert_eq!(Method::parse(&r.method).unwrap(), Method::PolicyList);
    // 문자열 id, params 없음
    let r = Request::parse_line(r#"{"jsonrpc":"2.0","id":"abc","method":"settings.get"}"#).unwrap();
    assert_eq!(r.id, Id::Str("abc".into()));
    assert!(r.params.is_null());
    // 잘못된 모양들
    let bad = [
        (
            r#"{"jsonrpc":"1.0","id":1,"method":"x"}"#,
            ErrorCode::InvalidRequest,
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"bad method!"}"#,
            ErrorCode::InvalidRequest,
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"policy.list","params":[1,2]}"#,
            ErrorCode::InvalidParams,
        ),
        (r#"not json"#, ErrorCode::ParseError),
        (
            "{\"jsonrpc\":\"2.0\",\n\"id\":1,\"method\":\"x\"}",
            ErrorCode::InvalidRequest,
        ),
    ];
    for (line, code) in bad {
        let e = Request::parse_line(line).unwrap_err();
        assert_eq!(e.code, code, "{line}");
    }
    let huge = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"policy.validate","params":{{"yaml":"{}"}}}}"#,
        "x".repeat(MAX_REQUEST_BYTES)
    );
    assert_eq!(
        Request::parse_line(&huge).unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        Method::parse("policy.nope").unwrap_err().code,
        ErrorCode::MethodNotFound
    );
}

#[test]
fn method_table_roles_and_idempotency_keys() {
    // 변경 메서드는 전부 관리자 + request_id
    let admin: Vec<&str> = Method::ALL
        .iter()
        .filter(|(_, m)| m.role() == Role::Admin)
        .map(|(n, _)| *n)
        .collect();
    assert_eq!(
        admin,
        vec![
            "judge.feedback_normal",
            "policy.apply",
            "policy.confirm",
            "policy.rollback",
            "policy.pause",
            "policy.release_address_blocks",
            "cut.apply",
            "retention.set",
            "settings.set",
            "change.get",
            "change.commit"
        ]
    );
    for (_, m) in Method::ALL {
        // change.get 은 관리자 읽기 — 멱등 키 없음
        assert_eq!(
            m.needs_request_id(),
            m.role() == Role::Admin && *m != Method::ChangeGet
        );
        assert_eq!(Method::parse(m.name()).unwrap(), *m, "이름 왕복");
    }
    // request_id 없음 / 형식 오류 / 정상
    let e =
        validate_params(Method::PolicyRollback, &serde_json::json!({"policy_id": 1})).unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidParams);
    let e = validate_params(
        Method::PolicyRollback,
        &serde_json::json!({"policy_id": 1, "request_id": "nope"}),
    )
    .unwrap_err();
    assert!(e.message.contains("UUID"));
    validate_params(
        Method::PolicyRollback,
        &serde_json::json!({"policy_id": 1, "request_id": "0f3c2a1e-9b7d-4c6a-8e5f-123456789abc"}),
    )
    .unwrap();
    // 조회는 request_id 불필요
    validate_params(Method::PolicyList, &serde_json::Value::Null).unwrap();
    assert!(
        Method::ConnectionsSubscribe.is_subscription()
            && !Method::ConnectionsList.is_subscription()
    );
}

#[test]
fn per_method_param_validation() {
    let uuid = "0f3c2a1e-9b7d-4c6a-8e5f-123456789abc";
    // policy.apply: yaml 필수, acknowledge 종류
    let e = validate_params(
        Method::PolicyApply,
        &serde_json::json!({"request_id": uuid, "yaml": "  "}),
    )
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidParams);
    let e = validate_params(Method::PolicyApply, &serde_json::json!({"request_id": uuid, "yaml": "- name: x", "acknowledge": [["x", "bogus"]]})).unwrap_err();
    assert!(e.message.contains("acknowledge"));
    validate_params(Method::PolicyApply, &serde_json::json!({"request_id": uuid, "yaml": "- name: x", "acknowledge": [["x", "wide"]]})).unwrap();
    // confirm 은 version 필수
    assert!(validate_params(
        Method::PolicyConfirm,
        &serde_json::json!({"request_id": uuid, "policy_id": 1})
    )
    .is_err());
    validate_params(
        Method::PolicyConfirm,
        &serde_json::json!({"request_id": uuid, "policy_id": 1, "version": 2}),
    )
    .unwrap();
    // story.events 기본값과 enum
    let p = validate_params(Method::StoryEvents, &serde_json::json!({})).unwrap();
    assert_eq!(
        p["level_min"],
        serde_json::Value::Null,
        "기본값은 디스패처가 serde 로 채운다 — 원본 params 는 그대로"
    );
    assert!(validate_params(
        Method::StoryEvents,
        &serde_json::json!({"level_min": "panic"})
    )
    .is_err());
    assert!(validate_params(Method::StoryEvents, &serde_json::json!({"voice": "shout"})).is_err());
    // graph: depth 범위, timeline: from<to
    assert!(validate_params(
        Method::GraphRewind,
        &serde_json::json!({"node_id": 1, "max_depth": 0})
    )
    .is_err());
    assert!(validate_params(
        Method::GraphTimeline,
        &serde_json::json!({"from_ts": 10, "to_ts": 5})
    )
    .is_err());
    validate_params(
        Method::GraphTimeline,
        &serde_json::json!({"from_ts": 1, "to_ts": 5}),
    )
    .unwrap();
    // cut.also
    assert!(validate_params(
        Method::CutApply,
        &serde_json::json!({"request_id": uuid, "story_root": 1, "also": ["format_disk"]})
    )
    .is_err());
    validate_params(Method::CutApply, &serde_json::json!({"request_id": uuid, "story_root": 1, "also": ["terminate", "quarantine"]})).unwrap();
    // story.today date 형식
    assert!(validate_params(
        Method::StoryToday,
        &serde_json::json!({"date": "2026/10/31"})
    )
    .is_err());
    validate_params(
        Method::StoryToday,
        &serde_json::json!({"date": "2026-10-31", "voice": "expert"}),
    )
    .unwrap();
}

#[test]
fn error_codes_roundtrip_and_response_lines() {
    for (code, num) in [
        (ErrorCode::Unauthorized, -32001),
        (ErrorCode::GuardRejected, -32002),
        (ErrorCode::NeedsAck, -32003),
        (ErrorCode::Busy, -32004),
        (ErrorCode::NotConfirmedYet, -32005),
        (ErrorCode::VersionMismatch, -32006),
        (ErrorCode::ParseError, -32700),
        (ErrorCode::MethodNotFound, -32601),
    ] {
        let e = RpcError::new(code).data(serde_json::json!({"items": [["wide", "x"]]}));
        let resp = Response::err(Some(Id::Num(7)), e.clone());
        let line = resp.to_line();
        assert!(
            line.ends_with('\n') && line.matches('\n').count() == 1,
            "한 줄 + 개행"
        );
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(v["error"]["code"], serde_json::json!(num));
        assert_eq!(v["error"]["message"], serde_json::json!(code.message()));
        let back: Response = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(back.error.unwrap().code, code);
    }
    // 알 수 없는 코드는 역직렬화 거부
    assert!(serde_json::from_str::<RpcError>(r#"{"code":-31000,"message":"x"}"#).is_err());
    // 성공 응답에는 error 키가 없다
    let ok = Response::ok(Id::Num(1), serde_json::json!({"a": 1})).to_line();
    assert!(!ok.contains("\"error\""));
    // 알림은 id 가 없다
    let n =
        Notification::new(NOTIFY_EVENT, serde_json::json!({"kind": "policy_tampered"})).to_line();
    assert!(!n.contains("\"id\"") && n.contains("events.new"));
}

#[test]
fn pages_are_capped_and_cursor_normalized() {
    let c = Cursor {
        after: None,
        limit: 50_000,
    }
    .normalized();
    assert_eq!(c.limit, PAGE_MAX);
    let c = Cursor {
        after: Some("x".into()),
        limit: 0,
    }
    .normalized();
    assert_eq!(c.limit, 1);
    let p = validate_params(
        Method::PolicyHistory,
        &serde_json::json!({"cursor": {"limit": 99999}}),
    )
    .unwrap();
    assert_eq!(p["cursor"]["limit"], serde_json::json!(PAGE_MAX));
    // overfetch(limit+1) → 잘라서 next
    let items: Vec<i64> = (1..=PAGE_MAX as i64 + 1).collect();
    let page = Page::from_overfetch(items, PAGE_MAX, |i| i.to_string());
    assert_eq!(page.items.len(), PAGE_MAX);
    assert_eq!(page.next.as_deref(), Some("1000"));
    let page = Page::from_overfetch(vec![1, 2, 3], 10, |i| i.to_string());
    assert!(page.next.is_none());
}

#[test]
fn version_negotiation() {
    negotiate(API_VERSION).unwrap();
    negotiate((API_VERSION.0, 0)).unwrap();
    let e = negotiate((API_VERSION.0 + 1, 0)).unwrap_err();
    assert_eq!(e.code, ErrorCode::VersionMismatch);
    assert!(e.message.contains("서비스 업데이트 필요"));
    assert_eq!(
        e.data.unwrap()["server_api"],
        serde_json::json!([API_VERSION.0, API_VERSION.1])
    );
    let e = negotiate((API_VERSION.0, API_VERSION.1 + 1)).unwrap_err();
    assert_eq!(
        e.code,
        ErrorCode::VersionMismatch,
        "클라이언트 마이너가 더 높아도 불일치"
    );
    let h: Hello =
        serde_json::from_value(serde_json::json!({"client_version": "0.1.0", "api": [1, 0]}))
            .unwrap();
    assert_eq!(h.api, (1, 0));
    validate_params(
        Method::RpcHello,
        &serde_json::json!({"client_version": "0.1.0", "api": [1, 0]}),
    )
    .unwrap();
    assert!(validate_params(
        Method::RpcHello,
        &serde_json::json!({"client_version": "0.1.0"})
    )
    .is_err());
}

/// 접점(A19 발견): cursor 를 생략하면 serde 기본값과 Default 가 같아야 한다 (예전엔 Default limit=0 → 1건만)
#[test]
fn omitted_cursor_defaults_to_page_max_both_ways() {
    let p: api::methods::StoryEventsParams = serde_json::from_value(serde_json::json!({})).unwrap();
    assert_eq!(p.cursor.clone().normalized().limit, api::PAGE_MAX);
    assert_eq!(api::Cursor::default().normalized().limit, api::PAGE_MAX);
    let c: api::Cursor = serde_json::from_value(serde_json::json!({})).unwrap();
    assert_eq!(c, api::Cursor::default());
}

#[test]
fn change_stage_validates_inner_method_and_params() {
    let uuid = "0f3c2a1e-9b7d-4c6a-8e5f-123456789abc";
    // 맡길 수 있는 것: 변경 메서드 (확인·change.* 는 안 됨)
    assert!(Method::PolicyApply.stageable() && Method::CutApply.stageable());
    assert!(
        !Method::PolicyConfirm.stageable()
            && !Method::ChangeCommit.stageable()
            && !Method::PolicyList.stageable()
    );
    for bad in [
        "policy.confirm",
        "change.commit",
        "change.stage",
        "policy.list",
    ] {
        let e = validate_params(
            Method::ChangeStage,
            &serde_json::json!({"method": bad, "params": {"request_id": uuid}}),
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidParams, "{bad}");
    }
    // 안쪽 검증이 그대로 적용된다: request_id 없음 → 거부
    let e = validate_params(
        Method::ChangeStage,
        &serde_json::json!({"method": "policy.rollback", "params": {"policy_id": 1}}),
    )
    .unwrap_err();
    assert!(e.message.contains("request_id"), "{}", e.message);
    let e = validate_params(Method::ChangeStage, &serde_json::json!({"method": "cut.apply", "params": {"request_id": uuid, "story_root": 1, "also": ["format_c"]}})).unwrap_err();
    assert!(e.message.contains("also"));
    validate_params(Method::ChangeStage, &serde_json::json!({"method": "cut.apply", "params": {"request_id": uuid, "story_root": 1, "also": ["terminate"]}})).unwrap();
    // 조회·확정: change_id UUID, digest 64 hex
    assert!(validate_params(Method::ChangeGet, &serde_json::json!({"change_id": "x"})).is_err());
    validate_params(Method::ChangeGet, &serde_json::json!({"change_id": uuid})).unwrap();
    assert!(validate_params(
        Method::ChangeCommit,
        &serde_json::json!({"request_id": uuid, "change_id": uuid, "digest": "zz"})
    )
    .is_err());
    validate_params(
        Method::ChangeCommit,
        &serde_json::json!({"request_id": uuid, "change_id": uuid, "digest": "a".repeat(64)}),
    )
    .unwrap();
}

/// 첫 실행 관찰실 설정 (17판 23-2 ①): 세 값·세 시간만 받고, 다른 설정만 바꾸는 호출은 그대로 통과
#[test]
fn first_run_watch_settings_are_validated() {
    let rid = "0f3c2a1e-9b7d-4c6a-8e5f-123456789abc";
    for (mode, min) in [("off", 5), ("notify", 10), ("block", 30)] {
        let p = serde_json::json!({"request_id": rid, "first_run_watch": mode, "first_run_minutes": min});
        assert!(validate_params(Method::SettingsSet, &p).is_ok(), "{p}");
    }
    for bad in [
        serde_json::json!({"request_id": rid, "first_run_watch": "kill"}),
        serde_json::json!({"request_id": rid, "first_run_watch": 1}),
        serde_json::json!({"request_id": rid, "first_run_minutes": 7}),
        serde_json::json!({"request_id": rid, "first_run_minutes": "10"}),
    ] {
        let e = validate_params(Method::SettingsSet, &bad).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidParams, "{bad}");
    }
    validate_params(
        Method::SettingsSet,
        &serde_json::json!({"request_id": rid, "voice": "plain"}),
    )
    .unwrap();
    // 맡긴 변경(승인 도우미) 경로에서도 같은 검사
    let staged = serde_json::json!({"method": "settings.set", "params": {"request_id": rid, "first_run_watch": "nope"}});
    assert!(validate_params(Method::ChangeStage, &staged).is_err());
}

/// 33차 Gemini Q4: "내가 쓰는 원격 도구" 목록은 도구 이름(소문자·_) 배열만
#[test]
fn remote_trusted_tools_are_validated() {
    let rid = "0f3c2a1e-9b7d-4c6a-8e5f-123456789abc";
    let ok = serde_json::json!({"request_id": rid, "remote_trusted_tools": ["teamviewer", "chrome_remote_desktop"]});
    assert!(validate_params(Method::SettingsSet, &ok).is_ok());
    assert!(validate_params(
        Method::SettingsSet,
        &serde_json::json!({"request_id": rid, "remote_trusted_tools": []})
    )
    .is_ok());
    for bad in [
        serde_json::json!({"request_id": rid, "remote_trusted_tools": "teamviewer"}),
        serde_json::json!({"request_id": rid, "remote_trusted_tools": ["Team Viewer"]}),
        serde_json::json!({"request_id": rid, "remote_trusted_tools": [1]}),
        serde_json::json!({"request_id": rid, "remote_trusted_tools": [""]}),
    ] {
        assert!(validate_params(Method::SettingsSet, &bad).is_err(), "{bad}");
    }
}
