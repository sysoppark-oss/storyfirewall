//! 차단 기록(사용자 요청 2026-11-09): 막은 규칙의 종류 — 우리 정책 / Windows 방화벽 계열 / 시스템 / 다른 보안 프로그램 / 모름
use svc::dispatch::rule_kind;

fn info(key: &str, ours: bool) -> policy::FilterInfo {
    policy::FilterInfo {
        name: "r".into(),
        provider_key: key.into(),
        ours,
        ..Default::default()
    }
}

#[test]
fn rule_kinds() {
    assert_eq!(rule_kind(Some(&info("x", true)), true), "ours");
    // 46차 Q2·Q3: 우리 공급자 키라도 받은 때 우리 정책 목록에 없으면 "우리 것"이라 하지 않는다
    assert_eq!(rule_kind(Some(&info("x", true)), false), "ours_unknown");
    assert_eq!(
        rule_kind(None, true),
        "ours",
        "지금 걸린 우리 필터면 정보가 없어도 우리 것"
    );
    assert_eq!(
        rule_kind(
            Some(&info("decc16ca-3f33-4346-be1e-8fb4ae0f3d62", false)),
            false
        ),
        "windows_firewall"
    );
    assert_eq!(
        rule_kind(
            Some(&info("4b153735-1049-4480-aab4-d1b9bdc03710", false)),
            false
        ),
        "windows_service_hardening"
    );
    assert_eq!(
        rule_kind(
            Some(&info("3cc2631f-2d5d-43a0-b174-614837d863a1", false)),
            false
        ),
        "windows_app_isolation"
    );
    assert_eq!(rule_kind(Some(&info("", false)), false), "system");
    assert_eq!(
        rule_kind(
            Some(&info("11111111-2222-3333-4444-555555555555", false)),
            false
        ),
        "other"
    );
    assert_eq!(rule_kind(None, false), "unknown");
}
