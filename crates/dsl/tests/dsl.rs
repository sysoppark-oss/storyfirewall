//! A6 통과 기준: 명세 2판 3장 예시 4건 파싱·검증·전개, 규칙 1~9 거부·경고, 전개 케이스(internet 범위·any·자정 넘김·process_not).

use dsl::expand::Resolver;
use dsl::model::Ack;
use dsl::{expand, parse, validate};
use policy::guard::Guard;
use policy::spec::{Action, Direction};

struct FakeResolver;
impl Resolver for FakeResolver {
    fn list_exes(&self, dir: &str) -> Vec<String> {
        if dir.to_ascii_lowercase().contains("chrome") {
            vec![format!("{dir}\\chrome.exe"), format!("{dir}\\chrome_proxy.exe")]
        } else {
            vec![]
        }
    }
    fn descendants(&self, file_path: &str, sha256: &str) -> Result<Vec<String>, String> {
        if sha256.starts_with("dead") {
            return Err("해시 불일치: 파일이 바뀌었음".into());
        }
        Ok(vec![file_path.to_string(), r"C:\Users\PJG\AppData\Local\Temp\dropper.exe".into(), r"C:\Windows\System32\svchost.exe".into(), r"C:\Windows\explorer.exe".into()])
    }
    fn exists(&self, path: &str) -> bool {
        !path.contains("missing")
    }
}

const SPEC_EXAMPLES: &str = r#"
- name: 야간 외부통신 제한
  action: block
  match: { direction: out, process_not: ["C:/Program Files/Google/Chrome/*"], remote_ip: [internet] }
  when: { time: "00:00-06:00" }
- name: 내부 PC 간 SMB·RDP 차단
  action: block
  match: { direction: in, protocol: tcp, remote_ip: [lan], local_port: [445, 3389, 5985] }
- name: 가상패치-SMBv1
  action: block
  match: { direction: in, local_port: [445] }
  expires: 14d
  on_expire: notify
- name: 끊기-invoice.exe
  action: block
  match: { direction: both, descendants_of: "file:C:/Users/PJG/Downloads/invoice.exe#sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
  also: [terminate, quarantine, remove_autorun]
"#;

#[test]
fn spec_examples_parse_validate_expand() {
    let doc = parse(SPEC_EXAMPLES).unwrap();
    assert_eq!(doc.version, 1);
    assert_eq!(doc.policies.len(), 4);
    let v = validate(&doc);
    assert!(v.errors.is_empty(), "{:?}", v.errors);
    // 가상패치-SMBv1 은 프로그램·주소 조건이 없어 규칙 3 확인 필요
    assert!(v.needs_ack.iter().any(|(n, a)| n == "가상패치-SMBv1" && *a == Ack::Wide), "{:?}", v.needs_ack);
    // 야간: internet + process_not → block(앱 없음) + permit(크롬 2개)
    let e = expand(&doc.policies[0], &FakeResolver).unwrap();
    let blocks: Vec<_> = e.specs.iter().filter(|s| s.action == Action::Block).collect();
    let permits: Vec<_> = e.specs.iter().filter(|s| s.action == Action::Permit).collect();
    assert_eq!(blocks.len(), 1);
    assert!(blocks[0].app_path.is_none());
    assert!(!blocks[0].remote_v4.is_empty() && !blocks[0].remote_v6.is_empty(), "internet 은 v4 범위 + v6 2000::/3");
    assert_eq!(blocks[0].protocols, vec![6, 17], "프로토콜 미지정 → tcp+udp (ICMP 제외)");
    assert_eq!(permits.len(), 2);
    assert!(permits.iter().all(|p| p.app_path.as_deref().map_or(false, |a| a.contains("chrome"))));
    let sch = e.schedule.unwrap();
    assert_eq!(sch.minutes, vec![(0, 360)]);
    // SMB·RDP: lan 범위, tcp, 3 포트 OR
    let e = expand(&doc.policies[1], &FakeResolver).unwrap();
    assert_eq!(e.specs.len(), 1);
    assert_eq!(e.specs[0].direction, Direction::In);
    assert_eq!(e.specs[0].protocols, vec![6]);
    assert_eq!(e.specs[0].local_ports.len(), 3);
    assert_eq!(e.specs[0].remote_v4.len(), 5);
    // 가상패치: 14d → 분
    let e = expand(&doc.policies[2], &FakeResolver).unwrap();
    assert_eq!(e.schedule.unwrap().expires_in_minutes, Some(14 * 24 * 60));
    // 끊기: both × 자손(시스템 프로세스 제외: svchost 는 유지, explorer 제외)
    let e = expand(&doc.policies[3], &FakeResolver).unwrap();
    let apps: Vec<&str> = e.specs.iter().filter_map(|s| s.app_path.as_deref()).collect();
    assert!(apps.iter().any(|a| a.ends_with("invoice.exe")));
    assert!(apps.iter().any(|a| a.ends_with("dropper.exe")));
    assert!(!apps.iter().any(|a| a.ends_with("explorer.exe")), "규칙 4");
    assert!(!apps.iter().any(|a| a.ends_with("svchost.exe")), "자손으로 딸려 온 svchost 는 광역 차단 대상이 아님");
    assert_eq!(e.specs.iter().filter(|s| s.direction == Direction::Out).count(), e.specs.iter().filter(|s| s.direction == Direction::In).count());
    assert_eq!(e.also.len(), 3);
    assert!(e.dryrun_required);
    assert!(e.warnings.iter().any(|w| w.contains("[4]")));
    let ex: Vec<&str> = e.excluded_system.iter().map(|s| s.rsplit('\\').next().unwrap()).collect();
    assert_eq!(ex, vec!["svchost.exe", "explorer.exe"], "정책 엔진이 의심 주소 차단으로 이어갈 목록");
    // 전개 결과는 가드도 통과해야 한다
    let g = Guard::new(&["story-firewall-svc.exe"]);
    for s in &e.specs {
        g.check(s).unwrap();
    }
}

#[test]
fn rejects_service_only_fields_and_unknown_fields() {
    let bad = "- name: x\n  action: block\n  acknowledge: [wide]\n  match: { direction: out }\n";
    assert!(parse(bad).is_err(), "acknowledge 는 입력에서 거부");
    let bad = "- name: x\n  action: block\n  source: ai\n  match: { direction: out }\n";
    assert!(parse(bad).is_err(), "source 는 입력에서 거부");
    let bad = "- name: x\n  action: block\n  match: { direction: out, foo: 1 }\n";
    assert!(parse(bad).is_err(), "모르는 필드 거부 (규칙 1)");
    let bad = "version: 2\npolicies: []\n";
    assert!(matches!(parse(bad), Err(dsl::DslError::Version(2))));
    let ok = "version: 1\npolicies:\n  - name: x\n    action: block\n    match: { direction: out, process: ['C:/a/b.exe'] }\n";
    assert_eq!(parse(ok).unwrap().policies.len(), 1);
}

#[test]
fn rule1_format_errors() {
    let text = r#"
- name: dup
  action: block
  match: { direction: out, process: ["C:/a/b.exe"] }
- name: dup
  action: block
  match: { direction: out, process: ["relative.exe", "C:/dir/*.exe"], remote_ip: ["300.1.1.1"], remote_port: ["99999", "10-5"] }
  when: { time: "25:00-06:00", days: [funday] }
  expires: 3w
  until: smbv1_disabled
- name: allow-with-also
  action: allow
  match: { direction: out, process: ["C:/a/b.exe"] }
  also: [terminate]
"#;
    let doc = parse(text).unwrap();
    let v = validate(&doc);
    let msgs: Vec<String> = v.errors.iter().map(|e| e.to_string()).collect();
    let has = |s: &str| msgs.iter().any(|m| m.contains(s));
    assert!(has("name 중복"));
    assert!(has("절대 경로"));
    assert!(has("와일드카드"));
    assert!(has("remote_ip 형식"));
    assert!(has("포트 형식"));
    assert!(has("when.time"));
    assert!(has("when.days"));
    assert!(has("expires 형식"));
    assert!(has("until"));
    assert!(has("allow 에는 also"));
}

#[test]
fn rules_2_3_9_need_ack_and_ack_clears_them() {
    let text = r#"
- name: block-dns
  action: block
  match: { direction: out, process: ["C:/a/b.exe"], remote_port: [53] }
- name: wide
  action: block
  match: { direction: out }
- name: svc
  action: block
  match: { direction: out, process: ["C:/Windows/System32/svchost.exe"] }
"#;
    let mut doc = parse(text).unwrap();
    let v = validate(&doc);
    assert!(v.needs_ack.contains(&("block-dns".into(), Ack::SelfBlock)));
    assert!(v.needs_ack.contains(&("wide".into(), Ack::Wide)));
    assert!(v.needs_ack.contains(&("svc".into(), Ack::Svchost)));
    assert!(!v.ok());
    // 서비스가 UI 확인 뒤 붙인다
    doc.policies[0].acknowledge.push(Ack::SelfBlock);
    doc.policies[1].acknowledge.push(Ack::Wide);
    doc.policies[2].acknowledge.push(Ack::Svchost);
    let v = validate(&doc);
    assert!(v.ok(), "{:?} {:?}", v.errors, v.needs_ack);
    // 규칙 8 은 그래도 자동 제외: svchost 광역 → 경고, 53 포트는 전개에서 빠짐
    let e = expand(&doc.policies[0], &FakeResolver).unwrap();
    assert_eq!(e.specs[0].remote_ports.len(), 1, "b.exe 의 53 은 OS 필수 통신이 아니므로 유지");
    let text2 = "- name: svc53\n  action: block\n  match: { direction: out, process: ['C:/Windows/System32/svchost.exe'], remote_port: ['50-60', 123] }\n";
    let doc2 = parse(text2).unwrap();
    let e = expand(&doc2.policies[0], &FakeResolver).unwrap();
    let ports = &e.specs[0].remote_ports;
    assert!(ports.iter().all(|r| !(r.lo <= 53 && 53 <= r.hi) && !(r.lo <= 123 && 123 <= r.hi)), "{ports:?}");
    assert_eq!(ports.len(), 2, "50-52, 54-60 로 쪼개짐 (123 은 통째로 제거)");
    assert!(e.warnings.iter().any(|w| w.contains("svchost 53")));
}

#[test]
fn rule8_auto_excludes_loopback_dhcp_icmp() {
    let text = r#"
- name: x
  action: block
  match: { direction: out, process: ["C:/a/b.exe"], remote_ip: ["127.0.0.0/8", "10.0.0.0/8"], remote_port: ["60-70"], protocol: any }
"#;
    let doc = parse(text).unwrap();
    let e = expand(&doc.policies[0], &FakeResolver).unwrap();
    let s = &e.specs[0];
    assert!(s.remote_v4.iter().all(|r| !r.lo.is_loopback()), "루프백 제외");
    assert_eq!(s.remote_v4.len(), 1);
    assert_eq!(s.protocols, vec![6, 17], "any → ICMP 없음");
    assert_eq!(s.remote_ports.len(), 2, "60-66, 69-70");
    assert!(e.warnings.iter().any(|w| w.contains("DHCP 67")));
    Guard::new(&[]).check(s).unwrap();
}

#[test]
fn midnight_wrap_and_rule5_conflict() {
    let text = r#"
- name: night
  action: block
  match: { direction: out, process: ["C:/a/b.exe"] }
  when: { time: "22:00-06:30", days: [Mon, tue] }
- name: night-allow
  action: allow
  match: { direction: out, process: ["C:/a/b.exe"] }
"#;
    let doc = parse(text).unwrap();
    let v = validate(&doc);
    assert!(v.warnings.iter().any(|w| w.contains("[5]")), "{:?}", v.warnings);
    let e = expand(&doc.policies[0], &FakeResolver).unwrap();
    let sch = e.schedule.unwrap();
    assert_eq!(sch.minutes, vec![(22 * 60, 24 * 60), (0, 6 * 60 + 30)]);
    assert_eq!(sch.days, vec!["mon", "tue"]);
    let e2 = expand(&doc.policies[1], &FakeResolver).unwrap();
    assert_eq!(e2.specs[0].action, Action::Permit);
}

#[test]
fn descendants_hash_mismatch_is_rejected() {
    let text = "- name: cut\n  action: block\n  match: { direction: out, descendants_of: 'file:C:/x/a.exe#sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' }\n";
    let doc = parse(text).unwrap();
    assert!(validate(&doc).errors.is_empty());
    let r = expand(&doc.policies[0], &FakeResolver);
    assert!(matches!(r, Err(dsl::DslError::Rule { rule: 4, .. })), "{r:?}");
}

// ---- 제안 5③: YAML 별칭 폭탄 (billion laughs). 256KB 상한과 별개로 파서가 메모리 폭발 없이 끝나야 한다 ----
#[test]
fn yaml_alias_bomb_does_not_explode() {
    let mut y = String::from("- name: bomb\n  action: block\n  match: { direction: out, process: ['C:/a/b.exe'] }\n");
    y.push_str("  also: &a0 [terminate]\n");
    // 중첩 별칭: 각 단계가 앞 단계를 10번 참조
    let mut doc = String::from("x0: &a0 [a]\n");
    for i in 1..8 {
        doc.push_str(&format!("x{i}: &a{i} [{}]\n", (0..10).map(|_| format!("*a{}", i - 1)).collect::<Vec<_>>().join(", ")));
    }
    doc.push_str("version: 1\npolicies: []\n");
    let started = std::time::Instant::now();
    let r = parse(&doc);
    assert!(started.elapsed().as_secs() < 5, "별칭 전개가 폭발하지 않아야 함");
    // 모르는 최상위 키(x0..)는 거부되거나(deny_unknown_fields) 별칭 한도로 오류 — 어느 쪽이든 Err
    assert!(r.is_err(), "{r:?}");
    let _ = y;
}

/// 16차 1-(b): 시스템 판정은 이름 + 시스템 디렉터리. 사용자 경로의 같은 이름은 시스템이 아니다.
#[test]
fn system_image_requires_system_directory() {
    use dsl::validate::is_system_image;
    for yes in [r"C:\Windows\System32\svchost.exe", r"c:\windows\system32\LSASS.EXE", r"D:\Windows\SysWOW64\svchost.exe", r"C:\Windows\explorer.exe", r"\SystemRoot\System32\csrss.exe", r"\\?\C:\Windows\System32\services.exe", "C:/Windows/System32/wininit.exe", "svchost.exe"] {
        assert!(is_system_image(yes), "{yes}");
    }
    for no in [r"C:\Users\pjg\AppData\Local\Temp\svchost.exe", r"C:\Windows\Temp\svchost.exe", r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\explorer.exe\..\svchost.exe", r"C:\ProgramData\explorer.exe", r"C:\Windows\System32\drivers\svchost.exe", "svch\u{043e}st.exe", ""] {
        assert!(!is_system_image(no), "{no}");
    }
}

/// 위장 svchost 가 descendants_of 자손으로 오면 제외가 아니라 차단 대상이어야 한다
#[test]
fn fake_svchost_descendant_is_blocked_not_excluded() {
    struct R;
    impl dsl::Resolver for R {
        fn list_exes(&self, _: &str) -> Vec<String> {
            vec![]
        }
        fn descendants(&self, f: &str, _: &str) -> Result<Vec<String>, String> {
            Ok(vec![f.to_string(), r"C:\Users\pjg\AppData\Local\Temp\svchost.exe".into(), r"C:\Windows\System32\svchost.exe".into()])
        }
        fn exists(&self, _: &str) -> bool {
            true
        }
    }
    let y = "- name: cut\n  action: block\n  match: { direction: out, descendants_of: 'file:C:/Users/pjg/Downloads/invoice.exe#sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' }\n";
    let doc = dsl::parse(y).unwrap();
    let e = dsl::expand(&doc.policies[0], &R).unwrap();
    let apps: Vec<String> = e.specs.iter().filter_map(|s| s.app_path.clone()).map(|a| a.to_ascii_lowercase()).collect();
    assert!(apps.iter().any(|a| a.contains(r"\temp\svchost.exe")), "위장 svchost 는 차단: {apps:?}");
    assert!(!apps.iter().any(|a| a.contains(r"\system32\svchost.exe")), "진짜 svchost 는 제외");
    assert_eq!(e.excluded_system.len(), 1);
}
