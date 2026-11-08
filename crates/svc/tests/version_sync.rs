//! 판 번호 한 곳 맞추기(사용자 요청 2026-11-08: 업데이트 뒤 판 표기도 바뀌어야 한다).
//! 서비스 크레이트·화면 크레이트·tauri.conf.json·package.json 의 판이 모두 같아야 한다 — 하나만 올리면
//! 상태 줄(서비스 판)과 업데이트 비교(화면 판)가 어긋난다. 공개 빌드는 태그와 이 판이 다르면 멈춘다(release-windows.yml).
use std::path::Path;

fn read(rel: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn toml_version(s: &str) -> String {
    s.lines()
        .find_map(|l| l.strip_prefix("version = \"").and_then(|r| r.strip_suffix('"')))
        .expect("version 줄")
        .to_string()
}

fn json_version(s: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(s).expect("json");
    v["version"].as_str().expect("version").to_string()
}

#[test]
fn all_version_fields_match() {
    let svc = env!("CARGO_PKG_VERSION").to_string();
    assert_eq!(toml_version(&read("ui/src-tauri/Cargo.toml")), svc, "ui/src-tauri/Cargo.toml");
    assert_eq!(json_version(&read("ui/src-tauri/tauri.conf.json")), svc, "tauri.conf.json");
    assert_eq!(json_version(&read("ui/package.json")), svc, "ui/package.json");
    assert_eq!(json_version(&read("ui/package-lock.json")), svc, "ui/package-lock.json");
}
