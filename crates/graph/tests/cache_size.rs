//! 엔진 연결의 쪽 캐시 설정(diag-259: 기본 2 MB 로 1 GB 그래프를 읽고 있었다)

use graph::store::Store;

#[test]
fn set_cache_kib_applies_to_this_connection_only() {
    let dir = std::env::temp_dir().join(format!("sf-cache-size-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("g.db");
    let a = Store::open(&path).unwrap();
    let before = a.cache_size().unwrap();
    a.set_cache_kib(65536).unwrap();
    // 음수 = KiB 단위
    assert_eq!(a.cache_size().unwrap(), -65536);
    // 다른 연결은 그대로다(연결마다 따로 — 파일에 저장되는 설정이 아니다)
    let b = Store::open(&path).unwrap();
    assert_eq!(b.cache_size().unwrap(), before);
    let ro = Store::open_read_only(&path).unwrap();
    assert_eq!(ro.cache_size().unwrap(), before);
    drop((a, b, ro));
    let _ = std::fs::remove_dir_all(&dir);
}
