//! 실제 서비스용 그래프 기반 조회기 (A26). 테스트용 가짜(`R`·`NoGraph`)를 대신한다.
//!
//! - `GraphResolver` = dsl::Resolver: `디렉터리\*` 의 실행 파일, `descendants_of` 의 자손(그래프), 파일 존재.
//! - `GraphAddresses` = engine::GraphQuery: 이미지 경로의 프로세스가 접속한 외부 (IP, 포트, 프로토콜) — 시스템 프로세스 주소 차단 재료.
//!
//! 엔진은 이것들을 자기 스레드에서 쓰므로 그래프 DB 에 **따로 연결**한다(WAL, 읽기 위주). 쓰기는 수집 세션·엔진의 Store 가 한다.

use dsl::expand::Resolver;
use engine::backend::GraphQuery;
use graph::Store;

/// 자손 목록 상한 (cut 과 같은 값)
pub const DESCENDANTS_MAX: usize = crate::cut::MAX_TARGETS;

pub struct GraphResolver {
    store: Store,
}

impl GraphResolver {
    pub fn open(graph_db: &str) -> Result<Self, String> {
        Ok(Self {
            store: Store::open(graph_db).map_err(|e| e.to_string())?,
        })
    }
    pub fn from_store(store: Store) -> Self {
        Self { store }
    }
}

fn is_exe(p: &std::path::Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
}

impl Resolver for GraphResolver {
    fn list_exes(&self, dir: &str) -> Vec<String> {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return vec![];
        };
        let mut out: Vec<String> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file() && is_exe(p))
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        out.sort();
        out
    }

    /// 파일이 없거나 해시가 다르면 거부 (6차 검증 Q4: "그 파일이 그때 그 파일"이 아니면 자손 전개를 믿지 않는다)
    fn descendants(&self, file_path: &str, sha256: &str) -> Result<Vec<String>, String> {
        if !std::path::Path::new(file_path).is_file() {
            return Err(format!("파일 없음: {file_path}"));
        }
        if !sha256.trim().is_empty() {
            match graph::hash::sha256_file(file_path) {
                graph::hash::HashOutcome::Ok { sha256: cur, .. }
                    if cur.eq_ignore_ascii_case(sha256.trim()) => {}
                graph::hash::HashOutcome::Ok { sha256: cur, .. } => {
                    return Err(format!("해시 불일치: 지금 {cur}"))
                }
                graph::hash::HashOutcome::TooLarge { .. } => {
                    return Err("해시 상한을 넘는 파일".into())
                }
                graph::hash::HashOutcome::Unreadable(e) => {
                    return Err(format!("읽을 수 없음: {e}"))
                }
            }
        }
        let mut imgs =
            graph::views::descendant_images_of_file(&self.store, file_path, DESCENDANTS_MAX)
                .map_err(|e| e.to_string())?;
        // 접점: graph 는 그래프에 없는 파일이면 빈 목록을 준다. dsl 은 "뿌리 포함 목록"을 기대한다 — 비면 정책이 아무것도
        // 막지 않게 된다. 아직 실행 기록이 없는(디스크에는 있는) 파일도 뿌리 자신은 막고, 새 자손은 열린 조건이 보충한다.
        if imgs.is_empty() {
            imgs.push(file_path.to_string());
        }
        Ok(imgs)
    }

    fn exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }
}

pub struct GraphAddresses {
    store: Store,
}

impl GraphAddresses {
    pub fn open(graph_db: &str) -> Result<Self, String> {
        Ok(Self {
            store: Store::open(graph_db).map_err(|e| e.to_string())?,
        })
    }
    pub fn from_store(store: Store) -> Self {
        Self { store }
    }
}

impl GraphQuery for GraphAddresses {
    fn event_addresses_of(&self, image: &str) -> Vec<(String, u16, u8)> {
        // 보관 중인 원시 접속 전부(7일). 사건 구간을 좁히는 것은 끊기(cut::plan)가 따로 한다
        graph::views::addresses_of_image(&self.store, image, 0)
            .unwrap_or_default()
            .into_iter()
            .map(|(ip, port, proto)| (ip, port, if proto == "udp" { 17 } else { 6 }))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_exes_descendants_and_hash_guard() {
        let dir = std::env::temp_dir().join(format!("sf-resolver-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.exe"), b"MZa").unwrap();
        std::fs::write(dir.join("B.EXE"), b"MZb").unwrap();
        std::fs::write(dir.join("note.txt"), b"x").unwrap();
        let r = GraphResolver::from_store(Store::open_in_memory().unwrap());
        let exes = r.list_exes(&dir.to_string_lossy());
        assert_eq!(exes.len(), 2, "{exes:?}");
        let a = dir.join("a.exe").to_string_lossy().into_owned();
        // 그래프에 기록 없음 → 뿌리만
        let d = r.descendants(&a, "").unwrap();
        assert_eq!(d, vec![a.clone()]);
        // 해시 대조
        let graph::hash::HashOutcome::Ok { sha256, .. } = graph::hash::sha256_file(&a) else {
            panic!()
        };
        assert!(r.descendants(&a, &sha256).is_ok());
        assert!(r
            .descendants(&a, &"0".repeat(64))
            .unwrap_err()
            .contains("해시 불일치"));
        assert!(r
            .descendants(&dir.join("none.exe").to_string_lossy(), "")
            .unwrap_err()
            .contains("파일 없음"));
        assert!(r.exists(&a) && !r.exists("/no/such"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
