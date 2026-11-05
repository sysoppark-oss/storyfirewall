//! OS 를 만지는 부분은 트레이트 뒤에. Windows 구현은 policy::wfp::Engine 을 감싸고, 테스트는 메모리 가짜.

use policy::spec::BlockSpec;

pub trait WfpBackend {
    /// 한 WFP 트랜잭션 안에서 `remove` 를 지우고 `add` 를 넣는다 (11차 Q1: 판 교체 공백 없음).
    /// `FwpmTransactionBegin0` → `FwpmFilterDeleteById0`… → `FwpmFilterAdd0`… → `FwpmTransactionCommit0`.
    /// 실패하면 abort — 아무것도 바뀌지 않는다. 성공하면 `add` 순서대로 새 필터 ID.
    fn replace(&mut self, remove: &[u64], add: &[BlockSpec]) -> std::result::Result<Vec<u64>, String>;
    /// 우리 Provider 의 필터 ID 전체 (재시작 대조)
    fn list_ours(&mut self) -> std::result::Result<Vec<u64>, String>;
    /// 우리 필터의 (ID, filterKey). ID 는 BFE 재시작·재부팅 뒤 바뀔 수 있어(문서: "runtime identifier") 대조는 키로 한다.
    /// 키를 모르는 백엔드는 빈 목록(→ 예전처럼 ID 로만 대조)
    fn list_keys(&mut self) -> std::result::Result<Vec<(u64, String)>, String> {
        Ok(vec![])
    }
}

/// 그래프 조회 (excluded_system 주소 차단·드라이런)
pub trait GraphQuery {
    /// 이미지 경로의 프로세스가 사건 구간에 접속한 외부 (ip, port, proto) 목록
    fn event_addresses_of(&self, image: &str) -> Vec<(String, u16, u8)>;
}

/// 테스트용 메모리 백엔드. 외부 삭제·실패 주입을 흉내 낸다. `replace` 는 원자적이다.
#[derive(Default)]
pub struct FakeWfp {
    pub next_id: u64,
    pub filters: std::collections::BTreeMap<u64, BlockSpec>,
    /// 이 번째(1부터) replace 호출을 실패시킨다 (엔진이 백엔드를 빌려 쥐기 전에 설정)
    pub fail_on_call: Option<usize>,
    pub calls: usize,
    /// replace 마다 (지운 수, 넣은 수) — 판 교체가 한 번에 됐는지 확인용
    pub log: Vec<(usize, usize)>,
    /// 필터 ID → filterKey(넣을 때 정함, 번호가 바뀌어도 그대로)
    pub keys: std::collections::BTreeMap<u64, String>,
}

impl FakeWfp {
    /// 외부 프로그램이 필터를 지운 것처럼
    pub fn external_delete(&mut self, id: u64) -> bool {
        self.keys.remove(&id);
        self.filters.remove(&id).is_some()
    }
    /// BFE 재시작·재부팅 흉내: 영구 필터는 남지만 ID 를 새로 받는다(키는 그대로)
    pub fn renumber_all(&mut self) {
        let old: Vec<(u64, BlockSpec)> = std::mem::take(&mut self.filters).into_iter().collect();
        let mut keys = std::collections::BTreeMap::new();
        for (id, spec) in old {
            self.next_id += 100;
            if let Some(k) = self.keys.remove(&id) {
                keys.insert(self.next_id, k);
            }
            self.filters.insert(self.next_id, spec);
        }
        self.keys = keys;
    }
    /// 기록에 없는 고아 필터를 심는다
    pub fn plant_orphan(&mut self, spec: BlockSpec) -> u64 {
        self.next_id += 1;
        self.filters.insert(self.next_id, spec);
        self.next_id
    }
}

impl WfpBackend for FakeWfp {
    fn replace(&mut self, remove: &[u64], add: &[BlockSpec]) -> std::result::Result<Vec<u64>, String> {
        self.calls += 1;
        if self.fail_on_call == Some(self.calls) {
            return Err("가짜 BFE 오류 (트랜잭션 abort)".into());
        }
        for id in remove {
            self.filters.remove(id);
            self.keys.remove(id);
        }
        // 실제 WFP 처럼: 명세 하나가 주소 체계마다 필터 하나 (A26 접점 — 예전 가짜는 늘 1개라 엔진의 1:1 전제를 가렸다)
        let mut ids = Vec::new();
        for s in add {
            for f in s.split_family() {
                self.next_id += 1;
                self.filters.insert(self.next_id, f);
                self.keys.insert(self.next_id, format!("key-{}", self.next_id));
                ids.push(self.next_id);
            }
        }
        self.log.push((remove.len(), add.len()));
        Ok(ids)
    }
    fn list_ours(&mut self) -> std::result::Result<Vec<u64>, String> {
        Ok(self.filters.keys().copied().collect())
    }
    fn list_keys(&mut self) -> std::result::Result<Vec<(u64, String)>, String> {
        Ok(self.filters.keys().filter_map(|id| self.keys.get(id).map(|k| (*id, k.clone()))).collect())
    }
}

pub struct NoGraph;
impl GraphQuery for NoGraph {
    fn event_addresses_of(&self, _: &str) -> Vec<(String, u16, u8)> {
        vec![]
    }
}
