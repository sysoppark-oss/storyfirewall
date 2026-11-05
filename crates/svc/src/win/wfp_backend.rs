//! engine::WfpBackend 의 Windows 구현 (A26): policy::wfp::Engine 을 감싼다.
//!
//! 접점: 엔진은 명세를 주소 체계별로 나눠(`BlockSpec::split_family`) 넘기므로 명세 1개 = 필터 1개다. 그래도 개수가 다르면
//! 엔진이 "필터 수 불일치"로 거부한다(트랜잭션은 이미 커밋됐으므로 고아 필터 → 다음 reconcile 이 지운다).

use engine::backend::WfpBackend;
use policy::spec::BlockSpec;

pub struct WinWfp {
    eng: policy::wfp::Engine,
}

impl WinWfp {
    /// 비동적 세션 + Provider·Sublayer 보장 (관리자/SYSTEM)
    pub fn open() -> Result<Self, String> {
        let eng = policy::wfp::Engine::open().map_err(|e| e.to_string())?;
        eng.ensure_provider_sublayer().map_err(|e| e.to_string())?;
        Ok(Self { eng })
    }
}

impl WfpBackend for WinWfp {
    fn replace(&mut self, remove: &[u64], add: &[BlockSpec]) -> Result<Vec<u64>, String> {
        let out = self.eng.replace(remove, add).map_err(|e| e.to_string())?;
        Ok(out.into_iter().map(|(id, _)| id).collect())
    }
    fn list_ours(&mut self) -> Result<Vec<u64>, String> {
        Ok(self
            .eng
            .list_ours()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|(id, _, _)| id)
            .collect())
    }
    fn list_keys(&mut self) -> Result<Vec<(u64, String)>, String> {
        self.eng.list_keys().map_err(|e| e.to_string())
    }
}

/// WFP 를 열지 못했을 때(권한·BFE 중지): 서비스는 보기(가시화)만 하고 변경은 오류로 돌려준다
pub struct NoWfp(pub String);
impl WfpBackend for NoWfp {
    fn replace(&mut self, _: &[u64], _: &[BlockSpec]) -> Result<Vec<u64>, String> {
        Err(format!("WFP 사용 불가: {}", self.0))
    }
    fn list_ours(&mut self) -> Result<Vec<u64>, String> {
        Ok(vec![])
    }
}
