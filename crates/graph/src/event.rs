//! 정규화된 이벤트
//!
//! 수집기(ETW, 연결 테이블, MOTW, Defender 로그 …)는 모두 이 형식으로 바꿔서 그래프에 넣는다.
//! OS 의존 필드는 여기 없다. 시각은 Windows FILETIME(100ns, 1601 기준)을 그대로 쓴다.

use serde::{Deserialize, Serialize};

/// 프로세스 고유 키 재료. PID 재사용에 대비해 생성 시각과 함께 쓴다.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcRef {
    pub pid: u32,
    /// 생성 시각(FILETIME). 모르면 None 이며, 이 경우 ingest 가 가장 최근 같은 PID 를 찾는다.
    pub start_ts: Option<i64>,
}

impl ProcRef {
    pub fn new(pid: u32, start_ts: Option<i64>) -> Self {
        Self { pid, start_ts }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    /// 프로세스 생성 (ETW Kernel-Process 1)
    ProcessStart {
        pid: u32,
        ppid: u32,
        image: String,
        /// 페이로드의 CreateTime(FILETIME). 프로세스 키의 재료. 없으면 이벤트 시각으로 대신한다
        /// (오프라인 로그용). 명세 4판 2-1: 이벤트 시각은 생성 시각과 수 ms 어긋나므로 키로 쓰지 않는다.
        #[serde(default)]
        create_time: Option<i64>,
    },
    /// 수집 시작 시 프로세스 스냅샷 (수집 전부터 살아 있던 프로세스). 명세 4판 2-2 시작 순서 ②.
    /// 같은 PID@CreateTime 의 ProcessStart 가 큐에 있으면 그쪽이 무시된다 (중복 제거).
    ProcessSnapshot {
        pid: u32,
        ppid: u32,
        image: String,
        create_time: i64,
        /// SCM 매핑: 이 PID 가 호스트하는 서비스 이름 목록 (svchost 공유 시 여러 개)
        #[serde(default)]
        services: Vec<String>,
    },
    /// SCM 매핑 갱신: 이 PID 의 서비스 목록 (1초 폴링). 시스템 서비스 판별 근거.
    /// system_token: 토큰이 SYSTEM/LocalService/NetworkService 인가 (못 열면 None)
    ServiceMap {
        pid: u32,
        services: Vec<String>,
        #[serde(default)]
        system_token: Option<bool>,
        /// 그 PID 의 생성 시각(FILETIME, GetProcessTimes). 노드 키 PID@생성시각과 정확히 맞춰 붙인다 —
        /// 시작 이벤트보다 먼저 오거나, 같은 PID 를 쓰던 예전 프로세스와 헷갈리지 않게(L048). 모르면 None(예전 형식)
        #[serde(default)]
        create_time: Option<i64>,
    },
    /// CAPI2 Build Chain Stop(11): 리프 인증서 subjectName, 체인의 인증서 fileRef(SHA-1 지문) 목록.
    /// run-9 실측: 11 과 41 의 TaskId 는 서로 다르다(별개 작업). 조인 키는 fileRef.
    CertChain {
        pid: u32,
        subject: String,
        task_id: String,
        #[serde(default)]
        chain_refs: Vec<String>,
    },
    /// CAPI2 Verify Revocation Stop(41): CRL/OCSP url 과 검사 대상 인증서 fileRef
    RevocationFetch {
        pid: u32,
        task_id: String,
        url: String,
        #[serde(default)]
        cert_ref: Option<String>,
    },
    /// 서명 검증 결과 (오프라인 WinVerifyTrust, 카탈로그 포함)
    Signature {
        path: String,
        signer: Option<String>,
        issuer: Option<String>,
        /// "valid" | "nosignature" | "untrusted:root" | "untrusted:distrusted" | "untrusted:bad_digest" | "error:<hresult>" (예전 "untrusted" = 루트·불신 구분 전)
        status: String,
        catalog: bool,
    },
    /// 프로세스의 로그온 세션 (A30, 22차 Q6): 여러 사용자가 쓰는 PC 에서 일반 사용자는 자기 세션 + 시스템(0)만 본다.
    /// ProcessStart·ProcessSnapshot 바로 뒤에 따로 보낸다(기존 이벤트 형식을 바꾸지 않으려고). 노드 `pid@create_time` 의 속성 `session`.
    ProcessSession {
        pid: u32,
        create_time: i64,
        session: u32,
    },
    /// 프로세스 명령줄 (10판 5-9). Kernel-Process 시작 이벤트에는 명령줄이 없어(poc3 스키마 확인) 수집기가 시작 직후
    /// 그 프로세스에서 읽는다. 명령줄에는 암호·토큰이 들어갈 수 있어 **복구 수단을 다루는 도구 몇 개만** 읽는다(수집기 T1490_TOOLS).
    /// ProcessStart 바로 뒤에 따로 보낸다(기존 이벤트 형식을 바꾸지 않으려고)
    ProcessCommand {
        proc: ProcRef,
        cmdline: String,
        /// 29차 Q1: 이미지 이름이 바뀐 복사본이면 버전 리소스의 원래 이름(OriginalFileName, 예: "vssadmin.exe"). 이름이 같으면 None
        #[serde(default)]
        tool: Option<String>,
    },
    /// 프로세스 종료 (ETW Kernel-Process 2)
    ProcessStop { pid: u32 },
    /// DNS 조회 (ETW DNS-Client 3006/3008/3020). results 는 응답이 있을 때만.
    DnsQuery {
        proc: ProcRef,
        name: String,
        results: Vec<String>,
    },
    /// TCP 연결 시도·수락 또는 UDP 송신 (ETW Kernel-Network 12/15/28/31/42/58)
    Connect {
        proc: ProcRef,
        proto: Proto,
        direction: Direction,
        laddr: String,
        lport: u16,
        raddr: String,
        rport: u16,
    },
    /// 파일 생성 (ETW Kernel-File, 실행 파일·스크립트 한정)
    FileWrite { proc: ProcRef, path: String },
    /// 감시 경로의 파일 열기 (ETW Kernel-File Create, 17판 23-2 ②). 브라우저 금고 파일·미끼 파일(graph::vault)만 보낸다.
    /// 열었다는 사실뿐이다 — 무엇을 읽었는지는 모른다
    FileOpen { proc: ProcRef, path: String },
    /// 다운로드 출처 (Zone.Identifier)
    Downloaded {
        path: String,
        host_url: Option<String>,
        referrer_url: Option<String>,
        #[serde(default)]
        zone_id: Option<u32>,
    },
    /// 자동 실행 등록 (Run 키·예약 작업 대조)
    AutorunRegistered {
        proc: ProcRef,
        location: String,
        target: String,
    },
    /// 코드 주입 (메모리 검사 또는 Sysmon 8/10/25)
    Injected {
        from: ProcRef,
        into: ProcRef,
        method: String,
    },
    /// 파일 해시 (A20). 서명 없음·MOTW 실행 파일만. 해시를 못 구하면 sha256=None, note 에 사유(too_large|unreadable:..)
    FileHash {
        path: String,
        sha256: Option<String>,
        size: u64,
        #[serde(default)]
        note: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Out,
    In,
}

/// 수집기가 그래프에 넘기는 단위
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Windows FILETIME (100ns since 1601-01-01)
    pub ts: i64,
    /// 출처 식별자. 예: "etw:process", "etw:network", "etw:dns", "conntable", "motw"
    pub source: String,
    #[serde(flatten)]
    pub kind: EventKind,
}

impl Event {
    pub fn new(ts: i64, source: &str, kind: EventKind) -> Self {
        Self {
            ts,
            source: source.to_string(),
            kind,
        }
    }
}
