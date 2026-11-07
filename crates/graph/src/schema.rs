//! SQLite 스키마 (이야기형 3판 3-1장)

pub const SCHEMA_VERSION: i64 = 3; // 2: conn_bytes (A3), 3: edges.attrs_json (A4 귀속 method/confidence)

pub const DDL: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- 노드: 프로세스·파일·원격지·도메인·자동실행 항목·사용자 행동
CREATE TABLE IF NOT EXISTS nodes (
  id        INTEGER PRIMARY KEY,
  kind      TEXT NOT NULL,            -- process / file / remote / domain / autorun / user_action / command
  key       TEXT NOT NULL,            -- process: "PID@생성시각" / file: 경로 / remote: ip:port / domain: 이름
  label     TEXT,                     -- 화면 표시 이름
  first_ts  INTEGER,
  last_ts   INTEGER,
  attrs_json TEXT,                    -- 서명자, MOTW HostUrl, 국가·ASN, 부모 키 등
  UNIQUE(kind, key)
);

-- 선: 실행함·만듦·다운로드함·접속함·조회함·등록함·주입함
CREATE TABLE IF NOT EXISTS edges (
  id          INTEGER PRIMARY KEY,
  src         INTEGER NOT NULL REFERENCES nodes(id),
  dst         INTEGER NOT NULL REFERENCES nodes(id),
  rel         TEXT NOT NULL,
  ts          INTEGER NOT NULL,
  evidence_id INTEGER REFERENCES raw_events(id),  -- "모든 문장에 근거" 원칙
  chapter     INTEGER,                             -- 4장 판정 (1~4, NULL=평범)
  attrs_json  TEXT                                 -- connected_via: method(capi2|window), confidence(high|low)
);

-- 원시 이벤트: 7일 보관
CREATE TABLE IF NOT EXISTS raw_events (
  id           INTEGER PRIMARY KEY,
  ts           INTEGER NOT NULL,
  source       TEXT NOT NULL,         -- etw:process / etw:network / etw:dns / conntable / motw ...
  payload_json TEXT NOT NULL
);

-- 출신 기록: 장기 보관 (서명 없음 또는 MOTW 있는 실행 파일만)
CREATE TABLE IF NOT EXISTS origins (
  file_node    INTEGER PRIMARY KEY REFERENCES nodes(id),
  host_url     TEXT,
  referrer_url TEXT,
  via_process  TEXT,
  signer       TEXT,
  first_seen   INTEGER,
  sha256       TEXT,                 -- A20: 처음 본 내용의 해시 (교체 감지·끊기/격리 확인용)
  sha256_ts    INTEGER
);

-- 선 하나에 근거가 여럿일 때 (합쳐진 DNS 조회 등). edges.evidence_id 는 첫 근거.
CREATE TABLE IF NOT EXISTS edge_evidence (
  edge_id  INTEGER NOT NULL REFERENCES edges(id) ON DELETE CASCADE,
  raw_id   INTEGER NOT NULL REFERENCES raw_events(id),
  PRIMARY KEY(edge_id, raw_id)
);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);

-- 연결별 송수신 바이트 (F2). 수집기가 1초마다 증분을 더한다 (명세 4판 2-2: 용량 이벤트는 집계만).
CREATE TABLE IF NOT EXISTS conn_bytes (
  pid      INTEGER NOT NULL,
  proto    TEXT    NOT NULL,
  raddr    TEXT    NOT NULL,
  rport    INTEGER NOT NULL,
  sent     INTEGER NOT NULL DEFAULT 0,
  recv     INTEGER NOT NULL DEFAULT 0,
  first_ts INTEGER NOT NULL,
  last_ts  INTEGER NOT NULL,
  PRIMARY KEY(pid, proto, raddr, rport)
);

-- 시간대별 트래픽 요약(개편안 2판 1-4 / 사용자 2026-11-07: 집계는 조회 때가 아니라 쓰기 경로에서).
-- hour = unix 초를 3600 으로 내린 값. 수집기가 바이트를 더할 때·접속 선을 넣을 때 같이 올린다.
CREATE TABLE IF NOT EXISTS traffic_hourly (
  hour  INTEGER PRIMARY KEY,
  sent  INTEGER NOT NULL DEFAULT 0,
  recv  INTEGER NOT NULL DEFAULT 0,
  conns INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_edges_src ON edges(src, ts);
CREATE INDEX IF NOT EXISTS ix_edges_dst ON edges(dst, ts);
CREATE INDEX IF NOT EXISTS ix_edges_ts  ON edges(ts);
-- 연결 목록(connections.list) 전용 덮는 부분 색인: 표를 읽지 않고 (ts, src, dst) 만으로 접는다
CREATE INDEX IF NOT EXISTS ix_edges_conn ON edges(ts, src, dst) WHERE rel = 'connected';
CREATE INDEX IF NOT EXISTS ix_nodes_kind_ts ON nodes(kind, last_ts);
CREATE INDEX IF NOT EXISTS ix_raw_ts ON raw_events(ts);
-- L028: 스냅샷 시각 목록(이야기의 "이미 열려 있음")을 매 호출 전체 훑기 없이. 스냅샷 행만 담는 작은 부분 색인(쓰기 비용은 스냅샷 때만)
CREATE INDEX IF NOT EXISTS ix_raw_snapshot ON raw_events(ts) WHERE source = 'snapshot';
"#;
