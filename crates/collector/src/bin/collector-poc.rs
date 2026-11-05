//! A3 러너용 실행 파일: N초 수집 → SQLite → 통계·스키마·되감기 출력
//!
//! 사용: collector-poc <초> <db경로> [--experimental]
//! 통과 기준 (명세 4판 5장 P8): EventsLost 0, 채널 drop 0, CreateTime 필드 존재, CreateNewFile 파일명 포함.
//! 관리자 권한 필요.

#[cfg(windows)]
fn main() {
    use collector::{run, Config};
    use graph::query::rewind;
    use graph::{NodeKind, Store};
    use std::time::Duration;

    let args: Vec<String> = std::env::args().collect();
    let secs: u64 = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(20);
    let db = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "collector.db".into());
    let experimental = args.iter().any(|a| a == "--experimental");
    let _ = std::fs::remove_file(&db);
    println!("A3 collector-poc — {secs}초 수집 → {db} (experimental={experimental})");

    let cfg = Config {
        db_path: db.clone(),
        duration: Duration::from_secs(secs),
        experimental,
        ..Config::default()
    };
    let report = match run(cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[error] {e}");
            std::process::exit(2);
        }
    };

    println!("=== REPORT ===");
    println!("elapsed={:?}", report.elapsed);
    println!(
        "events_ingested={} edges_created={}",
        report.events_ingested, report.edges_created
    );
    println!(
        "dropped={} rate_limited={} missing_fields={}",
        report.dropped, report.rate_limited, report.missing_fields
    );
    println!(
        "clock: jumps={} max_jump_ms={}",
        report.clock_jumps, report.clock_max_jump_ms
    );
    println!(
        "snapshot_processes={} path_unknown={} scm_pids={} conntable_missed={} bytes_rows_flushed={} file_ring={}",
        report.snapshot_processes, report.snapshot_path_unknown, report.scm_pids, report.conntable_missed,
        report.bytes_rows_flushed, report.file_ring_len
    );
    let mut counts: Vec<_> = report.counts.iter().collect();
    counts.sort();
    println!("callback_counts={counts:?}");
    match (&report.session, report.session_error) {
        (Some(s), _) => println!(
            "session: events_lost={} realtime_buffers_lost={} log_buffers_lost={} buffers_written={} buffers={} free={}",
            s.events_lost, s.realtime_buffers_lost, s.log_buffers_lost, s.buffers_written, s.number_of_buffers, s.free_buffers
        ),
        (None, Some(e)) => println!("session: query failed rc={e}"),
        _ => {}
    }
    println!("schema_notes={:?}", report.schema_notes);
    println!(
        "skipped_no_client_pid={} chains_found={}",
        report.skipped_no_client_pid, report.chains_found
    );
    // 17판 23-2 ②: 열기 이벤트 부하와 금고·미끼 열기 수(counts 의 vault_open)
    println!(
        "vault: file_opens_seen={} vault_open={}",
        report.file_opens_seen,
        report.counts.get("vault_open").copied().unwrap_or(0)
    );
    println!(
        "P8: max_flush_ms={} max_flush_gap_ms={} max_bytes_rows_per_flush={}",
        report.max_flush_ms, report.max_flush_gap_ms, report.max_bytes_rows_per_flush
    );
    println!(
        "A4: motw_found={} signatures_done={} capi2_chains={} capi2_fetches={}",
        report.motw_found, report.signatures_done, report.capi2_chains, report.capi2_fetches
    );
    println!(
        "A20: hashes={} store_failed={}",
        report.hashes, report.store_failed
    );
    println!(
        "volumes={:?} rename_methods={:?}",
        report.volumes, report.rename_methods
    );
    println!("new_images={:?}", report.new_images);
    for l in &report.file_ring_tail {
        println!("ring: {l}");
    }
    let store0 = Store::open(&db).expect("db");
    {
        // A30 접점: 프로세스 노드에 로그온 세션이 붙는가 (ETW SessionID 필드 이름·스냅샷 ProcessIdToSessionId)
        let (with, all): (i64, i64) = store0
            .conn()
            .query_row("SELECT COUNT(json_extract(attrs_json, '$.session')), COUNT(*) FROM nodes WHERE kind = 'process'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap_or((0, 0));
        let etw: i64 = store0.conn().query_row("SELECT COUNT(*) FROM raw_events WHERE source = 'etw:process' AND payload_json LIKE '%process_session%'", [], |r| r.get(0)).unwrap_or(0);
        println!("A30: process_sessions={with}/{all} etw_session_events={etw}");
        // B2 실측 결함 회귀: 받은 TCP 연결의 로컬 포트 = 듣는 포트 (시나리오 P8 의 로컬 리스너 47555)
        let inbound_local: i64 = store0
            .conn()
            .query_row("SELECT COUNT(*) FROM raw_events WHERE source = 'etw:network' AND json_extract(payload_json, '$.direction') = 'in' AND json_extract(payload_json, '$.lport') = 47555", [], |r| r.get(0))
            .unwrap_or(0);
        let inbound_swapped: i64 = store0
            .conn()
            .query_row("SELECT COUNT(*) FROM raw_events WHERE source = 'etw:network' AND json_extract(payload_json, '$.direction') = 'in' AND json_extract(payload_json, '$.rport') = 47555", [], |r| r.get(0))
            .unwrap_or(0);
        println!(
            "B2fix: inbound_lport_47555={inbound_local} inbound_rport_47555={inbound_swapped}"
        );
    }
    {
        let mut st = store0
            .conn()
            .prepare("SELECT source, COUNT(*) FROM raw_events GROUP BY source ORDER BY 2 DESC")
            .unwrap();
        let rows: Vec<(String, i64)> = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .flatten()
            .collect();
        println!("raw_by_source={rows:?}");
    }

    // 스키마 기록 (stderr): 필드명 확정용. CreateTime·FileName 존재 여부를 여기서 읽는다.
    let store = Store::open(&db).expect("db");
    for (prov, id) in &report.schema_notes {
        if let Ok(Some(js)) = store.get_meta(&format!("schema:{prov}:{id}")) {
            eprintln!("[schema] {prov} id={id} {js}");
        }
    }
    for line in &report.experimental_dumps {
        eprintln!("[exp] {line}");
    }

    // 그래프 요약
    let conn = store.conn();
    let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap_or(-1) };
    println!(
        "nodes={} edges={} raw={}",
        store.count_nodes().unwrap_or(-1),
        store.count_edges().unwrap_or(-1),
        q("SELECT COUNT(*) FROM raw_events")
    );
    println!(
        "process_nodes={} (preexisting={}, unresolved={}) remote_nodes={} domain_nodes={} file_nodes={}",
        q("SELECT COUNT(*) FROM nodes WHERE kind='process'"),
        q("SELECT COUNT(*) FROM nodes WHERE kind='process' AND attrs_json LIKE '%\"preexisting\":true%'"),
        q("SELECT COUNT(*) FROM nodes WHERE kind='process' AND attrs_json LIKE '%\"unresolved\":true%'"),
        q("SELECT COUNT(*) FROM nodes WHERE kind='remote'"),
        q("SELECT COUNT(*) FROM nodes WHERE kind='domain'"),
        q("SELECT COUNT(*) FROM nodes WHERE kind='file'"),
    );
    println!(
        "connected={} connected_via={} resolved={} spawned={} wrote={}",
        q("SELECT COUNT(*) FROM edges WHERE rel='connected'"),
        q("SELECT COUNT(*) FROM edges WHERE rel='connected_via'"),
        q("SELECT COUNT(*) FROM edges WHERE rel='resolved'"),
        q("SELECT COUNT(*) FROM edges WHERE rel='spawned'"),
        q("SELECT COUNT(*) FROM edges WHERE rel='wrote'"),
    );
    // 도메인 부여율 (P7): remote 노드 중 domain 속성이 있는 비율
    println!(
        "remote_with_domain={} / remote_total={}",
        q("SELECT COUNT(*) FROM nodes WHERE kind='remote' AND attrs_json NOT LIKE '%\"domain\":null%'"),
        q("SELECT COUNT(*) FROM nodes WHERE kind='remote'"),
    );
    println!(
        "conn_bytes_rows={} total_sent={} total_recv={}",
        q("SELECT COUNT(*) FROM conn_bytes"),
        q("SELECT COALESCE(SUM(sent),0) FROM conn_bytes"),
        q("SELECT COALESCE(SUM(recv),0) FROM conn_bytes")
    );
    {
        let mut st = conn
            .prepare(
                "SELECT pid, raddr, rport, sent, recv FROM conn_bytes ORDER BY recv DESC LIMIT 5",
            )
            .unwrap();
        let rows: Vec<(i64, String, i64, i64, i64)> = st
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .unwrap()
            .flatten()
            .collect();
        println!("top_recv={rows:?}");
    }

    // 되감기: 세션 중 새로 생성된(preexisting 아님) 프로세스의 아웃바운드 접속마다 사슬을 출력
    let mut stmt = conn
        .prepare(
            "SELECT e.dst, n.label, r.label FROM edges e
             JOIN nodes n ON n.id = e.src JOIN nodes r ON r.id = e.dst
             WHERE e.rel='connected' AND n.kind='process' AND n.attrs_json NOT LIKE '%\"preexisting\":true%'
             ORDER BY e.ts LIMIT 40",
        )
        .unwrap();
    let rows: Vec<(i64, String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .filter_map(|x| x.ok())
        .collect();
    println!("=== REWIND (new processes' connections) ===");
    for (remote, proc_label, remote_label) in rows {
        let steps = rewind(&store, remote, 6).unwrap_or_default();
        let chain: Vec<String> = steps
            .iter()
            .map(|s| format!("{}:{}", s.node.kind, s.node.label))
            .collect();
        println!("{proc_label} -> {remote_label} :: {}", chain.join(" <- "));
    }
    // 파일 사슬 (P9): wrote 선이 있는 파일과 그 파일을 실행한 프로세스
    let mut stmt = conn
        .prepare(
            "SELECT f.label, re.source, p.label FROM edges w
             JOIN nodes f ON f.id = w.dst JOIN raw_events re ON re.id = w.evidence_id
             JOIN edges x ON x.src = f.id AND x.rel='executed_as' JOIN nodes p ON p.id = x.dst
             WHERE w.rel='wrote' ORDER BY w.ts LIMIT 20",
        )
        .unwrap();
    println!("=== FILE CHAINS ===");
    for row in stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .flatten()
    {
        println!("file {} ({}) -> executed as {}", row.0, row.1, row.2);
    }
    // A4: 귀속 선 method/confidence, 출신·서명
    println!("=== CONNECTED_VIA (method/confidence) ===");
    let mut st = conn
        .prepare(
            "SELECT p.label, r.label, COALESCE(e.attrs_json,'') FROM edges e JOIN nodes p ON p.id=e.src JOIN nodes r ON r.id=e.dst
             WHERE e.rel='connected_via' ORDER BY e.ts LIMIT 40",
        )
        .unwrap();
    for row in st
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .flatten()
    {
        println!("{} -> {} {}", row.0, row.1, row.2);
    }
    println!("=== ORIGINS (MOTW) ===");
    let mut st = conn
        .prepare("SELECT f.label, o.host_url, o.referrer_url, COALESCE(f.attrs_json,'') FROM origins o JOIN nodes f ON f.id=o.file_node LIMIT 20")
        .unwrap();
    for row in st
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .unwrap()
        .flatten()
    {
        println!(
            "{} host={:?} referrer={:?} attrs={}",
            row.0, row.1, row.2, row.3
        );
    }
    println!("=== HASHES (A20: origins.sha256) ===");
    let mut st = conn
        .prepare("SELECT f.label, o.sha256, o.host_url FROM origins o JOIN nodes f ON f.id=o.file_node WHERE o.sha256 IS NOT NULL ORDER BY f.label LIMIT 20")
        .unwrap();
    for row in st
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .unwrap()
        .flatten()
    {
        println!("hash: {} sha256={} motw={}", row.0, row.1, row.2.is_some());
    }
    println!("=== SIGNATURES (files with sig_status) ===");
    let mut st = conn
        .prepare("SELECT label, attrs_json FROM nodes WHERE kind='file' AND attrs_json LIKE '%sig_status%' ORDER BY label LIMIT 60")
        .unwrap();
    for row in st
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .unwrap()
        .flatten()
    {
        println!("{} {}", row.0, row.1);
    }
    println!(
        "sig_summary: valid={} nosignature={} untrusted={} catalog={}",
        q(
            r#"SELECT COUNT(*) FROM nodes WHERE kind='file' AND attrs_json LIKE '%"sig_status":"valid"%'"#
        ),
        q(
            r#"SELECT COUNT(*) FROM nodes WHERE kind='file' AND attrs_json LIKE '%"sig_status":"nosignature"%'"#
        ),
        q(
            r#"SELECT COUNT(*) FROM nodes WHERE kind='file' AND attrs_json LIKE '%"sig_status":"untrusted%'"#
        ),
        q(r#"SELECT COUNT(*) FROM nodes WHERE kind='file' AND attrs_json LIKE '%"catalog":true%'"#),
    );
    let _ = NodeKind::Process;
    println!("END");
}

#[cfg(not(windows))]
fn main() {
    eprintln!("collector-poc 는 Windows 전용입니다.");
}
