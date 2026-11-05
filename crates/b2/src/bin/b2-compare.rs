//! B2 비교 실행 파일
//!
//! 사용: b2-compare <collector.db> <sysmon.jsonl> <구간 시작 UTC> <구간 끝 UTC> [--tolerance-ms 2000] [--exclude a.exe,b.exe] [--json out.json] [--out report.txt]
//! 시각 형식: "YYYY-MM-DD hh:mm:ss.fff" (UTC). 결과는 표준 출력(사람용) + --json(기계용).

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("사용: b2-compare <collector.db> <sysmon.jsonl> <from UTC> <to UTC> [--tolerance-ms N] [--exclude a.exe,b.exe] [--json out.json]");
        std::process::exit(2);
    }
    let opt_val = |name: &str| {
        a.iter()
            .position(|x| x == name)
            .and_then(|i| a.get(i + 1))
            .cloned()
    };
    let from = b2::utc_to_filetime(&a[3]).unwrap_or_else(|| fail("구간 시작 형식"));
    let to = b2::utc_to_filetime(&a[4]).unwrap_or_else(|| fail("구간 끝 형식"));
    let tol_ms: i64 = opt_val("--tolerance-ms")
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let mut exclude: Vec<String> = vec![
        "sysmon.exe".into(),
        "sysmon64.exe".into(),
        "collector-poc.exe".into(),
        "b2-compare.exe".into(),
    ];
    if let Some(v) = opt_val("--exclude") {
        exclude.extend(
            v.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty()),
        );
    }

    let ours = b2::load_ours(&a[1]).unwrap_or_else(|e| fail(&format!("collector.db: {e}")));
    let text = std::fs::read_to_string(&a[2]).unwrap_or_else(|e| fail(&format!("sysmon: {e}")));
    let (sys, n, bad) = b2::load_sysmon(&text);
    let rep = b2::compare(
        &sys,
        &ours,
        &b2::Options {
            from,
            to,
            tolerance: tol_ms * 10_000,
            exclude_images: exclude,
            examples: 15,
        },
    );

    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(
        o,
        "B2 누락률 — 구간 {} ~ {} (허용치 {}ms)",
        b2::filetime_to_utc(from),
        b2::filetime_to_utc(to),
        tol_ms
    );
    let _ = writeln!(
        o,
        "sysmon_lines={n} sysmon_bad={bad} sysmon_keyed={} ours_keyed={} sysmon_etw_offset_ms={}",
        sys.len(),
        ours.len(),
        rep.sysmon_etw_offset / 10_000
    );
    let _ = writeln!(
        o,
        "{:<20} {:>8} {:>8} {:>8} {:>9} {:>10} {:>10} {:>9}",
        "category", "sysmon", "matched", "missed", "miss%", "ours_only", "by_offset", "boundary"
    );
    for (c, s) in &rep.categories {
        let _ = writeln!(
            o,
            "{:<20} {:>8} {:>8} {:>8} {:>8.2}% {:>10} {:>10} {:>9}",
            c,
            s.sysmon,
            s.matched,
            s.missed,
            s.miss_rate_pct,
            s.ours_only,
            s.matched_by_offset,
            s.boundary_skipped
        );
    }
    for (c, s) in &rep.categories {
        for e in &s.missed_examples {
            let _ = writeln!(o, "missed[{c}] {e}");
        }
    }
    print!("{o}");
    // PowerShell 파이프는 네이티브 출력을 콘솔 코드페이지로 해석해 한글이 깨진다 — 파일은 직접 UTF-8 로 쓴다
    if let Some(p) = opt_val("--out") {
        let _ = std::fs::write(&p, &o);
    }
    if let Some(p) = opt_val("--json") {
        let _ = std::fs::write(&p, serde_json::to_string_pretty(&rep).unwrap_or_default());
    }
}

fn fail(m: &str) -> ! {
    eprintln!("[error] {m}");
    std::process::exit(2)
}
