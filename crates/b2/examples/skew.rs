//! 진단: Sysmon 네트워크·DNS 사건별 (우리 − Sysmon) 가장 가까운 차이와 그 열쇠의 우리 쪽 사건 수
use b2::*;
use std::collections::HashMap;
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let ours = load_ours(&a[1]).unwrap();
    let (sys, _, _) = load_sysmon(&std::fs::read_to_string(&a[2]).unwrap());
    let mut idx: HashMap<&Key, Vec<i64>> = HashMap::new();
    for (t, k) in &ours { idx.entry(k).or_default().push(*t); }
    for (t, k, img) in &sys {
        let cat = match k { Key::Net { .. } => "net", Key::Dns { .. } => "dns", _ => continue };
        let v = idx.get(k);
        let d = v.and_then(|v| v.iter().map(|o| o - t).min_by_key(|x| x.abs()));
        let n = v.map(|v| v.len()).unwrap_or(0);
        let near0 = v.map(|v| v.iter().filter(|o| ((*o - t) as i64).abs() < 20_000_000).count()).unwrap_or(0);
        let nearoff = v.map(|v| v.iter().filter(|o| ((*o - t - 1_527_940_000) as i64).abs() < 20_000_000).count()).unwrap_or(0);
        println!("{}\t{}\t{}\t{}\t{}\t{}\t{}", filetime_to_utc(*t), cat, d.map(|x| format!("{:.1}", x as f64 / 1e7)).unwrap_or("-".into()), n, near0, nearoff, base_name_pub(img));
    }
}
fn base_name_pub(s: &str) -> String { s.rsplit('\\').next().unwrap_or(s).to_lowercase() }
