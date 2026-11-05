//! 출신 성분 작업 큐 (명세 5판 2-3): Zone.Identifier 읽기 + 서명 검증을 저우선 스레드에서
//!
//! - ADS 생성 이벤트(`<path>:Zone.Identifier`)는 내용을 쓰기 전일 수 있어 1초 뒤에 읽는다. 빈 스트림이면 1회 재시도.
//! - ProcessStart 이미지는 즉시 큐에 넣고, 실행 시점에 다시 읽어 보정한다.
//! - 서명 검증 결과는 (경로, 크기, 수정시각) 으로 캐시한다.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use graph::event::{Event, EventKind};

use crate::ctx::Ctx;
use crate::pipeline::now_filetime;
use crate::signature;

#[derive(Debug, Clone)]
pub struct OriginJob {
    pub path: String,
    pub due: Instant,
    /// MOTW 를 읽을지 (ADS 이벤트·실행 시)
    pub motw: bool,
    /// 서명을 검증할지 (실행 파일만)
    pub sign: bool,
    pub retried: bool,
}

/// Zone.Identifier ADS 파싱: (ZoneId, HostUrl, ReferrerUrl)
pub fn parse_motw(text: &str) -> (Option<u32>, Option<String>, Option<String>) {
    let mut zone = None;
    let mut host = None;
    let mut referrer = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("ZoneId=") {
            zone = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("HostUrl=") {
            host = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("ReferrerUrl=") {
            referrer = Some(v.trim().to_string());
        }
    }
    (zone, host, referrer)
}

pub fn read_motw(path: &str) -> Option<(Option<u32>, Option<String>, Option<String>)> {
    let ads = format!("{path}:Zone.Identifier");
    let text = std::fs::read_to_string(&ads).ok()?;
    if text.trim().is_empty() {
        return None;
    }
    Some(parse_motw(&text))
}

fn file_stamp(path: &str) -> Option<(u64, u64)> {
    let m = std::fs::metadata(path).ok()?;
    let mtime = m
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some((m.len(), mtime))
}

/// 작업 스레드 본체. `stop` 이 true 가 되고 큐가 비면 끝난다.
/// 해시할 실행 파일·스크립트 확장자 (A20)
const HASH_EXT: &[&str] = &[
    ".exe", ".dll", ".scr", ".com", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".msi", ".lnk",
    ".sys",
];

fn hashable(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    HASH_EXT.iter().any(|x| l.ends_with(x))
}

/// 실행 직후 먼저 읽어 둘 해시의 크기 상한. 서명 검증(수십~수백 ms) 전에 읽어 실행 직후 파일을 바꾸는 창을 줄인다 (14~17차 답변 A1)
const EARLY_HASH_MAX: u64 = 64 * 1024 * 1024;

/// 실행 시점에 바로 계산한 해시 (아직 낼지 모름: 서명 없음·MOTW 일 때만 낸다)
type Early = Option<graph::hash::HashOutcome>;

fn early_hash(path: &str, done: &std::collections::HashSet<(String, u64, u64)>) -> Early {
    let (len, mtime) = file_stamp(path)?;
    if len > EARLY_HASH_MAX
        || done.contains(&(path.to_ascii_lowercase(), len, mtime))
        || !hashable(path)
    {
        return None;
    }
    Some(graph::hash::sha256_file(path))
}

/// (경로, 크기, 수정시각) 이 처음이면 해시 이벤트를 낸다. 같은 파일을 실행할 때마다 다시 읽지 않는다.
/// `early` 가 있으면 그 결과(실행 직후 읽은 것)를 쓴다.
fn emit_hash(
    ctx: &Ctx,
    path: &str,
    done: &mut std::collections::HashSet<(String, u64, u64)>,
    ts: i64,
    early: &mut Early,
) -> bool {
    let Some((len, mtime)) = file_stamp(path) else {
        // 이미 지워졌어도 실행 직후 읽은 해시가 있으면 그것을 낸다
        if let Some(graph::hash::HashOutcome::Ok { sha256, size }) = early.take() {
            ctx.emit(Event::new(
                ts,
                "hash",
                EventKind::FileHash {
                    path: path.to_string(),
                    sha256: Some(sha256),
                    size,
                    note: Some("file_gone_after_exec".into()),
                },
            ));
            return true;
        }
        return false;
    };
    if !done.insert((path.to_ascii_lowercase(), len, mtime)) {
        return false;
    }
    let outcome = early
        .take()
        .unwrap_or_else(|| graph::hash::sha256_file(path));
    let (sha256, size, note) = match outcome {
        graph::hash::HashOutcome::Ok { sha256, size } => (Some(sha256), size, None),
        graph::hash::HashOutcome::TooLarge { size } => (None, size, Some("too_large".to_string())),
        graph::hash::HashOutcome::Unreadable(e) => (None, len, Some(format!("unreadable:{e}"))),
    };
    ctx.emit(Event::new(
        ts,
        "hash",
        EventKind::FileHash {
            path: path.to_string(),
            sha256,
            size,
            note,
        },
    ));
    true
}

pub fn worker(
    rx: Receiver<OriginJob>,
    ctx: Arc<Ctx>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> (u64, u64) {
    let mut pending: Vec<OriginJob> = Vec::new();
    let mut sig_cache: HashMap<(String, u64, u64), signature::SigResult> = HashMap::new();
    let mut hashed: std::collections::HashSet<(String, u64, u64)> =
        std::collections::HashSet::new();
    let (mut motw_found, mut sigs_done) = (0u64, 0u64);
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(j) => pending.push(j),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        let now = Instant::now();
        let mut i = 0;
        while i < pending.len() {
            if pending[i].due > now {
                i += 1;
                continue;
            }
            let job = pending.remove(i);
            let ts = now_filetime();
            // 실행 파일 작업(서명 검증 대상)은 다른 일보다 먼저 해시를 읽어 둔다
            let mut early: Early = if job.sign {
                early_hash(&job.path, &hashed)
            } else {
                None
            };
            if job.motw {
                match read_motw(&job.path) {
                    Some((zone_id, host_url, referrer_url)) => {
                        motw_found += 1;
                        ctx.emit(Event::new(
                            ts,
                            "motw",
                            EventKind::Downloaded {
                                path: job.path.clone(),
                                host_url,
                                referrer_url,
                                zone_id,
                            },
                        ));
                        // 인터넷에서 받은 실행 파일: 해시 (A20)
                        if hashable(&job.path)
                            && emit_hash(&ctx, &job.path, &mut hashed, ts, &mut early)
                        {
                            ctx.hashes
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    None if !job.retried => {
                        // 아직 안 쓰였을 수 있다: 1초 뒤 1회 재시도
                        pending.push(OriginJob {
                            due: Instant::now() + Duration::from_secs(1),
                            retried: true,
                            sign: false,
                            ..job.clone()
                        });
                    }
                    None => {}
                }
            }
            if job.sign {
                if let Some((len, mtime)) = file_stamp(&job.path) {
                    let key = (job.path.to_ascii_lowercase(), len, mtime);
                    let r = sig_cache
                        .entry(key)
                        .or_insert_with(|| signature::verify(&job.path))
                        .clone();
                    sigs_done += 1;
                    let unsigned = r.status != "valid";
                    ctx.emit(Event::new(
                        ts,
                        "signature",
                        EventKind::Signature {
                            path: job.path.clone(),
                            signer: r.signer,
                            issuer: r.issuer,
                            status: r.status,
                            catalog: r.catalog,
                        },
                    ));
                    // 서명 없는(또는 신뢰 안 되는) 실행 파일: 해시 (A20). 서명된 파일은 서명이 정체를 묶는다.
                    if unsigned && emit_hash(&ctx, &job.path, &mut hashed, ts, &mut early) {
                        ctx.hashes
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                } else if early.is_some() && emit_hash(&ctx, &job.path, &mut hashed, ts, &mut early)
                {
                    // 서명 검증 전에 파일이 사라졌다(실행 직후 삭제): 먼저 읽어 둔 해시를 "실행 뒤 사라짐" 사유와 함께 남긴다
                    ctx.hashes
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        if stop.load(std::sync::atomic::Ordering::Relaxed) && pending.is_empty() {
            break;
        }
    }
    (motw_found, sigs_done)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hashable_extensions() {
        assert!(
            hashable(r"C:\Temp\A.EXE")
                && hashable("x.ps1")
                && !hashable("report.pdf")
                && !hashable("exe")
        );
    }
    #[test]
    fn parses_zone_identifier() {
        let (z, h, r) = parse_motw(
            "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://a/\r\nHostUrl=https://b/x.exe\r\n",
        );
        assert_eq!(z, Some(3));
        assert_eq!(h.as_deref(), Some("https://b/x.exe"));
        assert_eq!(r.as_deref(), Some("https://a/"));
    }
}
