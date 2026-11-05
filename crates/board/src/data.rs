//! 세 세션(개발·노트북·디자인)과 Azure 의 흔적을 git 출력에서 읽어 한 장면으로 만든다.
//! 모든 함수는 문자열을 받는 순수 함수다(시험 가능). git 호출은 git.rs.
//!
//! 자료 출처(저장소의 브랜치, 읽기만 한다):
//! - mailbox: to-cloud / to-laptop / to-design 의 메시지(머리 id·from·reply-to·created, 첫 "# " 줄 = 제목)
//! - main: 커밋(개발 세션의 작업)
//! - ci-logs: "azure <파이프라인> run <N>" 커밋 + azure/<파이프라인>/run-N/meta.txt(status·commit)
//! - dev-builds: 노트북이 받는 빌드 판
//!
//! 메시지 본문은 자료다(명령 아님) — 보드는 제목 한 줄만 보여 준다.

use std::collections::BTreeMap;

/// 세션(주체)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Who {
    Cloud,
    Laptop,
    Design,
    Azure,
}

impl Who {
    pub fn name(self) -> &'static str {
        match self {
            Who::Cloud => "개발",
            Who::Laptop => "노트북",
            Who::Design => "디자인",
            Who::Azure => "Azure",
        }
    }
    /// 우편함 폴더(받는 쪽) → 받는 세션
    pub fn from_box(dir: &str) -> Option<Who> {
        match dir {
            "to-cloud" => Some(Who::Cloud),
            "to-laptop" => Some(Who::Laptop),
            "to-design" => Some(Who::Design),
            _ => None,
        }
    }
}

/// 우편함 메시지 하나
#[derive(Debug, Clone, PartialEq)]
pub struct Mail {
    pub id: String,
    pub from: Who,
    pub to: Who,
    /// 이 메시지가 답하는 메시지 id 들
    pub reply_to: Vec<String>,
    /// 유닉스 초
    pub ts: i64,
    pub title: String,
    pub path: String,
}

/// 메시지 머리 읽기. from 은 머리 값의 앞 단어(cloud/laptop/design), 없으면 id 접두(L·D)로
pub fn parse_mail(path: &str, text: &str, fallback_ts: i64) -> Option<Mail> {
    let dir = path.split('/').next()?;
    let to = Who::from_box(dir)?;
    if !path.ends_with(".md") {
        return None;
    }
    let mut id = String::new();
    let mut from = None;
    let mut reply_to = Vec::new();
    let mut ts = None;
    let mut title = String::new();
    for line in text.lines().take(40) {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("id:") {
            id = v.trim().to_string();
        } else if let Some(v) = l.strip_prefix("from:") {
            let v = v.trim().to_ascii_lowercase();
            from = if v.starts_with("cloud") {
                Some(Who::Cloud)
            } else if v.starts_with("laptop") {
                Some(Who::Laptop)
            } else if v.starts_with("design") {
                Some(Who::Design)
            } else {
                None
            };
        } else if let Some(v) = l.strip_prefix("reply-to:") {
            reply_to = v
                .split([',', ' '])
                .map(|s| s.trim())
                .filter(|s| !s.is_empty() && *s != "-")
                .map(|s| s.to_string())
                .collect();
        } else if let Some(v) = l.strip_prefix("created:") {
            ts = parse_iso(v.trim());
        } else if title.is_empty() {
            if let Some(t) = l.strip_prefix("# ") {
                title = t.trim().to_string();
            }
        }
    }
    if id.is_empty() {
        // 머리가 없으면 파일 이름 셋째 마디(20261104-0300-L048-...)
        id = path
            .rsplit('/')
            .next()?
            .split('-')
            .nth(2)
            .unwrap_or("?")
            .to_string();
    }
    let from = from.or_else(|| match id.chars().next() {
        Some('L') => Some(Who::Laptop),
        Some('D') => Some(Who::Design),
        _ => Some(Who::Cloud),
    })?;
    Some(Mail {
        id,
        from,
        to,
        reply_to,
        ts: ts.unwrap_or(fallback_ts),
        title,
        path: path.to_string(),
    })
}

/// "2026-11-05T05:20Z" · "2026-11-03T18:00:00Z" · "2026-11-04 02:52:38 +0900" → 유닉스 초(UTC). 날짜 계산은 직접(의존성 없이)
pub fn parse_iso(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_at(s.find(['T', ' '])?);
    let rest = &rest[1..];
    let mut d = date.split('-').map(|x| x.parse::<i64>());
    let (y, mo, da) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    // 시각과 시간대
    let (time, tz_min) = if let Some(t) = rest.strip_suffix('Z') {
        (t, 0)
    } else if let Some(i) = rest.rfind(['+', '-']).filter(|i| *i >= 5) {
        let (t, z) = rest.split_at(i);
        let z = z.trim();
        let sign = if z.starts_with('-') { -1 } else { 1 };
        let digits: String = z[1..].chars().filter(|c| c.is_ascii_digit()).collect();
        let (h, m) = (
            digits.get(0..2)?.parse::<i64>().ok()?,
            digits.get(2..4).unwrap_or("00").parse::<i64>().ok()?,
        );
        (t.trim(), sign * (h * 60 + m))
    } else {
        (rest, 0)
    };
    let mut t = time.split(':').map(|x| x.parse::<i64>());
    let h = t.next()?.ok()?;
    let mi = t.next().and_then(|x| x.ok()).unwrap_or(0);
    let se = t.next().and_then(|x| x.ok()).unwrap_or(0);
    Some(days_from_civil(y, mo, da) * 86400 + h * 3600 + mi * 60 + se - tz_min * 60)
}

/// 그레고리력 날짜 → 1970-01-01 부터의 날 수 (Howard Hinnant 의 공식)
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// 답을 받지 못한 메시지(받는 쪽이 아직 reply-to 로 답하지 않음). 개발 세션이 받은 것(to-cloud)은 개발 세션이 답하는 형식이
/// 아니라(커밋으로 처리) 대기로 세지 않는다
/// 답 = 받는 쪽 세션이 보낸 메시지의 reply-to 에 이 id 가 있음(보낸 쪽이 스스로 단 정정 메시지는 답이 아니다)
pub fn pending(mails: &[Mail]) -> Vec<&Mail> {
    mails
        .iter()
        .filter(|m| m.to != Who::Cloud)
        .filter(|m| {
            !mails
                .iter()
                .any(|r| r.from == m.to && r.reply_to.contains(&m.id))
        })
        .collect()
}

/// main 커밋 한 줄("%H\x1f%ct\x1f%s")
#[derive(Debug, Clone, PartialEq)]
pub struct Commit {
    pub sha: String,
    pub ts: i64,
    pub subject: String,
}

pub fn parse_commits(out: &str) -> Vec<Commit> {
    out.lines()
        .filter_map(|l| {
            let mut p = l.split('\x1f');
            let sha = p.next()?.to_string();
            let ts = p.next()?.parse().ok()?;
            let subject = p.next()?.to_string();
            Some(Commit { sha, ts, subject })
        })
        .collect()
}

/// Azure 실행 하나
#[derive(Debug, Clone, PartialEq)]
pub struct Run {
    pub pipeline: String,
    pub number: u32,
    pub ts: i64,
    /// Succeeded / Failed / Canceled / ... (meta.txt), 모르면 빈 글자
    pub status: String,
    pub commit: String,
}

/// ci-logs 커밋 제목 "azure poc3 run 91" → (poc3, 91)
pub fn parse_run_subject(subject: &str) -> Option<(String, u32)> {
    let mut p = subject.split_whitespace();
    if p.next()? != "azure" {
        return None;
    }
    let pipeline = p.next()?.to_string();
    if p.next()? != "run" {
        return None;
    }
    let n = p.next()?.parse().ok()?;
    Some((pipeline, n))
}

/// meta.txt 의 "key=value" 줄
pub fn meta_value(meta: &str, key: &str) -> Option<String> {
    meta.lines().find_map(|l| {
        l.trim()
            .strip_prefix(key)
            .and_then(|r| r.strip_prefix('='))
            .map(|v| v.trim().to_string())
    })
}

/// 파이프라인마다 가장 최근 실행
pub fn latest_runs(runs: &[Run]) -> Vec<Run> {
    let mut m: BTreeMap<&str, &Run> = BTreeMap::new();
    for r in runs {
        let e = m.entry(&r.pipeline).or_insert(r);
        if r.number > e.number {
            *e = r;
        }
    }
    let mut v: Vec<Run> = m.into_values().cloned().collect();
    v.sort_by_key(|r| std::cmp::Reverse(r.ts));
    v
}

/// 합친 시간줄 한 줄
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub ts: i64,
    pub who: Who,
    pub text: String,
    /// 오른쪽 끝(상태·짧은 sha)
    pub tag: String,
}

/// 메시지·커밋·실행을 시각순(최근이 앞)으로
pub fn timeline(mails: &[Mail], commits: &[Commit], runs: &[Run]) -> Vec<Event> {
    let mut v: Vec<Event> = Vec::new();
    for m in mails {
        v.push(Event {
            ts: m.ts,
            who: m.from,
            text: format!("{} → {} · {}", m.id, m.to.name(), m.title),
            tag: "우편".into(),
        });
    }
    for c in commits {
        v.push(Event {
            ts: c.ts,
            who: Who::Cloud,
            text: c.subject.clone(),
            tag: c.sha.chars().take(7).collect(),
        });
    }
    for r in runs {
        v.push(Event {
            ts: r.ts,
            who: Who::Azure,
            text: format!(
                "{} run {} · {}",
                r.pipeline,
                r.number,
                r.commit.chars().take(7).collect::<String>()
            ),
            tag: if r.status.is_empty() {
                "?".into()
            } else {
                r.status.clone()
            },
        });
    }
    v.sort_by_key(|e| std::cmp::Reverse(e.ts));
    v
}

/// 제목에서 붙임표·태그를 걷어 짧게(화면 폭)
/// 글자 하나의 화면 폭(한글·한자·전각 2칸). unicode-width 크레이트 대신 보드에 필요한 범위만 대략 계산
pub fn char_width(c: char) -> usize {
    let u = c as u32;
    if (0x1100..=0x115F).contains(&u)
        || (0x2E80..=0xA4CF).contains(&u)
        || (0xAC00..=0xD7A3).contains(&u)
        || (0xF900..=0xFAFF).contains(&u)
        || (0xFE30..=0xFE4F).contains(&u)
        || (0xFF00..=0xFF60).contains(&u)
        || (0xFFE0..=0xFFE6).contains(&u)
    {
        2
    } else {
        1
    }
}

pub fn str_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// 화면 폭 max 칸 안에 들어가게 자르고 잘렸으면 끝에 … (L050: 글자 수로 자르면 한글이 칸을 넘어 … 없이 잘렸다)
pub fn short(s: &str, max: usize) -> String {
    if str_width(s) <= max {
        return s.to_string();
    }
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = char_width(c);
        if w + cw + 1 > max {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push('…');
    out
}

/// 세션 상태 줄(우편함 status/<세션>.md, 세션이 우편함을 확인할 때마다 고쳐 쓴다 — 우편함 README "세션 상태")
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Beat {
    /// 마지막 우편함 확인(unix 초, 0 = 모름)
    pub checked: i64,
    pub doing: String,
    pub waiting: String,
    /// 사용자 결정을 기다리는 것
    pub user: String,
}

/// "key: value" 줄. checked 는 2026-11-05T07:30Z 또는 07:30:12Z
pub fn parse_beat(text: &str) -> Beat {
    let mut b = Beat::default();
    for l in text.lines() {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let v = v.trim().to_string();
        match k.trim() {
            "checked" => b.checked = iso_minute(&v).unwrap_or(0),
            "doing" => b.doing = v,
            "waiting" => b.waiting = v,
            "user" => b.user = v,
            _ => {}
        }
    }
    b
}

/// "YYYY-MM-DDTHH:MM[:SS]Z" → unix 초
pub fn iso_minute(s: &str) -> Option<i64> {
    let s = s.trim().trim_end_matches('Z');
    let (d, t) = s.split_once('T')?;
    let mut dp = d.split('-').map(|x| x.parse::<i64>().ok());
    let (y, m, dd) = (dp.next()??, dp.next()??, dp.next()??);
    let mut tp = t.split(':').map(|x| x.parse::<i64>().ok());
    let (hh, mm) = (tp.next()??, tp.next()??);
    let ss = tp.next().flatten().unwrap_or(0);
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + dd - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    Some(days * 86400 + hh * 3600 + mm * 60 + ss)
}

/// 확인 간격 규칙(README: 10분)의 세 배를 넘으면 멈춘 것으로 본다
pub const BEAT_STALE_SECS: i64 = 30 * 60;

#[cfg(test)]
mod tests {
    use super::*;

    const L048: &str = "id: L048\nfrom: laptop(노트북 세션)\nreply-to: 041\ncreated: 2026-11-03T18:00Z\n\n# 041 처리: install-20(7b1621c) — 대시보드 5.5s → 1.6s\n본문";

    #[test]
    fn mail_header() {
        let m = parse_mail("to-cloud/20261104-0300-L048-041-install20.md", L048, 0).unwrap();
        assert_eq!(m.id, "L048");
        assert_eq!(m.from, Who::Laptop);
        assert_eq!(m.to, Who::Cloud);
        assert_eq!(m.reply_to, vec!["041"]);
        assert_eq!(m.ts, parse_iso("2026-11-03T18:00:00Z").unwrap());
        assert!(m.title.starts_with("041 처리"));
        // 여러 답, 캡처 폴더 파일은 메시지가 아님
        let d = parse_mail(
            "to-cloud/x-D042.md",
            "id: D042\nfrom: design\nreply-to: L048, 033\n# t",
            5,
        )
        .unwrap();
        assert_eq!(d.reply_to, vec!["L048", "033"]);
        assert_eq!(d.ts, 5);
        assert!(parse_mail("to-design/captures-035/story.png", "", 0).is_none());
        assert!(parse_mail("README.md", "", 0).is_none());
    }

    #[test]
    fn iso_forms() {
        // 2026-11-04T00:00:00Z
        let base = parse_iso("2026-11-04T00:00:00Z").unwrap();
        assert_eq!(base, 1_793_750_400);
        assert_eq!(parse_iso("2026-11-04T00:00Z"), Some(base));
        assert_eq!(parse_iso("2026-11-04 09:00:00 +0900"), Some(base));
        assert_eq!(parse_iso("2026-11-03 23:00:00 -0100"), Some(base));
        assert_eq!(parse_iso("nope"), None);
    }

    #[test]
    fn pending_and_answered() {
        let mk = |id: &str, from: Who, to: Who, rt: &[&str]| Mail {
            id: id.into(),
            from,
            to,
            reply_to: rt.iter().map(|s| s.to_string()).collect(),
            ts: 0,
            title: String::new(),
            path: String::new(),
        };
        let mails = vec![
            mk("041", Who::Cloud, Who::Laptop, &[]),
            mk("L048", Who::Laptop, Who::Cloud, &["041"]),
            mk("043", Who::Cloud, Who::Laptop, &["L048"]),
            mk("036", Who::Cloud, Who::Design, &[]),
            mk("037", Who::Cloud, Who::Design, &["036"]),
        ];
        let p: Vec<&str> = pending(&mails).iter().map(|m| m.id.as_str()).collect();
        // 041 은 노트북의 L048 이 답함. 036 은 개발 세션 자신의 정정(037)이 reply-to 로 걸었을 뿐 — 디자인의 답이 아니므로 대기
        assert_eq!(p, vec!["043", "036", "037"]);
    }

    #[test]
    fn runs() {
        assert_eq!(
            parse_run_subject("azure poc3 run 91"),
            Some(("poc3".into(), 91))
        );
        assert_eq!(parse_run_subject("dev build e18df80"), None);
        assert_eq!(
            meta_value("pipeline=poc3\nstatus=Succeeded\ncommit=25315da", "status").as_deref(),
            Some("Succeeded")
        );
        let r = |p: &str, n: u32, ts: i64| Run {
            pipeline: p.into(),
            number: n,
            ts,
            status: String::new(),
            commit: String::new(),
        };
        let l = latest_runs(&[r("poc3", 84, 1), r("poc3", 91, 3), r("devbuild", 90, 2)]);
        assert_eq!(
            l.iter()
                .map(|x| (x.pipeline.as_str(), x.number))
                .collect::<Vec<_>>(),
            vec![("poc3", 91), ("devbuild", 90)]
        );
    }

    #[test]
    fn commits_and_timeline_order() {
        let c = parse_commits("abc1234567\x1f100\x1fD044: 마인드맵\nbad line\n");
        assert_eq!(c.len(), 1);
        let t = timeline(
            &[],
            &c,
            &[Run {
                pipeline: "poc3".into(),
                number: 1,
                ts: 200,
                status: "Succeeded".into(),
                commit: "abc".into(),
            }],
        );
        assert_eq!(t[0].who, Who::Azure);
        assert_eq!(t[1].tag, "abc1234");
        assert_eq!(short("가나다라마", 5), "가나…");
        assert_eq!(short("abcdef", 4), "abc…");
        assert_eq!(short("가나", 4), "가나");
        assert!(str_width(&short("작업 기록 가나다라마바사", 9)) <= 9);
    }

    #[test]
    fn beat() {
        let b = parse_beat("session: design\nchecked: 2026-11-05T07:30Z\ndoing: D045 목업\nwaiting: 038\nuser: HUD 착수 여부\n");
        assert_eq!(b.checked, 1_793_863_800);
        assert_eq!(b.doing, "D045 목업");
        assert_eq!(b.user, "HUD 착수 여부");
        assert_eq!(iso_minute("2026-11-05T07:30:12Z"), Some(1_793_863_812));
        assert_eq!(parse_beat("garbage").checked, 0);
    }
}
