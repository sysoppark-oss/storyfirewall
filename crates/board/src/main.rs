//! sf-board — 스토리방화벽을 만드는 세 세션(개발·노트북·디자인)과 Azure 의 움직임을 한 화면에 보는 터미널 보드.
//!
//! 사용: sf-board [--repo <저장소 폴더>] [--remote origin] [--days 2] [--interval 30] [--once]
//!   저장소 폴더는 story-firewall 클론(노트북의 작업 폴더 등). 원격 브랜치(main·mailbox·ci-logs·dev-builds)를 fetch 해서 읽기만 한다.
//!   --once: 한 번 그려 글자로 찍고 끝(터미널 없이 확인용).
//! 키: q·Esc 끝, r 지금 다시 읽기.

mod data;
mod git;

use data::{Event, Mail, Run, Who};
use ratatui::crossterm::event::{self, Event as CEvent, KeyCode, KeyEventKind};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn color(w: Who) -> Color {
    match w {
        Who::Cloud => Color::Rgb(232, 140, 92),
        Who::Laptop => Color::Rgb(110, 170, 240),
        Who::Design => Color::Rgb(180, 150, 240),
        Who::Azure => Color::Rgb(120, 210, 150),
    }
}
const DIM: Color = Color::Rgb(120, 128, 140);
const FG: Color = Color::Rgb(220, 224, 230);
const BAD: Color = Color::Rgb(235, 100, 100);

struct Args {
    repo: std::path::PathBuf,
    remote: String,
    days: u32,
    interval: u64,
    once: bool,
}

fn args() -> Args {
    let mut a = Args {
        repo: ".".into(),
        remote: "origin".into(),
        days: 2,
        interval: 30,
        once: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        match k.as_str() {
            "--repo" => a.repo = it.next().unwrap_or_else(|| ".".into()).into(),
            "--remote" => a.remote = it.next().unwrap_or_else(|| "origin".into()),
            "--days" => a.days = it.next().and_then(|v| v.parse().ok()).unwrap_or(2),
            "--interval" => {
                a.interval = it.next().and_then(|v| v.parse().ok()).unwrap_or(30).max(10)
            }
            "--once" => a.once = true,
            "-h" | "--help" => {
                println!(
                    "sf-board [--repo DIR] [--remote origin] [--days 2] [--interval 30] [--once]"
                );
                std::process::exit(0);
            }
            _ => {}
        }
    }
    a
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// "3분 전", "2시간 전", "1일 전"
fn ago(ts: i64, now: i64) -> String {
    let d = (now - ts).max(0);
    if d < 60 {
        format!("{d}초 전")
    } else if d < 3600 {
        format!("{}분 전", d / 60)
    } else if d < 86400 {
        format!("{}시간 전", d / 3600)
    } else {
        format!("{}일 전", d / 86400)
    }
}

/// 한국 시각 HH:MM:SS (보드는 사용자 시간대 KST 고정 — 세 세션이 같은 시계로 보이게)
fn kst(ts: i64) -> String {
    let t = (ts + 9 * 3600).rem_euclid(86400);
    format!("{:02}:{:02}:{:02}", t / 3600, (t / 60) % 60, t % 60)
}

/// 기록 줄 시각: 오늘(KST)이면 "HH:MM:SS", 아니면 "MM-DD HH:MM"
fn kst_stamp(ts: i64, now: i64) -> String {
    let day = |x: i64| (x + 9 * 3600).div_euclid(86400);
    if day(ts) == day(now) {
        return kst(ts);
    }
    let (_, m, d) = civil_from_days(day(ts));
    format!("{m:02}-{d:02} {}", &kst(ts)[..5])
}

/// 날 수 → (연, 월, 일) (Howard Hinnant)
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

#[cfg(test)]
mod tests {
    #[test]
    fn stamps() {
        // 2026-11-05 05:00Z = 14:00 KST
        let now = 1_793_854_800;
        assert_eq!(super::kst_stamp(now - 60, now), "13:59:00");
        assert_eq!(super::kst_stamp(now - 86400, now), "11-04 14:00");
        assert_eq!(super::civil_from_days(0), (1970, 1, 1));
    }
}

struct App {
    snap: git::Snapshot,
    last_read: i64,
    tick: u64,
    reading: bool,
}

fn main() {
    let a = args();
    let repo = git::Repo::new(&a.repo, &a.remote);
    if a.once {
        let _ = repo.fetch();
        let app = App {
            snap: repo.snapshot(a.days),
            last_read: now(),
            tick: 0,
            reading: false,
        };
        let backend = ratatui::backend::TestBackend::new(150, 46);
        let mut term = ratatui::Terminal::new(backend).expect("터미널");
        term.draw(|f| draw(f, &app)).expect("그리기");
        let buf = term.backend().buffer().clone();
        for y in 0..buf.area.height {
            let mut line = String::new();
            let mut skip = 0;
            for x in 0..buf.area.width {
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                let sym = buf[(x, y)].symbol();
                skip = unicode_width(sym).saturating_sub(1);
                line.push_str(sym);
            }
            println!("{}", line.trim_end());
        }
        return;
    }

    // 읽기는 뒤 스레드에서(화면이 git 을 기다리지 않게)
    let (req_tx, req_rx) = mpsc::channel::<()>();
    let (snap_tx, snap_rx) = mpsc::channel::<git::Snapshot>();
    let days = a.days;
    std::thread::spawn(move || {
        while req_rx.recv().is_ok() {
            // fetch 가 실패해도(오프라인) 이미 받아 둔 원격 브랜치로 그린다
            let fetched = repo.fetch();
            let mut s = repo.snapshot(days);
            if let Err(e) = fetched {
                s.error = Some(match s.error.take() {
                    Some(o) => format!("fetch: {e} · {o}"),
                    None => format!("fetch: {e}"),
                });
            }
            if snap_tx.send(s).is_err() {
                break;
            }
        }
    });
    let _ = req_tx.send(());

    let mut terminal = ratatui::init();
    let mut app = App {
        snap: git::Snapshot::default(),
        last_read: 0,
        tick: 0,
        reading: true,
    };
    let mut next = Instant::now() + Duration::from_secs(a.interval);
    loop {
        while let Ok(s) = snap_rx.try_recv() {
            app.snap = s;
            app.last_read = now();
            app.reading = false;
        }
        if Instant::now() >= next && !app.reading {
            app.reading = true;
            let _ = req_tx.send(());
            next = Instant::now() + Duration::from_secs(a.interval);
        }
        if terminal.draw(|f| draw(f, &app)).is_err() {
            break;
        }
        if event::poll(Duration::from_millis(200)).unwrap_or(false) {
            if let Ok(CEvent::Key(k)) = event::read() {
                if k.kind == KeyEventKind::Press {
                    match k.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('r') if !app.reading => {
                            app.reading = true;
                            let _ = req_tx.send(());
                            next = Instant::now() + Duration::from_secs(a.interval);
                        }
                        _ => {}
                    }
                }
            }
        }
        app.tick = app.tick.wrapping_add(1);
    }
    ratatui::restore();
}

/// 글자 폭(한글 등 넓은 글자 2칸) — --once 출력용
fn unicode_width(s: &str) -> usize {
    data::str_width(s).max(1)
}

fn boxed<'a>(title: Line<'a>, c: Color) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(c))
        .title(title)
}

fn draw(f: &mut Frame, app: &App) {
    let n = now();
    let s = &app.snap;
    let area = f.area();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(18),
            Constraint::Length(9),
            Constraint::Length(1),
        ])
        .split(area);

    // 머리
    let commits_today = s.commits.iter().filter(|c| n - c.ts < 86400).count();
    let mails_today = s.mails.iter().filter(|m| n - m.ts < 86400).count();
    let head = Line::from(vec![
        Span::styled(
            "STORY FIREWALL 세션 보드",
            Style::default().fg(FG).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ·  ", Style::default().fg(DIM)),
        Span::styled(
            format!("개발 커밋 {commits_today}"),
            Style::default().fg(color(Who::Cloud)),
        ),
        Span::styled("  ·  ", Style::default().fg(DIM)),
        Span::styled(
            format!("우편 {mails_today}"),
            Style::default().fg(color(Who::Design)),
        ),
        Span::styled("  ·  ", Style::default().fg(DIM)),
        Span::styled(
            format!(
                "Azure 실행 {}",
                s.runs.iter().filter(|r| n - r.ts < 86400).count()
            ),
            Style::default().fg(color(Who::Azure)),
        ),
        Span::styled(
            format!("   (최근 24시간)   {} KST", kst(n)),
            Style::default().fg(DIM),
        ),
    ]);
    f.render_widget(Paragraph::new(head).alignment(Alignment::Center), outer[0]);
    let legend = Line::from(
        [Who::Cloud, Who::Laptop, Who::Design, Who::Azure]
            .iter()
            .flat_map(|w| {
                let role = match w {
                    Who::Cloud => "코드·커밋·의뢰서",
                    Who::Laptop => "설치·실기기 시험",
                    Who::Design => "UI 조사·검수",
                    Who::Azure => "Windows 빌드·PoC",
                };
                vec![
                    Span::styled("■ ", Style::default().fg(color(*w))),
                    Span::styled(
                        format!("{} · {role}     ", w.name()),
                        Style::default().fg(DIM),
                    ),
                ]
            })
            .collect::<Vec<_>>(),
    );
    f.render_widget(
        Paragraph::new(legend).alignment(Alignment::Center),
        outer[1],
    );

    // 몸통: 왼쪽 레일 | 오른쪽(세션 상자 · 우편 흐름 · Azure)
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(36), Constraint::Min(60)])
        .split(outer[2]);
    draw_rail(f, body[0], app, n);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(12),
            Constraint::Length(5),
            Constraint::Min(6),
        ])
        .split(body[1]);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 3); 3])
        .split(right[0]);
    draw_session(f, cols[0], app, Who::Cloud, n);
    draw_session(f, cols[1], app, Who::Laptop, n);
    draw_session(f, cols[2], app, Who::Design, n);
    draw_flow(f, right[1], app, n);
    draw_azure(f, right[2], app, n);

    // 아래: 합친 시간줄 꼬리
    draw_log(f, outer[3], app, n);

    // 상태 줄
    let main = s
        .commits
        .first()
        .map(|c| c.sha.chars().take(7).collect::<String>())
        .unwrap_or_else(|| "-".into());
    let dev = s
        .devbuild
        .as_ref()
        .map(|(subj, ts)| {
            format!(
                "{} ({})",
                subj.split_whitespace()
                    .last()
                    .map(|x| x.chars().take(7).collect::<String>())
                    .unwrap_or_default(),
                ago(*ts, n)
            )
        })
        .unwrap_or_else(|| "-".into());
    let pend = data::pending(&s.mails).len();
    let mut st = vec![
        Span::styled("~/story-firewall $ ", Style::default().fg(DIM)),
        Span::styled("main ", Style::default().fg(DIM)),
        Span::styled(format!("[{main}]"), Style::default().fg(color(Who::Cloud))),
        Span::styled("   dev-builds ", Style::default().fg(DIM)),
        Span::styled(format!("[{dev}]"), Style::default().fg(color(Who::Laptop))),
        Span::styled("   답 기다림 ", Style::default().fg(DIM)),
        Span::styled(format!("[{pend}]"), Style::default().fg(color(Who::Design))),
        Span::styled(
            if app.reading {
                "   읽는 중…".to_string()
            } else {
                format!(
                    "   읽음 {}",
                    if app.last_read > 0 {
                        ago(app.last_read, n)
                    } else {
                        "-".into()
                    }
                )
            },
            Style::default().fg(DIM),
        ),
        Span::styled("   q 끝 · r 다시 읽기", Style::default().fg(DIM)),
    ];
    if let Some(e) = &s.error {
        st.push(Span::styled(
            format!(
                "   오류: {}",
                data::short(e, (outer[4].width as usize).saturating_sub(70).max(30))
            ),
            Style::default().fg(BAD),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(st)), outer[4]);
}

/// 왼쪽 레일: 답을 기다리는 메시지(◇) — 가장 오래 기다린 것이 위
fn draw_rail(f: &mut Frame, r: Rect, app: &App, n: i64) {
    let mut p: Vec<&Mail> = data::pending(&app.snap.mails);
    p.sort_by_key(|m| m.ts);
    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            "답을 기다리는 일",
            Style::default().fg(FG).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    if p.is_empty() {
        lines.push(Line::from(Span::styled(
            "  없음 — 모두 답을 받았다",
            Style::default().fg(DIM),
        )));
    }
    let w = r.width.saturating_sub(6) as usize;
    for m in p.iter().take(((r.height as usize).saturating_sub(4)) / 3) {
        lines.push(Line::from(vec![
            Span::styled("◇ ", Style::default().fg(color(m.to))),
            Span::styled(
                format!("{} ", m.id),
                Style::default()
                    .fg(color(m.from))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("→ {}", m.to.name()),
                Style::default().fg(color(m.to)),
            ),
            Span::styled(format!(" · {}", ago(m.ts, n)), Style::default().fg(DIM)),
        ]));
        lines.push(Line::from(Span::styled(
            format!("  {}", data::short(&m.title, w)),
            Style::default().fg(FG),
        )));
        lines.push(Line::from(""));
    }
    let blk = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(DIM));
    f.render_widget(Paragraph::new(lines).block(blk), r);
}

/// 세션 상자: 마지막 움직임 + 수
fn draw_session(f: &mut Frame, r: Rect, app: &App, who: Who, n: i64) {
    let s = &app.snap;
    let w = r.width.saturating_sub(4) as usize;
    let mut lines: Vec<Line> = Vec::new();
    let recent = |ts: i64| n - ts < 120;
    match who {
        Who::Cloud => {
            if let Some(c) = s.commits.first() {
                lines.push(Line::from(vec![
                    Span::styled("마지막 커밋 ", Style::default().fg(DIM)),
                    Span::styled(
                        format!(
                            "{} · {}",
                            c.sha.chars().take(7).collect::<String>(),
                            ago(c.ts, n)
                        ),
                        Style::default().fg(FG),
                    ),
                ]));
                lines.push(Line::from(Span::styled(
                    data::short(&c.subject, w),
                    Style::default().fg(color(who)),
                )));
            }
            let sent = s
                .mails
                .iter()
                .filter(|m| m.from == Who::Cloud && n - m.ts < 86400)
                .count();
            lines.push(Line::from(""));
            lines.push(kv(
                "커밋(24시간)",
                s.commits
                    .iter()
                    .filter(|c| n - c.ts < 86400)
                    .count()
                    .to_string(),
                w,
            ));
            lines.push(kv("보낸 우편(24시간)", sent.to_string(), w));
        }
        _ => {
            let last = s
                .mails
                .iter()
                .filter(|m| m.from == who)
                .max_by_key(|m| m.ts);
            if let Some(m) = last {
                lines.push(Line::from(vec![
                    Span::styled("마지막 우편 ", Style::default().fg(DIM)),
                    Span::styled(
                        format!("{} · {}", m.id, ago(m.ts, n)),
                        Style::default().fg(FG),
                    ),
                ]));
                lines.push(Line::from(Span::styled(
                    data::short(&m.title, w),
                    Style::default().fg(color(who)),
                )));
            } else {
                lines.push(Line::from(Span::styled(
                    "최근 우편 없음",
                    Style::default().fg(DIM),
                )));
            }
            lines.push(Line::from(""));
            let waiting: Vec<String> = data::pending(&s.mails)
                .iter()
                .filter(|m| m.to == who)
                .map(|m| m.id.clone())
                .collect();
            lines.push(kv(
                "받은 일(답 대기)",
                if waiting.is_empty() {
                    "없음".into()
                } else {
                    waiting.join(" ")
                },
                w,
            ));
            if who == Who::Laptop {
                if let Some((subj, ts)) = &s.devbuild {
                    let sha: String = subj
                        .split_whitespace()
                        .last()
                        .unwrap_or("")
                        .chars()
                        .take(7)
                        .collect();
                    lines.push(kv("받을 빌드", format!("{sha} · {}", ago(*ts, n)), w));
                }
            }
        }
    }
    let active = match who {
        Who::Cloud => s.commits.first().map(|c| recent(c.ts)).unwrap_or(false),
        _ => s.mails.iter().any(|m| m.from == who && recent(m.ts)),
    };
    // 세션 상태 줄: 마지막 우편함 확인·하는 일·사용자 결정 대기. 30분 넘게 확인이 없으면 [멈춤?]
    let bi = match who {
        Who::Cloud => Some(0),
        Who::Laptop => Some(1),
        Who::Design => Some(2),
        Who::Azure => None,
    };
    let beat = bi.and_then(|i| s.beats[i].as_ref());
    let stale = match beat {
        Some(b) => b.checked == 0 || n - b.checked > data::BEAT_STALE_SECS,
        None => bi.is_some(),
    };
    if let Some(b) = beat {
        lines.push(kv(
            "우편함 확인",
            if b.checked > 0 {
                ago(b.checked, n)
            } else {
                "-".into()
            },
            w,
        ));
        if !b.doing.is_empty() {
            lines.push(Line::from(Span::styled(
                data::short(&format!("하는 일: {}", b.doing), w),
                Style::default().fg(FG),
            )));
        }
        if !b.user.is_empty() {
            lines.push(Line::from(Span::styled(
                data::short(&format!("사용자 결정 대기: {}", b.user), w),
                Style::default().fg(BAD),
            )));
        }
    } else if bi.is_some() {
        lines.push(Line::from(Span::styled(
            "상태 줄 없음(status/ 미작성)",
            Style::default().fg(DIM),
        )));
    }
    let title = Line::from(vec![
        Span::styled(
            format!(" {} ", who.name()),
            Style::default().fg(color(who)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            if active { "[움직임] " } else { "" },
            Style::default().fg(color(who)),
        ),
        Span::styled(
            if stale { "[멈춤?] " } else { "" },
            Style::default().fg(BAD),
        ),
    ]);
    let blk = boxed(title, color(who));
    f.render_widget(Paragraph::new(lines).block(blk), r);
}

fn kv<'a>(k: &str, v: String, w: usize) -> Line<'a> {
    let kw = data::str_width(k);
    let pad = w.saturating_sub(kw + data::str_width(&v) + 1);
    Line::from(vec![
        Span::styled(k.to_string(), Style::default().fg(DIM)),
        Span::raw(" ".repeat(pad.max(1))),
        Span::styled(v, Style::default().fg(FG)),
    ])
}

/// 우편 흐름: 개발 ↔ 노트북, 개발 ↔ 디자인. 답을 기다리는 쪽 화살표 위로 점이 흐른다(움직임은 대기·최근 우편이 있을 때만)
fn draw_flow(f: &mut Frame, r: Rect, app: &App, n: i64) {
    let s = &app.snap;
    let pend = data::pending(&s.mails);
    let mut lines = vec![];
    for peer in [Who::Laptop, Who::Design] {
        let out: Vec<&str> = pend
            .iter()
            .filter(|m| m.to == peer)
            .map(|m| m.id.as_str())
            .collect();
        let last_in = s
            .mails
            .iter()
            .filter(|m| m.from == peer)
            .max_by_key(|m| m.ts);
        let moving = !out.is_empty();
        let len = 18usize;
        let pos = (app.tick as usize / 2) % len;
        let arrow: String = (0..len)
            .map(|i| {
                if moving && (i == pos || i + 1 == pos) {
                    '●'
                } else {
                    '─'
                }
            })
            .collect();
        lines.push(Line::from(vec![
            Span::styled(" 개발 ", Style::default().fg(color(Who::Cloud))),
            Span::styled(
                format!("{arrow}▶ "),
                Style::default().fg(if moving { color(peer) } else { DIM }),
            ),
            Span::styled(
                format!("{:<6}", peer.name()),
                Style::default()
                    .fg(color(peer))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if out.is_empty() {
                    "  답 기다리는 우편 없음".to_string()
                } else {
                    format!("  {} 답 대기", out.join(", "))
                },
                Style::default().fg(if out.is_empty() { DIM } else { FG }),
            ),
            Span::styled(
                last_in
                    .map(|m| format!("   ◀ 최근 답 {} · {}", m.id, ago(m.ts, n)))
                    .unwrap_or_default(),
                Style::default().fg(DIM),
            ),
        ]));
    }
    let blk = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(DIM))
        .title(Span::styled(" 우편함(mailbox) ", Style::default().fg(FG)));
    f.render_widget(Paragraph::new(lines).block(blk), r);
}

/// Azure: 파이프라인별 마지막 실행
fn draw_azure(f: &mut Frame, r: Rect, app: &App, n: i64) {
    let latest: Vec<Run> = data::latest_runs(&app.snap.runs);
    let mut lines = vec![];
    for run in latest.iter().take(r.height.saturating_sub(2) as usize) {
        let (sym, c) = match run.status.as_str() {
            "Succeeded" => ("✓ 성공", color(Who::Azure)),
            "Failed" => ("✗ 실패", BAD),
            "Canceled" => ("○ 취소", DIM),
            "" => ("? 상태 모름", DIM),
            _ => ("◐ 진행", FG),
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<12}", run.pipeline), Style::default().fg(FG)),
            Span::styled(format!("run {:<5}", run.number), Style::default().fg(DIM)),
            Span::styled(
                format!("{sym:<10}"),
                Style::default().fg(c).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{}  ", run.commit.chars().take(7).collect::<String>()),
                Style::default().fg(color(Who::Cloud)),
            ),
            Span::styled(ago(run.ts, n), Style::default().fg(DIM)),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " 최근 실행 없음",
            Style::default().fg(DIM),
        )));
    }
    let blk = boxed(
        Line::from(Span::styled(
            " Azure · Windows 빌드·PoC ",
            Style::default()
                .fg(color(Who::Azure))
                .add_modifier(Modifier::BOLD),
        )),
        color(Who::Azure),
    );
    f.render_widget(Paragraph::new(lines).block(blk), r);
}

/// 합친 시간줄(최근이 위)
fn draw_log(f: &mut Frame, r: Rect, app: &App, n: i64) {
    let s = &app.snap;
    let ev: Vec<Event> = data::timeline(&s.mails, &s.commits, &s.runs);
    let w = r.width.saturating_sub(40) as usize / 2 + 10;
    let lines: Vec<Line> = ev
        .iter()
        .take(r.height.saturating_sub(2) as usize)
        .map(|e| {
            Line::from(vec![
                Span::styled(
                    format!(" {:>11} ", kst_stamp(e.ts, n)),
                    Style::default().fg(DIM),
                ),
                Span::styled(
                    format!("{:<7}", e.who.name()),
                    Style::default()
                        .fg(color(e.who))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(data::short(&e.text, w), Style::default().fg(FG)),
                Span::styled(format!("  [{}]", e.tag), Style::default().fg(DIM)),
            ])
        })
        .collect();
    let blk = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(DIM))
        .title(Span::styled(" 작업 기록 [live] ", Style::default().fg(FG)));
    f.render_widget(Paragraph::new(lines).block(blk), r);
}
