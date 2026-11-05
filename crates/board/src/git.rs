//! git 명령으로 브랜치를 읽는다(읽기 전용). 저장소를 바꾸지 않는다 — fetch 와 원격 브랜치 읽기(origin/...)만.

use crate::data::{self, Commit, Mail, Run};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Repo {
    pub dir: PathBuf,
    pub remote: String,
}

/// 보드 한 장면의 재료
#[derive(Default, Clone)]
pub struct Snapshot {
    pub mails: Vec<Mail>,
    pub commits: Vec<Commit>,
    pub runs: Vec<Run>,
    /// dev-builds 마지막 판 (제목, 시각)
    pub devbuild: Option<(String, i64)>,
    /// 세션 상태 줄(개발·노트북·디자인 순). 파일이 없으면 None
    pub beats: [Option<data::Beat>; 3],
    /// 마지막 오류(fetch 실패 등)
    pub error: Option<String>,
}

impl Repo {
    pub fn new(dir: &Path, remote: &str) -> Self {
        Self {
            dir: dir.to_path_buf(),
            remote: remote.to_string(),
        }
    }

    fn git(&self, args: &[&str]) -> Result<String, String> {
        // L050: 자격 증명 관리자(GCM) 창이 뜨지 않게 — 보드는 묻지 않고 실패를 화면에 보인다
        let out = Command::new("git")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GCM_INTERACTIVE", "never")
            .arg("-c")
            .arg("credential.interactive=never")
            .arg("-C")
            .arg(&self.dir)
            .args(args)
            .output()
            .map_err(|e| format!("git 실행 실패: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr)
                .lines()
                .next()
                .unwrap_or("git 오류")
                .to_string());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// 원격 브랜치 네 개를 받아 온다(로컬 작업 트리는 건드리지 않는다)
    pub fn fetch(&self) -> Result<(), String> {
        self.git(&[
            "fetch",
            "-q",
            &self.remote,
            "main",
            "mailbox",
            "ci-logs",
            "dev-builds",
        ])
        .map(|_| ())
    }

    fn r(&self, branch: &str) -> String {
        format!("{}/{}", self.remote, branch)
    }

    pub fn snapshot(&self, days: u32) -> Snapshot {
        let mut s = Snapshot::default();
        let since = format!("--since={days}.days");
        // 개발 세션 커밋(main)
        match self.git(&["log", &self.r("main"), &since, "--format=%H%x1f%ct%x1f%s"]) {
            Ok(o) => s.commits = data::parse_commits(&o),
            Err(e) => s.error = Some(e),
        }
        // 우편함: 최근 커밋에서 바뀐 메시지 파일 → 내용
        let mut errs: Vec<String> = Vec::new();
        if let Some(e) = s.error.take() {
            errs.push(format!("main: {e}"));
        }
        let mailbox = self.git(&[
            "log",
            &self.r("mailbox"),
            &since,
            "--name-only",
            "--format=@%ct",
        ]);
        if let Err(e) = &mailbox {
            errs.push(format!("mailbox: {e}"));
        }
        if let Ok(o) = mailbox {
            let mut ts = 0i64;
            let mut seen = std::collections::HashSet::new();
            for line in o.lines() {
                if let Some(t) = line.strip_prefix('@') {
                    ts = t.parse().unwrap_or(0);
                } else if line.ends_with(".md") && seen.insert(line.to_string()) {
                    if let Ok(text) =
                        self.git(&["show", &format!("{}:{}", self.r("mailbox"), line)])
                    {
                        if let Some(m) = data::parse_mail(line, &text, ts) {
                            s.mails.push(m);
                        }
                    }
                }
            }
        }
        // Azure 실행: ci-logs 커밋 제목 + meta.txt
        let ci = self.git(&["log", &self.r("ci-logs"), &since, "--format=%ct%x1f%s"]);
        if let Err(e) = &ci {
            errs.push(format!("ci-logs: {e}"));
        }
        if let Ok(o) = ci {
            for line in o.lines() {
                let mut p = line.split('\x1f');
                let (Some(ts), Some(subj)) =
                    (p.next().and_then(|x| x.parse::<i64>().ok()), p.next())
                else {
                    continue;
                };
                let Some((pipeline, number)) = data::parse_run_subject(subj) else {
                    continue;
                };
                let meta = self
                    .git(&[
                        "show",
                        &format!(
                            "{}:azure/{}/run-{}/meta.txt",
                            self.r("ci-logs"),
                            pipeline,
                            number
                        ),
                    ])
                    .unwrap_or_default();
                s.runs.push(Run {
                    pipeline,
                    number,
                    ts,
                    status: data::meta_value(&meta, "status").unwrap_or_default(),
                    commit: data::meta_value(&meta, "commit").unwrap_or_default(),
                });
            }
        }
        let db = self.git(&["log", "-1", &self.r("dev-builds"), "--format=%s%x1f%ct"]);
        if let Err(e) = &db {
            errs.push(format!("dev-builds: {e}"));
        }
        if let Ok(o) = db {
            let mut p = o.trim().split('\x1f');
            if let (Some(subj), Some(ts)) = (p.next(), p.next().and_then(|x| x.parse().ok())) {
                s.devbuild = Some((subj.to_string(), ts));
            }
        }
        for (i, name) in ["cloud", "laptop", "design"].iter().enumerate() {
            if let Ok(t) = self.git(&["show", &format!("{}:status/{name}.md", self.r("mailbox"))]) {
                s.beats[i] = Some(data::parse_beat(&t));
            }
        }
        // L050: 어느 브랜치를 못 읽었는지 숨기지 않는다(0 으로 보이면 "일이 없다"로 오해한다)
        if !errs.is_empty() {
            s.error = Some(errs.join(" · "));
        }
        s
    }
}
