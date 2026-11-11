//! 재현용 이벤트 (개발 서버·UI 시연). 통합 테스트의 payload 사건과 평범한 브라우저 활동을 섞는다.
//! 시각은 FILETIME(100ns). `now_ft` 기준으로 몇 분 전 일로 만든다.

use graph::event::{Direction, Event, EventKind, ProcRef, Proto};

pub fn demo_events(now_ft: i64) -> Vec<Event> {
    let s = 10_000_000i64; // 1초
    let t = now_ft - 600 * s; // 10분 전
    let ev = |ts: i64, source: &str, kind: EventKind| Event {
        ts,
        source: source.into(),
        kind,
    };
    let payload = r"C:\Users\pjg\AppData\Local\Temp\payload.exe";
    let chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
    let mut v = vec![
        ev(
            t,
            "snapshot",
            EventKind::ProcessSnapshot {
                pid: 1000,
                ppid: 4,
                image: r"C:\Windows\explorer.exe".into(),
                create_time: t,
                services: vec![],
            },
        ),
        ev(
            t,
            "snapshot",
            EventKind::ProcessSnapshot {
                pid: 1500,
                ppid: 1000,
                image: chrome.into(),
                create_time: t,
                services: vec![],
            },
        ),
        ev(
            t,
            "signature",
            EventKind::Signature {
                path: chrome.into(),
                signer: Some("Google LLC".into()),
                issuer: Some("DigiCert".into()),
                status: "valid".into(),
                catalog: false,
            },
        ),
    ];
    // 평범한 브라우저 활동
    for (i, host) in [
        "www.google.com",
        "mail.google.com",
        "www.naver.com",
        "fonts.gstatic.com",
        // D005: 대만 등록(TW → "대만") · 지정 안 됨(ZZ → 회색 점)
        "cdn.example.tw",
        "edge.example.net",
        // D009: 작은 나라(홍콩) — 지도에서 원으로
        "cdn.example.hk",
    ]
    .iter()
    .enumerate()
    {
        let ts = t + (5 + i as i64 * 7) * s;
        v.push(ev(
            ts,
            "etw:dns",
            EventKind::DnsQuery {
                proc: ProcRef::new(1500, None),
                name: host.to_string(),
                results: vec![format!("142.250.{}.{}", 10 + i, 100 + i)],
            },
        ));
        v.push(ev(
            ts + s,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(1500, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 49000 + i as u16,
                raddr: format!("142.250.{}.{}", 10 + i, 100 + i),
                rport: 443,
            },
        ));
    }
    // 특수 주소 (D001: '어디' 칸이 국가 대신 종류를 보이는지) — 같은 망 이름 찾기(LLMNR)·NetBIOS 브로드캐스트
    for (i, (ip, port)) in [("224.0.0.252", 5355u16), ("192.168.0.255", 137)]
        .iter()
        .enumerate()
    {
        v.push(ev(
            t + (40 + i as i64) * s,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(1500, None),
                proto: Proto::Udp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50100 + i as u16,
                raddr: ip.to_string(),
                rport: *port,
            },
        ));
    }
    // payload 사건 (4장까지)
    let p = t + 120 * s;
    v.extend([
        ev(
            p,
            "etw:file",
            EventKind::FileWrite {
                proc: ProcRef::new(1500, None),
                path: payload.into(),
            },
        ),
        ev(
            p,
            "motw",
            EventKind::Downloaded {
                path: payload.into(),
                host_url: Some("https://evil.example/p".into()),
                referrer_url: Some("https://mail.google.com/".into()),
                zone_id: Some(3),
            },
        ),
        ev(
            p + 2 * s,
            "signature",
            EventKind::Signature {
                path: payload.into(),
                signer: None,
                issuer: None,
                status: "nosignature".into(),
                catalog: false,
            },
        ),
        ev(
            p + 3 * s,
            "etw:process",
            EventKind::ProcessStart {
                pid: 2200,
                ppid: 1000,
                image: payload.into(),
                create_time: Some(p + 3 * s),
            },
        ),
        ev(
            p + 4 * s,
            "autorun",
            EventKind::AutorunRegistered {
                proc: ProcRef::new(2200, None),
                location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater".into(),
                target: payload.into(),
            },
        ),
        ev(
            p + 5 * s,
            "etw:dns",
            EventKind::DnsQuery {
                proc: ProcRef::new(2200, None),
                name: "c2.evil.example".into(),
                results: vec!["203.0.113.9".into()],
            },
        ),
        ev(
            p + 6 * s,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(2200, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50000,
                raddr: "203.0.113.9".into(),
                rport: 8443,
            },
        ),
        // 브라우저에 코드 주입 → 브라우저가 낯선 곳에 접속 (끊기 미리보기의 "주입당한 정상 프로그램" 시연)
        ev(
            p + 7 * s,
            "sysmon:8",
            EventKind::Injected {
                from: ProcRef::new(2200, None),
                into: ProcRef::new(1500, None),
                method: "CreateRemoteThread".into(),
            },
        ),
        ev(
            p + 8 * s,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(1500, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50010,
                raddr: "203.0.113.77".into(),
                rport: 443,
            },
        ),
    ]);
    // D004 시연: 수집 시작 전부터 실행 중이던 프로세스 2건 — 오늘 새 활동 없음(updater) / 있음(helper)
    let day = 86_400 * s;
    let updater = r"C:\Users\pjg\AppData\Roaming\Vendor\updater.exe";
    let helper = r"C:\Users\pjg\AppData\Local\Tools\helper.exe";
    for (pid, img, born) in [
        (3100u32, updater, now_ft - 200 * day),
        (3200u32, helper, now_ft - 3 * day),
    ] {
        v.push(ev(
            t,
            "snapshot",
            EventKind::ProcessSnapshot {
                pid,
                ppid: 4,
                image: img.into(),
                create_time: born,
                services: vec![],
            },
        ));
        v.push(ev(
            t,
            "signature",
            EventKind::Signature {
                path: img.into(),
                signer: None,
                issuer: None,
                status: "nosignature".into(),
                catalog: false,
            },
        ));
        // 수집 시작 직후(연결 테이블 첫 폴링에 해당) 이미 있던 접속
        v.push(ev(
            t + 5 * s,
            "conntable",
            EventKind::Connect {
                proc: ProcRef::new(pid, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50100 + (pid as u16 % 100),
                raddr: "142.250.26.126".into(),
                rport: 8443,
            },
        ));
    }
    // 25차 Q1 시연: 서비스가 멈춰 있던 동안(기록 없는 구간, demo_no_record_gap) 시작된 agent.exe — 관측 직후 접속뿐이라도 접지 않는다
    let agent = r"C:\Users\pjg\AppData\Local\Temp\agent.exe";
    v.push(ev(
        t,
        "snapshot",
        EventKind::ProcessSnapshot {
            pid: 3300,
            ppid: 4,
            image: agent.into(),
            create_time: t - 1200 * s,
            services: vec![],
        },
    ));
    v.push(ev(
        t,
        "signature",
        EventKind::Signature {
            path: agent.into(),
            signer: None,
            issuer: None,
            status: "nosignature".into(),
            catalog: false,
        },
    ));
    v.push(ev(
        t + 5 * s,
        "conntable",
        EventKind::Connect {
            proc: ProcRef::new(3300, None),
            proto: Proto::Tcp,
            direction: Direction::Out,
            laddr: "10.0.0.2".into(),
            lport: 50300,
            raddr: "142.250.26.126".into(),
            rport: 8443,
        },
    ));
    // D020 시연: 고립 svchost(알려진 서비스 없음) 5개 — 같은 판정 묶기, 핵심 프로세스 카드("이 접속지만 차단")
    let svch = r"C:\Windows\System32\svchost.exe";
    for k in 0..5u32 {
        let pid = 4100 + k;
        let born = t + (60 + 40 * k as i64) * s;
        v.push(ev(
            born,
            "etw:process",
            EventKind::ProcessStart {
                pid,
                ppid: 700,
                image: svch.into(),
                create_time: Some(born),
            },
        ));
        v.push(ev(
            born + 2 * s,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(pid, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 50400 + k as u16,
                raddr: format!("198.51.100.{}", 10 + k),
                rport: 443,
            },
        ));
    }
    v.push(ev(
        t,
        "signature",
        EventKind::Signature {
            path: svch.into(),
            signer: Some("Microsoft Windows".into()),
            issuer: Some("Microsoft Windows Production PCA 2011".into()),
            status: "valid".into(),
            catalog: true,
        },
    ));
    // A2 "오늘 처음" 시연: 사흘 전에도 접속했던 망들(이전 기록). helper 의 Example Hosting(142.250.27.127)·대만 망은 오늘 처음
    let old = now_ft - 3 * day;
    v.push(ev(
        old,
        "etw:process",
        EventKind::ProcessStart {
            pid: 1400,
            ppid: 4,
            image: chrome.into(),
            create_time: Some(old),
        },
    ));
    for (i, ip) in [
        "142.250.10.100",
        "142.250.11.101",
        "142.250.12.102",
        "142.250.13.103",
        "142.250.26.126",
    ]
    .iter()
    .enumerate()
    {
        v.push(ev(
            old + (i as i64 + 1) * s,
            "etw:network",
            EventKind::Connect {
                proc: ProcRef::new(1400, None),
                proto: Proto::Tcp,
                direction: Direction::Out,
                laddr: "10.0.0.2".into(),
                lport: 48000 + i as u16,
                raddr: ip.to_string(),
                rport: 443,
            },
        ));
    }
    // D030-2 시연: git 작업 한 번 — git-credential-manager 가 같은 분에 git.exe 를 12번 실행(오늘 한 일 "×12" 묶음)
    let gcm = r"C:\Program Files\Git\mingw64\bin\git-credential-manager.exe";
    let git = r"C:\Program Files\Git\cmd\git.exe";
    let tg = t + 420 * s - (t + 420 * s) % (60 * s); // 분 경계에서 시작(같은 분 안에 들게)
    v.push(ev(
        tg,
        "etw:process",
        EventKind::ProcessStart {
            pid: 3600,
            ppid: 1000,
            image: gcm.into(),
            create_time: Some(tg),
        },
    ));
    for k in 0..12u32 {
        let ts = tg + (k as i64 + 1) * 2 * s;
        v.push(ev(
            ts,
            "etw:process",
            EventKind::ProcessStart {
                pid: 3700 + k,
                ppid: 3600,
                image: git.into(),
                create_time: Some(ts),
            },
        ));
    }
    // 10판 5-9 (1) 시연: cmd 가 vssadmin 으로 그림자 복사본 삭제 명령 실행(5장 파괴 징후 카드·다섯째 칸)
    let cmdx = r"C:\Windows\System32\cmd.exe";
    let vss = r"C:\Windows\System32\vssadmin.exe";
    let tv = t + 480 * s;
    v.push(ev(
        tv,
        "etw:process",
        EventKind::ProcessStart {
            pid: 3900,
            ppid: 1000,
            image: cmdx.into(),
            create_time: Some(tv),
        },
    ));
    v.push(ev(
        tv + s,
        "etw:process",
        EventKind::ProcessStart {
            pid: 3910,
            ppid: 3900,
            image: vss.into(),
            create_time: Some(tv + s),
        },
    ));
    v.push(ev(
        tv + s,
        "etw:process",
        EventKind::ProcessCommand {
            proc: ProcRef::new(3910, Some(tv + s)),
            cmdline: "vssadmin.exe delete shadows /all /quiet".into(),
            tool: None,
        },
    ));
    v.push(ev(
        tv + s,
        "signature",
        EventKind::Signature {
            path: vss.into(),
            signer: Some("Microsoft Windows".into()),
            issuer: Some("Microsoft Windows Production PCA 2011".into()),
            status: "valid".into(),
            catalog: true,
        },
    ));
    // helper 만 수집 시작 몇 분 뒤 새 접속 = 오늘 새 활동
    v.push(ev(
        t + 300 * s,
        "etw:network",
        EventKind::Connect {
            proc: ProcRef::new(3200, None),
            proto: Proto::Tcp,
            direction: Direction::Out,
            laddr: "10.0.0.2".into(),
            lport: 50150,
            raddr: "142.250.27.127".into(),
            rport: 8443,
        },
    ));
    v
}

/// 25차 Q1 시연: 기록 없는 구간 = 수집 시작(t) 45분 전 ~ t. 살아 있음 표시 두 번으로 만든다
pub fn demo_heartbeats(now_ft: i64) -> [i64; 2] {
    let s = 10_000_000i64;
    let t = now_ft - 600 * s;
    [t - 2700 * s, t + s]
}

/// 시연 데이터의 공인 주소(142.250.x)에 고정 국가·ASN 을 준다 — 러너에는 DB-IP 파일이 없어도 '어디' 칸을 캡처하려고(D001).
/// 한 행은 60자 조직 이름(말줄임 시험). 실제 등록 정보가 아니다(시험값).
pub fn demo_geo() -> geo::Geo {
    demo_geo_on(geo::Geo::default())
}

/// 실제 DB(있으면) 위에 시연 고정값을 얹는다 — 설정 화면의 "IP 데이터 기준일" 캡처용(D007-3)
pub fn demo_geo_on(base: geo::Geo) -> geo::Geo {
    use geo::{Scope, Where};
    let w = |cc: &str, country: &str, asn: u32, org: &str| Where {
        scope: Scope::Public,
        cc: Some(cc.into()),
        country: Some(country.into()),
        asn: Some(asn),
        org: Some(org.into()),
    };
    let ip = |s: &str| s.parse().unwrap();
    base.with_overrides(vec![
        (
            ip("142.250.10.100"),
            w("KR", "대한민국", 3786, "LG POWERCOMM"),
        ),
        (
            ip("142.250.11.101"),
            w(
                "US",
                "미국",
                64500,
                "Example Very Long Organization Name For Ellipsis Test, Inc.",
            ),
        ),
        (ip("142.250.12.102"), w("US", "미국", 15169, "Google LLC")),
        (
            ip("142.250.13.103"),
            w("JP", "일본", 2516, "KDDI CORPORATION"),
        ),
        // D004 시연(updater·helper) 접속지 — 도메인 없는 IP
        (
            ip("142.250.26.126"),
            w("JP", "일본", 2516, "KDDI CORPORATION"),
        ),
        (
            ip("142.250.27.127"),
            w("US", "미국", 64502, "Example Hosting LLC"),
        ),
        (
            ip("142.250.14.104"),
            w(
                "TW",
                geo::country_name_ko("TW").unwrap_or("TW"),
                3462,
                "Chunghwa Telecom Co., Ltd.",
            ),
        ),
        (
            ip("142.250.16.106"),
            w(
                "HK",
                geo::country_name_ko("HK").unwrap_or("HK"),
                4760,
                "HKT Limited",
            ),
        ),
        (
            ip("142.250.15.105"),
            w(
                "ZZ",
                geo::country_name_ko("ZZ").unwrap_or("ZZ"),
                64501,
                "Example Unassigned Block",
            ),
        ),
    ])
}

/// D030-3 시연(svc-dev --live): 지금 시각의 새 접속 하나(브라우저 → 매번 다른 주소). n 은 일련번호
pub fn demo_live_connect(now_ft: i64, n: u32) -> Vec<Event> {
    vec![Event {
        ts: now_ft,
        source: "etw:network".into(),
        kind: EventKind::Connect {
            proc: ProcRef::new(1500, None),
            proto: Proto::Tcp,
            direction: Direction::Out,
            laddr: "10.0.0.2".into(),
            lport: 51000 + (n % 10000) as u16,
            raddr: format!("203.0.113.{}", 100 + n % 150),
            rport: 443,
        },
    }]
}

/// 시연 프로세스에 로그온 세션을 붙인다(ProcessStart 마다 바로 뒤에 ProcessSession).
/// 세션을 모르는 프로세스가 든 사건은 일반 사용자에게 보이지 않으므로(49차 답변 1), 일반 사용자로 띄운 실제 화면 시험(A27)은
/// 시연 프로세스가 그 사용자의 세션에 있어야 사건을 본다
pub fn with_session(events: Vec<Event>, session: u32) -> Vec<Event> {
    let mut out = Vec::with_capacity(events.len() * 2);
    for e in events {
        let add = match &e.kind {
            EventKind::ProcessStart {
                pid,
                create_time: Some(ct),
                ..
            } => Some(Event {
                ts: e.ts,
                source: e.source.clone(),
                kind: EventKind::ProcessSession {
                    pid: *pid,
                    create_time: *ct,
                    session,
                },
            }),
            _ => None,
        };
        out.push(e);
        out.extend(add);
    }
    out
}
