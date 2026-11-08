//! 자동 조사(2026-11-07 노트북 사건): chrome.exe → cmd.exe → chrome-native-host.exe(Claude in Chrome 보조 프로그램)를
//! 서비스가 스스로 "등록된 브라우저 확장 보조 프로그램"으로 확인하고 정상 처리를 권한다. 흉내(등록 경로와 다른 곳·서명 없음)는 권하지 않는다

use graph::event::{Event, EventKind};
use graph::ingest::Ingester;
use graph::Store;
use svc::host::{Host, NativeHost, SigInfo};
use svc::investigate::{investigate, Action, Verdict};

const S: i64 = 10_000_000;
const T0: i64 = 134_000_000_000_000_000;
const CHROME: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
const CMD: &str = r"C:\Windows\System32\cmd.exe";
const NH: &str = r"C:\Program Files\WindowsApps\Claude_1.0.0_x64__pzs8sxrjxfjjc\app\resources\chrome-native-host.exe";

struct Fake {
    signed: bool,
}
impl Host for Fake {
    fn live_image(&self, pid: u32, create_ft: i64, _seen: i64) -> Option<(String, i64)> {
        (pid == 200).then(|| (CMD.to_string(), create_ft))
    }
    fn cmdline(&self, _pid: u32, _ft: i64) -> Option<String> {
        Some(format!(
            r#"C:\Windows\system32\cmd.exe /d /s /c ""{NH}" chrome-extension://abc/ --parent-window=0" < \\.\pipe\x"#
        ))
    }
    fn signature(&self, path: &str) -> Option<SigInfo> {
        Some(
            if self.signed || !path.ends_with("chrome-native-host.exe") {
                SigInfo {
                    status: "valid".into(),
                    signer: Some(if path.ends_with("chrome-native-host.exe") {
                        "Anthropic, PBC".into()
                    } else {
                        "Microsoft Windows".into()
                    }),
                }
            } else {
                SigInfo {
                    status: "nosignature".into(),
                    signer: None,
                }
            },
        )
    }
    fn native_hosts(&self) -> Vec<NativeHost> {
        vec![NativeHost {
            browser: "chrome".into(),
            name: "com.anthropic.claude_browser_extension".into(),
            scope: "HKU\\S-1-5-21-1".into(),
            manifest: r"C:\Users\SAMSUNG\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude-NativeHost\com.anthropic.claude_browser_extension.json".into(),
            path: NH.to_ascii_uppercase(),
        }]
    }
}

fn start(ts: i64, pid: u32, ppid: u32, image: &str) -> Event {
    Event::new(
        ts,
        "etw",
        EventKind::ProcessStart {
            pid,
            ppid,
            image: image.into(),
            create_time: Some(ts),
        },
    )
}

fn graph_with(native_image: &str) -> (Store, i64) {
    let store = Store::open_in_memory().unwrap();
    {
        let mut ing = Ingester::new(&store);
        ing.ingest(&start(T0, 100, 4, CHROME)).unwrap();
        ing.ingest(&start(T0 + S, 200, 100, CMD)).unwrap();
        ing.ingest(&start(T0 + 2 * S, 300, 200, native_image))
            .unwrap();
    }
    let root = store
        .find_node(graph::NodeKind::Process, &format!("200@{}", T0 + S))
        .unwrap()
        .unwrap();
    (store, root)
}

#[test]
fn registered_signed_native_host_is_known_normal() {
    let (store, root) = graph_with(NH);
    let r = investigate(&store, &Fake { signed: true }, root).unwrap();
    assert_eq!(r.verdict, Verdict::KnownNormal, "{r:#?}");
    assert_eq!(r.recommend, Action::MarkNormal);
    assert_eq!(
        r.native_host.as_ref().unwrap().name,
        "com.anthropic.claude_browser_extension"
    );
    // 개발 세션이 손으로 한 실물 확인과 같은 사실이 들어 있다
    let labels: Vec<&str> = r.facts.iter().map(|f| f.label.as_str()).collect();
    for want in [
        "지금 상태",
        "경로",
        "명령줄",
        "부모",
        "서명",
        "브라우저 확장 보조 프로그램",
    ] {
        assert!(labels.contains(&want), "{want} 없음: {labels:?}");
    }
    assert!(
        r.facts.iter().any(|f| f.value.contains("Anthropic, PBC")),
        "{r:#?}"
    );
}

#[test]
fn unsigned_registered_host_is_not_marked_normal() {
    let (store, root) = graph_with(NH);
    let r = investigate(&store, &Fake { signed: false }, root).unwrap();
    assert_eq!(r.verdict, Verdict::Unknown);
    assert_eq!(r.recommend, Action::Review);
}

#[test]
fn lookalike_in_other_folder_is_not_matched() {
    // 같은 파일 이름이지만 등록 경로와 다른 곳(사용자 임시 폴더) — 흉내
    let fake = r"C:\Users\SAMSUNG\AppData\Local\Temp\chrome-native-host.exe";
    let (store, root) = graph_with(fake);
    let r = investigate(&store, &Fake { signed: true }, root).unwrap();
    assert_ne!(r.verdict, Verdict::KnownNormal, "{r:#?}");
    assert!(r.native_host.is_none());
    assert!(r
        .facts
        .iter()
        .any(|f| f.label == "브라우저 확장 보조 프로그램" && f.ok == Some(false)));
}
