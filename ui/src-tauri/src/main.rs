// Windows 릴리스에서 콘솔 창을 띄우지 않는다
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // 승인 도우미(--approve <id>): 웹뷰를 만들지 않고 OS 대화상자만 쓴다 (A23)
    let args: Vec<String> = std::env::args().collect();
    // 시험 빌드만(A27): 다른 사용자로 띄울 때 환경 변수가 이어지지 않으므로 인자로 받는다. 단일 스레드인 시작 시점에만
    story_firewall_ui_lib::elevate::e2e_env_from_args(&args);
    if let Some(code) = story_firewall_ui_lib::approve::from_args(&args) {
        std::process::exit(code);
    }
    // 웹뷰가 만들어지기 전에: WebView2 를 바꾸는 환경 변수 제거 (배포 빌드)
    story_firewall_ui_lib::elevate::harden_webview_env();
    story_firewall_ui_lib::run()
}
