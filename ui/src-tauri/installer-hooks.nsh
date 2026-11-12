;  Story Firewall 설치 훅 (A28). Tauri NSIS 템플릿(installer.nsi)이 불러 쓴다.
;  설치 위치는 Program Files(perMachine) — 관리자만 쓸 수 있어 실행 파일 바꿔치기로 UAC 동의를 가로채지 못한다.
;  서비스는 story-firewall-svc.exe 의 install/start/stop/uninstall 명령을 그대로 쓴다(SCM·WFP·HKLM 정리 코드가 한 곳에 있게).

!macro SF_RUNKEY_SET
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "StoryFirewall" '"$INSTDIR\story-firewall-ui.exe" --tray'
!macroend

!macro SF_RACK_SET
  WriteRegStr HKLM "SOFTWARE\Antioch\Modules\storyfirewall" "Exe" "$INSTDIR\story-firewall-svc.exe"
  WriteRegStr HKLM "SOFTWARE\Antioch\Modules\storyfirewall" "ClientExe" "$INSTDIR\story-firewall-ui.exe"
  WriteRegStr HKLM "SOFTWARE\Antioch\Modules\storyfirewall" "Kind" "service"
  WriteRegStr HKLM "SOFTWARE\Antioch\Modules\storyfirewall" "Api" "1.0"
!macroend

!macro NSIS_HOOK_PREINSTALL
  ; L049: 로그온 때 Run 키로 뜬 트레이 UI(사용자 세션)가 있으면 템플릿의 "실행 중인 앱" 확인이 /S 에서 설치를 중단(exit 2)한다.
  ;  이 훅은 그 확인보다 먼저 돈다(노트북 install-21: 훅의 svc stop 은 실행됐고 그 뒤 exit 2). 업그레이드 전에 UI 를 끈다.
  ;  UI 는 보기 전용이라 꺼도 보호는 그대로. 다음 로그온(Run 키) 또는 사용자가 다시 연다.
  nsExec::ExecToLog 'taskkill /F /IM story-firewall-ui.exe'
  Pop $0
  ; 업그레이드: 파일을 바꿀 수 있게 서비스를 멈춘다(등록·필터는 그대로 — 제거하면 보호가 빈다)
  IfFileExists "$INSTDIR\story-firewall-svc.exe" 0 sf_pre_done
    nsExec::ExecToLog '"$INSTDIR\story-firewall-svc.exe" stop'
    Pop $0
  sf_pre_done:
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; 서비스 등록(있으면 경로·시작 유형 갱신) → 시작
  nsExec::ExecToLog '"$INSTDIR\story-firewall-svc.exe" install'
  Pop $0
  StrCmp $0 "0" sf_installed
    MessageBox MB_ICONEXCLAMATION|MB_OK "보호 서비스를 등록하지 못했습니다 (코드 $0). 설치 기록을 확인하세요." /SD IDOK
  sf_installed:
  nsExec::ExecToLog '"$INSTDIR\story-firewall-svc.exe" start'
  Pop $0
  ; 로그온하면 트레이에 뜬다 (모든 사용자)
  !insertmacro SF_RUNKEY_SET
  ; 안디옥 슬롯 등록부(통합 설계 0.15판 8.1 "첫 연동", 8.3 의 1번): 다른 랙 구성원(NetX)이 이 값으로 우리를 확인한다.
  ;  Exe = 파이프를 여는 쪽(서비스), ClientExe = 남에게 접속하는 쪽(화면). HKLM 은 관리자만 쓸 수 있다.
  !insertmacro SF_RACK_SET
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; 업그레이드가 부르는 이전 판 제거(인자 /UPDATE)면 서비스·필터·기록을 그대로 둔다 — 제거하면 업그레이드 사이에 보호가 빈다.
  ; (추측: Tauri 템플릿이 업데이트 때 /UPDATE 를 넘기는지는 러너 시험과 실기기에서 확인. 안 넘기면 이 분기는 쓰이지 않고,
  ;  POSTINSTALL 의 install 이 다시 등록하며 엔진이 시작 때 저장된 정책으로 필터를 되살린다)
  ; $CMDLINE 에서 /UPDATE 를 찾는다 (FileFunc 의 un. 판 의존을 피해 직접 훑는다)
  StrCpy $R8 0
  sf_scan:
    StrCpy $R9 $CMDLINE 7 $R8
    StrCmp $R9 "" sf_scan_done
    StrCmp $R9 "/UPDATE" sf_skip_uninstall
    IntOp $R8 $R8 + 1
    Goto sf_scan
  sf_scan_done:
  ; 화면 끝내기 → 서비스 멈춤·등록 해제·우리 WFP 필터 제거·HKLM 정리 (svc uninstall 이 한다)
  nsExec::ExecToLog 'taskkill /F /IM story-firewall-ui.exe'
  Pop $0
  ; 기록(%ProgramData%\StoryFirewall)은 묻고 지운다. 조용한 제거(/S)는 남긴다(되돌릴 수 없는 삭제를 기본으로 하지 않는다).
  ; 지우기는 서비스 실행 파일이 한다: 우리 이름 형식·정션 아님·소유자 SYSTEM/Administrators 일 때만 (정션으로 다른 폴더 지우기 방지)
  StrCpy $R7 ""
  MessageBox MB_YESNO|MB_ICONQUESTION "기록·정책 데이터(ProgramData\StoryFirewall)도 지울까요?$\r$\n아니요를 고르면 다시 설치할 때 이어서 씁니다." /SD IDNO IDNO sf_keep_data
    StrCpy $R7 " --purge-data"
  sf_keep_data:
  nsExec::ExecToLog '"$INSTDIR\story-firewall-svc.exe" uninstall$R7'
  Pop $0
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "StoryFirewall"
  ; 안디옥 등록부에서 우리 항목만 지운다. 위의 Modules·Antioch 열쇠는 다른 프로그램(NetX 등)과 언어 설정이 함께 쓰므로 건드리지 않는다
  DeleteRegKey HKLM "SOFTWARE\Antioch\Modules\storyfirewall"
  sf_skip_uninstall:
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
!macroend
