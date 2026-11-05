#!/usr/bin/env python3
# GitHub Actions PoC 워크플로(.github/workflows/*-windows.yml) → Azure Pipelines job 묶음(.azure/poc-jobs.yml) 변환기.
# GitHub Actions 는 결제 제한으로 멈췄고(2026-11), 실행 시험은 Azure win-tests 파이프라인의 job 으로 옮긴다.
# 원본 워크플로를 고치면 이 스크립트를 다시 돌려 poc-jobs.yml 을 만든다(손으로 고치지 않는다).
#   python3 .azure/gen-poc-jobs.py
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WF = ROOT / ".github" / "workflows"

# (job 이름, 원본 워크플로, Windows 이미지, 제한 시간[분])
JOBS = [
    ("poc2", "poc2-wfp-windows.yml", "windows-2025", 40),
    ("poc3", "poc3-collector-windows.yml", "windows-2025", 50),
    ("poc4", "poc4-svc-windows.yml", "windows-2025", 60),
    ("poc5", "poc5-ui-windows.yml", "windows-2022", 75),
    ("a28", "a28-installer-windows.yml", "windows-2022", 75),
    ("devhost", "devhost-windows.yml", "windows-2022", 30),
]

# 로그 올리기 단계가 없는 job 에서 함께 올릴 폴더
EXTRA_LOG_DIRS = {"devhost": r"C:\Program Files\StoryFirewallDev\logs"}  # 실행기 작업 기록(install-job-runner.ps1 의 $base\logs)

# 스크립트 안의 GitHub 표현식 → Azure 매크로
EXPR = {
    "github.sha": "$(Build.SourceVersion)",
    "github.run_number": "$(Build.BuildId)",
    "github.workflow": "$(Build.DefinitionName)",
    "job.status": "$(Agent.JobStatus)",
    "github.repository": "sysoppark-oss/story-firewall",
    "github.ref": "$(Build.SourceBranch)",
}

RUST = """\
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
  $ri = Join-Path $env:AGENT_TEMPDIRECTORY "rustup-init.exe"
  Invoke-WebRequest https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe -OutFile $ri
  & $ri -y --profile minimal --default-toolchain stable
  $cb = Join-Path $env:USERPROFILE ".cargo\\bin"
  $env:PATH = "$cb;$env:PATH"
  Write-Host "##vso[task.prependpath]$cb"
}
rustup default stable
cargo --version
"""

GEO = """\
git fetch --depth 1 origin geo-data
New-Item -ItemType Directory -Force ui\\src-tauri\\geo | Out-Null
git archive FETCH_HEAD | tar -x -C ui/src-tauri/geo
Get-ChildItem ui\\src-tauri\\geo
"""


def sub_expr(text: str, os_name: str) -> str:
    def rep(m: re.Match) -> str:
        e = m.group(1).strip()
        if e == "matrix.os":
            return os_name
        if e in EXPR:
            return EXPR[e]
        if e == "github.token":
            return "$(GH_PUSH_TOKEN)"
        sys.exit(f"변환 못 하는 표현식: {e}")
    return re.sub(r"\$\{\{([^}]*)\}\}", rep, text)


def condition(gif: str | None) -> str | None:
    if gif is None:
        return None
    g = gif.strip()
    return {"always()": "always()", "failure()": "failed()", "success()": "succeeded()", "cancelled()": "canceled()"}.get(g) or sys.exit(f"if 변환 불가: {g}")


def publish_step(name: str, script: str) -> str:
    # 원본의 Copy-Item ... $run 줄만 살려 로그 폴더에 모으고 push-log.ps1 로 올린다
    copies = [ln.strip() for ln in script.splitlines() if "Copy-Item" in ln and "$run" in ln]
    if not copies:
        sys.exit(f"{name}: 로그 Copy-Item 줄을 못 찾음")
    body = "$run = Join-Path $env:AGENT_TEMPDIRECTORY \"poclogs\"\nNew-Item -ItemType Directory -Force $run | Out-Null\n"
    body += "\n".join(copies) + "\n"
    body += f"pwsh -NoProfile -File .azure/push-log.ps1 -Name {name} -Dir $run\n"
    return body


def block(s: str, indent: int) -> str:
    pad = " " * indent
    return "\n".join((pad + ln) if ln.strip() else "" for ln in s.rstrip("\n").split("\n"))


def convert(name: str, src: str, os_name: str, timeout: int) -> str:
    wf = yaml.safe_load((WF / src).read_text(encoding="utf-8"))
    (job,) = wf["jobs"].values()
    out = [
        f"  - job: {name}",
        f"    displayName: {name} ({src})",
        "    dependsOn: plan",
        f"    condition: and(succeeded(), eq(dependencies.plan.outputs['p.{name}'], 'true'))",
        f"    timeoutInMinutes: {timeout}",
        "    pool:",
        f"      vmImage: {os_name}",
        "    variables:",
        "      CARGO_TERM_COLOR: never",
        "      RUNNER_TEMP: $(Agent.TempDirectory)",
        "    steps:",
    ]
    checked_out = False
    subdir_ckout = False
    for st in job["steps"]:
        uses = st.get("uses", "")
        nm = st.get("name") or uses
        if uses.startswith("actions/checkout"):
            if st.get("with", {}).get("ref") == "geo-data":
                out += ["      - pwsh: |", block(GEO, 10), "        displayName: Fetch geo data"]
            elif not checked_out:
                out += ["      - checkout: self", "        persistCredentials: true", "        fetchDepth: 1"]
                # GitHub checkout 의 path(예: devhost 의 story-firewall) — Azure 는 $(Agent.BuildDirectory) 기준 경로.
                # 스크립트는 원래처럼 그 바깥(s)에서 돌며 상대 경로로 부른다
                if st.get("with", {}).get("path"):
                    out.append(f"        path: s/{st['with']['path']}")
                    subdir_ckout = True
                checked_out = True
            continue
        if uses.startswith("dtolnay/rust-toolchain"):
            out += ["      - pwsh: |", block(RUST, 10), "        displayName: Rust toolchain"]
            continue
        if uses.startswith("actions/setup-node"):
            out += ["      - task: UseNode@1", "        inputs:", "          versionSource: spec", '          version: "22.x"']
            continue
        if uses.startswith("actions/cache"):
            continue  # 호스팅 실행기는 매번 새 VM, 캐시는 쓰지 않는다(무료 한도·단순성)
        if uses:
            sys.exit(f"{src}: 모르는 action {uses}")
        script = st["run"]
        shell = st.get("shell", "pwsh")
        if "Publish logs to ci-logs" in nm:
            script, shell = publish_step(name, script), "pwsh"
        script = sub_expr(script, os_name)
        kind = {"pwsh": "pwsh", "powershell": "powershell"}.get(shell) or sys.exit(f"{src}: shell {shell}")
        out += [f"      - {kind}: |", block(script, 10), f"        displayName: {yaml.safe_dump(nm, allow_unicode=True).strip().removesuffix(chr(10) + '...')}"]
        c = condition(st.get("if"))
        if c:
            out.append(f"        condition: {c}")
        if "working-directory" in st:
            out.append(f"        workingDirectory: {st['working-directory']}")
        elif subdir_ckout:
            out.append("        workingDirectory: $(Agent.BuildDirectory)/s")
        if "timeout-minutes" in st:
            out.append(f"        timeoutInMinutes: {st['timeout-minutes']}")
        if st.get("continue-on-error"):
            out.append("        continueOnError: true")
        env = dict(st.get("env") or {})
        if "Publish logs to ci-logs" in nm or "$(GH_PUSH_TOKEN)" in script or any("github.token" in str(v) for v in env.values()):
            env = {k: ("$(GH_PUSH_TOKEN)" if "github.token" in str(v) else v) for k, v in env.items()}
            env["GH_PUSH_TOKEN"] = "$(GH_PUSH_TOKEN)"
        if env:
            out.append("        env:")
            for k, v in env.items():
                out.append(f"          {k}: {sub_expr(str(v), os_name)}")
    # 원본에 로그 올리기 단계가 없는 job(devhost)도 결과를 GitHub ci-logs 로 — Azure 화면 로그인 없이 결과를 본다
    if not any("Publish logs to ci-logs" in (st.get("name") or "") for st in job["steps"]):
        script_path = ".azure/push-log.ps1" if not subdir_ckout else "story-firewall/.azure/push-log.ps1"
        extra = EXTRA_LOG_DIRS.get(name, "")
        body = "$run = Join-Path $env:AGENT_TEMPDIRECTORY \"poclogs\"\nNew-Item -ItemType Directory -Force $run | Out-Null\n"
        if extra:
            body += f"if (Test-Path '{extra}') {{ Copy-Item '{extra}\\*' $run -Recurse -ErrorAction SilentlyContinue }}\n"
        body += f"pwsh -NoProfile -File {script_path} -Name {name} -Dir $run\n"
        out += ["      - pwsh: |", block(body, 10), "        displayName: Publish logs to ci-logs branch", "        condition: always()"]
        if subdir_ckout:
            out.append("        workingDirectory: $(Agent.BuildDirectory)/s")
        out += ["        env:", "          GH_PUSH_TOKEN: $(GH_PUSH_TOKEN)"]
    return "\n".join(out)


def paths_of(src: str) -> list[str]:
    wf = yaml.safe_load((WF / src).read_text(encoding="utf-8"))
    on = wf.get(True) or wf.get("on")
    ps = list(on["push"]["paths"])
    # 원본 워크플로 파일 대신 Azure 쪽 파일이 바뀌어도 돈다
    return [p for p in ps if not p.startswith(".github/")] + [".azure/poc-jobs.yml"]


def main() -> None:
    head = [
        "# 자동 생성: python3 .azure/gen-poc-jobs.py (원본: .github/workflows/*-windows.yml). 손으로 고치지 말 것.",
        "# win-tests 파이프라인 안의 PoC 실행 시험 job 들. plan job 이 바뀐 경로로 돌릴 job 을 고른다(무료 월 1,800분 절약).",
        "jobs:",
    ]
    rules = "\n".join(f"{n}={','.join(paths_of(s))}" for n, s, _, _ in JOBS)
    plan = f"""  - job: plan
    displayName: 바뀐 경로로 돌릴 PoC job 고르기
    # 태그가 없는 보통 커밋에서는 이 job 도 돌지 않는다(VM 1분 절약) → 뒤 job 들도 건너뜀
    condition: or(in(variables['Build.Reason'], 'Manual', 'Schedule'), contains(variables['Build.SourceVersionMessage'], '[poc'), contains(variables['Build.SourceVersionMessage'], '[a28]'), contains(variables['Build.SourceVersionMessage'], '[devhost]'))
    pool:
      vmImage: windows-2025
    steps:
      - checkout: self
        fetchDepth: 2
      - pwsh: |
          $rules = @'
{block(rules, 10)}
          '@
          pwsh -NoProfile -File .azure/poc-plan.ps1 -Rules $rules
        name: p
        displayName: plan
        env:
          COMMIT_MSG: $(Build.SourceVersionMessage)"""
    body = [convert(*j) for j in JOBS]
    text = "\n".join(head) + "\n" + plan + "\n" + "\n".join(body) + "\n"
    (ROOT / ".azure" / "poc-jobs.yml").write_text(text, encoding="utf-8", newline="\n")
    yaml.safe_load(text)
    print(f"wrote .azure/poc-jobs.yml ({len(text.splitlines())} lines)")


if __name__ == "__main__":
    main()
