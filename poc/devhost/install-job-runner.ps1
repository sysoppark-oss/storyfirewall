# One-time setup of the dev-laptop job runner (run from an ELEVATED PowerShell).
#   powershell -ExecutionPolicy Bypass -File C:\fw\story-firewall\poc\devhost\install-job-runner.ps1
# Undo (task only; the folder is kept so you can inspect it):
#   powershell -ExecutionPolicy Bypass -File C:\fw\story-firewall\poc\devhost\install-job-runner.ps1 -Uninstall
#
# Installs, all under %ProgramFiles%\StoryFirewallDev (Administrators/SYSTEM write, Users read):
#   bin\job-runner.ps1, an admin-only Rust toolchain (rustup, stable, minimal profile), a clone of the repo,
#   logs\, tmp\, home\gitconfig (empty git global config for the runner).
# Writes nothing to the user's profile (no ~/.gitconfig changes). The task runs as SYSTEM (also when nobody is logged on).
# GitHub access for the clone: token from `gh auth token` (or -Token / env SF_GIT_TOKEN) stored only in the
# clone's .git\config, which is made Administrators/SYSTEM-only.

param([switch]$Uninstall, [string]$Token = $env:SF_GIT_TOKEN)
$ErrorActionPreference = "Stop"
$taskName = "StoryFirewallDevJobs"
$base = Join-Path $env:ProgramFiles "StoryFirewallDev"
$sys = $env:SystemRoot

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host "run elevated"; exit 2 }

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "task removed. Folder kept: $base"
    exit 0
}

$git = Join-Path $env:ProgramFiles "Git\cmd\git.exe"
if (-not (Test-Path $git)) { throw "Git for Windows not found at $git" }

foreach ($d in @("", "bin", "logs\jobs", "tmp", "home", "rust")) { New-Item -ItemType Directory -Force -Path (Join-Path $base $d) | Out-Null }
& icacls $base /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
Copy-Item (Join-Path $PSScriptRoot "job-runner.ps1") (Join-Path $base "bin\job-runner.ps1") -Force
$gc = Join-Path $base "home\gitconfig"
Set-Content -Path $gc -Value "[safe]`r`n`tdirectory = *`r`n[core]`r`n`tfsmonitor = false`r`n`thooksPath = NUL`r`n" -Encoding ASCII

# Same clean environment as the runner for everything below
$env:CARGO_HOME = Join-Path $base "rust\cargo"
$env:RUSTUP_HOME = Join-Path $base "rust\rustup"
$env:HOME = Join-Path $base "home"
$env:XDG_CONFIG_HOME = $env:HOME
$env:GIT_CONFIG_GLOBAL = $gc
$env:GIT_CONFIG_NOSYSTEM = "1"
$env:GIT_TERMINAL_PROMPT = "0"
$env:TEMP = Join-Path $base "tmp"
$env:TMP = $env:TEMP

# Admin-only Rust toolchain (official rustup-init over HTTPS, SHA-256 checked against the published value)
# "installed" = rustc actually runs (a failed earlier attempt can leave only the proxy exes in cargo\bin; mailbox L002)
$rustc = Join-Path $env:CARGO_HOME "bin\rustc.exe"
$rustOk = $false
if (Test-Path $rustc) {
    $ErrorActionPreference = "Continue"
    $v = & $rustc --version 2>$null
    $rustOk = ($LASTEXITCODE -eq 0) -and ($v -match '^rustc ')
    $ErrorActionPreference = "Stop"
}
if (-not $rustOk) {
    Remove-Item -Recurse -Force (Join-Path $base "rust\cargo"), (Join-Path $base "rust\rustup") -ErrorAction SilentlyContinue
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $url = "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe"
    $exe = Join-Path $env:TEMP "rustup-init.exe"
    Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing
    # the .sha256 file is served as octet-stream (Content would be a byte array in PS 5.1) -> save and read as text
    $shaFile = Join-Path $env:TEMP "rustup-init.exe.sha256"
    Invoke-WebRequest -Uri ($url + ".sha256") -OutFile $shaFile -UseBasicParsing
    $want = ((Get-Content -Path $shaFile -Raw) -split '\s+')[0].Trim().ToLower()
    Remove-Item $shaFile -Force
    $got = (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLower()
    if ($want -ne $got) { throw "rustup-init sha256 mismatch: $got vs $want" }
    # rustup writes "info:" lines to stderr; under PS 5.1 + Stop that becomes a terminating error if redirected -> Continue
    $ErrorActionPreference = "Continue"
    & $exe -y --no-modify-path --profile minimal --default-toolchain stable 2>&1 | Out-Null
    $rc = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    if ($rc -ne 0) { throw "rustup-init failed ($rc)" }
    Remove-Item $exe -Force
}

# Admin-only clone
$repo = Join-Path $base "story-firewall"
$haveClone = Test-Path (Join-Path $repo ".git")
# Re-running without -Token keeps the token already in the admin-only clone (do NOT fall back to the broad gh token).
if (-not $Token -and -not $haveClone) {
    # Prefer a fine-grained token (this repository only, Contents: read-only) passed with -Token.
    # Falling back to the gh CLI token, which can write to every repository of the account.
    $gh = Join-Path $env:ProgramFiles "GitHub CLI\gh.exe"
    if (Test-Path $gh) {
        $Token = (& $gh auth token 2>$null)
        if ($Token) { Write-Host "WARNING: using the gh CLI token (write access to all your repos). Re-run later with -Token <fine-grained read-only token> to narrow it." }
    }
}
if (-not $haveClone) {
    if (-not $Token) { throw "no GitHub token (run 'gh auth login' first, or pass -Token)" }
    $url = "https://x-access-token:" + $Token.Trim() + "@github.com/sysoppark-oss/story-firewall.git"
    & $git -c core.hooksPath=NUL clone --quiet $url $repo 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
} elseif ($Token) {
    $url = "https://x-access-token:" + $Token.Trim() + "@github.com/sysoppark-oss/story-firewall.git"
    & $git -C $repo remote set-url origin $url
} else {
    Write-Host "keeping the token already stored in the runner clone"
}
& icacls (Join-Path $repo ".git\config") /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null

# Inbox inside the admin-only base: Users may add files (WD = add file) and own what they create (CREATOR OWNER),
# but cannot delete or rename the folder; the parent is Administrators/SYSTEM-only, so no junction swap.
$inbox = Join-Path $base "requests"
New-Item -ItemType Directory -Force -Path $inbox | Out-Null
& icacls $inbox /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(WD,RD,RA,REA,X)" "*S-1-3-0:(OI)(IO)F" | Out-Null

$runner = Join-Path $base "bin\job-runner.ps1"
$ps = "$sys\System32\WindowsPowerShell\v1.0\powershell.exe"
$action = New-ScheduledTaskAction -Execute $ps -Argument ("-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"" + $runner + "`"")
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
# SYSTEM, not "this user + highest": a user-principal task starts with the user's HKCU\Environment, which a medium
# process can change (COR_PROFILER DLL injection into the elevated powershell.exe before our script runs).
$pr = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
$set = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $pr -Settings $set -Force | Out-Null
Write-Host "installed: task=$taskName runner=$runner inbox=$inbox logs=$base\logs"
