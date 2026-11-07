# Dev-laptop job runner (story-firewall). Runs ONLY allow-listed jobs requested by small JSON files.
# Runs as SYSTEM (scheduled task): it never loads a user's HKCU\Environment, so values a user process can plant there
# (COR_ENABLE_PROFILING/COR_PROFILER_PATH, PSModulePath, PATH ...) cannot reach powershell.exe before this script starts.
#
# Why: the cloud Claude session can read/write files in C:\fw on the laptop but cannot run commands.
# The laptop session drops a request file into %ProgramFiles%\StoryFirewallDev\requests; this runner (scheduled task, elevated, every minute)
# validates it and runs the matching job.
#
# Security model (an elevated process must not read or run anything a medium-integrity user process can change):
# - A request can only pick a job name from the allow-list and integer parameters in fixed ranges.
#   No paths, no command text, nothing is evaluated.
# - Code runs only from an admin-only clone under %ProgramFiles%\StoryFirewallDev, never from C:\fw.
# - The environment is rebuilt here, not inherited from the user profile:
#   PATH = system dirs + Git (Program Files) + an admin-only Rust toolchain (CARGO_HOME/RUSTUP_HOME under the base);
#   git ignores the user's ~/.gitconfig (GIT_CONFIG_GLOBAL = admin file, GIT_CONFIG_NOSYSTEM, HOME/XDG under the base;
#   core.fsmonitor / url.insteadOf / credential helpers planted there cannot reach us);
#   TEMP/TMP under the base (b2 copies and runs a test exe from TEMP); PSModulePath = system modules only;
#   cmd.exe is always started with /d (ignores HKCU Command Processor AutoRun).
# - Output goes to %ProgramFiles%\StoryFirewallDev\logs (admin-written, user-readable).
# Request format (UTF-8 JSON, one object):  {"job":"b2","seconds":900}   {"job":"pull"}   {"job":"status"}
#                                           {"job":"install"}   {"job":"uninstall"}   {"job":"selfupdate"}   {"job":"diag"}   {"job":"hostinfo"}   {"job":"sandbox","reboot":"true"}   {"job":"sysmon"}
# selfupdate: pull, then replace bin\job-runner.ps1 with the repo copy (no new trust: b2 already runs repo scripts
#   as SYSTEM; whoever can write main can already run code here). Takes effect from the next run.
# install (user decision 2026-11-02): installs the latest dev build from the orphan branch dev-builds (CI-built,
#   test-signed with a per-build certificate). The certificate is NOT added to any trust store; the service is
#   re-registered with --test-signer-sha256 <pin from the manifest>, so it accepts only clients signed by that
#   exact certificate. setup.exe is checked against the manifest SHA-256 before it runs. Collection only - this
#   job never applies a policy.

param([string]$Base = (Join-Path $env:ProgramFiles "StoryFirewallDev"))

$ErrorActionPreference = "Stop"
$sys = $env:SystemRoot
$reqDir = Join-Path $Base "requests"
$repo   = Join-Path $Base "story-firewall"
$logs   = Join-Path $Base "logs"
$jobs   = Join-Path $logs "jobs"
$lock   = Join-Path $Base "runner.lock"

# ---- clean environment (see header) ----
$gitDir = Join-Path $env:ProgramFiles "Git\cmd"
$env:CARGO_HOME = Join-Path $Base "rust\cargo"
$env:RUSTUP_HOME = Join-Path $Base "rust\rustup"
$env:PATH = (Join-Path $env:CARGO_HOME "bin") + ";" + $gitDir + ";" + "$sys\System32;$sys;$sys\System32\Wbem;$sys\System32\WindowsPowerShell\v1.0"
$env:HOME = Join-Path $Base "home"
$env:XDG_CONFIG_HOME = Join-Path $Base "home"
$env:GIT_CONFIG_GLOBAL = Join-Path $Base "home\gitconfig"
$env:GIT_CONFIG_NOSYSTEM = "1"
$env:GIT_TERMINAL_PROMPT = "0"
$env:TEMP = Join-Path $Base "tmp"
$env:TMP = $env:TEMP
$env:PSModulePath = "$sys\System32\WindowsPowerShell\v1.0\Modules;" + (Join-Path $env:ProgramFiles "WindowsPowerShell\Modules")
Remove-Item Env:\RUSTC_WRAPPER, Env:\RUSTFLAGS, Env:\CARGO_BUILD_RUSTC_WRAPPER, Env:\CARGO_TARGET_DIR -ErrorAction SilentlyContinue
$git = Join-Path $gitDir "git.exe"
$ps  = "$sys\System32\WindowsPowerShell\v1.0\powershell.exe"

if (-not (Test-Path $reqDir)) { exit 0 }
# The inbox lives INSIDE the admin-only base: Users may only add files to it (no delete/rename of the folder,
# and its parent is Administrators/SYSTEM-only), so it cannot be swapped for a junction between check and use
# (mailbox L001: check-then-use race on the old C:\fw\requests). Reparse-point files are still skipped.
$pending = @(Get-ChildItem -LiteralPath $reqDir -Filter "*.json" -File -Force -ErrorAction SilentlyContinue | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | Sort-Object LastWriteTime)
if ($pending.Count -eq 0) { exit 0 }

# one runner at a time
try { $lockStream = [IO.File]::Open($lock, 'OpenOrCreate', 'ReadWrite', 'None') } catch { exit 0 }

function Log([string]$id, [string]$s) {
    $line = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + "Z " + $s
    Add-Content -Path (Join-Path $jobs ($id + ".txt")) -Value $line -Encoding UTF8
}

# Returns $true only when fetch succeeded. A failed fetch (expired/revoked token, network) used to look like
# success ("repo at <old HEAD>" + "done"), so the exit code and the first error line are logged (L007).
function Update-Repo([string]$id) {
    $out = & $git -C $repo -c core.hooksPath=NUL -c core.fsmonitor=false fetch --quiet origin 2>&1
    $fx = $LASTEXITCODE
    if ($fx -ne 0) {
        $first = ($out | Select-Object -First 1 | Out-String).Trim() -replace 'github_pat_[A-Za-z0-9_]+', 'github_pat_***' -replace 'gho_[A-Za-z0-9]+', 'gho_***'
        Log $id ("fetch failed exit=" + $fx + " " + $first)
        return $false
    }
    & $git -C $repo -c core.hooksPath=NUL -c core.fsmonitor=false reset --quiet --hard origin/main 2>&1 | Out-Null
    & $git -C $repo -c core.hooksPath=NUL -c core.fsmonitor=false clean -qfdx -e target 2>&1 | Out-Null
    $head = (& $git -C $repo rev-parse --short HEAD)
    Log $id ("fetch exit=0 repo at " + $head)
    return $true
}

try {
    foreach ($f in $pending) {
        $id = [IO.Path]::GetFileNameWithoutExtension($f.Name)
        if ($id -notmatch '^[A-Za-z0-9_-]{1,40}$') { Remove-Item $f.FullName -Force; continue }
        $raw = Get-Content -Path $f.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        Remove-Item $f.FullName -Force
        if (-not $raw -or $raw.Length -gt 512) { continue }
        try { $r = $raw | ConvertFrom-Json } catch { continue }
        $job = [string]$r.job
        # The job name is attacker-controlled text (any user can drop a request). Log it only after it passes the
        # allow-list shape, so a request cannot forge lines like "done exit=0" in the job log (23rd review S2).
        if ($job -notmatch '^[a-z0-9]{1,16}$') { Log $id "rejected: bad job name"; continue }
        Log $id ("request job=" + $job)
        $ErrorActionPreference = "Continue"
        try {
            switch ($job) {
                "status" {
                    $os = Get-CimInstance Win32_OperatingSystem
                    $rc = Test-Path (Join-Path $env:CARGO_HOME "bin\cargo.exe")
                    Log $id ("ok free_gb=" + [math]::Round($os.FreePhysicalMemory / 1MB, 1) + " sysmon=" + [bool](Get-Service Sysmon64 -ErrorAction SilentlyContinue) + " admin_toolchain=" + $rc)
                }
                "pull" {
                    if (Update-Repo $id) { Log $id "done exit=0" } else { Log $id "done exit=1" }
                }
                "b2" {
                    $sec = 0
                    if (-not [int]::TryParse([string]$r.seconds, [ref]$sec) -or $sec -lt 60 -or $sec -gt 3600) { Log $id "rejected: seconds must be 60..3600"; break }
                    if (-not (Update-Repo $id)) { Log $id "done exit=1 (not measured: repo not updated)"; break }
                    $script = Join-Path $repo "poc\b2\b2-run.ps1"
                    $p = Start-Process -FilePath $ps -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$script`"", "-Seconds", "$sec", "-Root", "`"$Base`"") -WindowStyle Hidden -PassThru -Wait
                    $last = Get-ChildItem (Join-Path $logs "b2-*") -Directory -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
                    Log $id ("done exit=" + $p.ExitCode + " out=" + $(if ($last) { $last.FullName } else { "-" }))
                }
                "install" {
                    # 2026-11-06: builds now come from the public repo's CI and are copied to dev-builds-gh by the dev
                    # session. Azure (private repo) still writes dev-builds with an hour-plus lag and could overwrite a
                    # newer build with an older one (install-37, install-50). Prefer dev-builds-gh; fall back to dev-builds.
                    $ref = "origin/dev-builds-gh"
                    $out = & $git -C $repo -c core.hooksPath=NUL -c core.fsmonitor=false fetch --quiet origin "+refs/heads/dev-builds-gh:refs/remotes/origin/dev-builds-gh" 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        $ref = "origin/dev-builds"
                        $out = & $git -C $repo -c core.hooksPath=NUL -c core.fsmonitor=false fetch --quiet origin "+refs/heads/dev-builds:refs/remotes/origin/dev-builds" 2>&1
                    }
                    if ($LASTEXITCODE -ne 0) { Log $id ("fetch failed exit=" + $LASTEXITCODE); Log $id "done exit=1"; break }
                    Log $id ("source " + $ref)
                    $man = (& $git -C $repo show ($ref + ":manifest.txt")) -join "`n"
                    $pin = if ($man -match '(?m)^pin=([0-9a-f]{64})\s*$') { $Matches[1] } else { $null }
                    $want = if ($man -match '(?m)^setup_sha256=([0-9a-f]{64})\s*$') { $Matches[1] } else { $null }
                    $built = if ($man -match '(?m)^commit=([0-9a-f]{40})\s*$') { $Matches[1] } else { "?" }
                    if (-not $pin -or -not $want) { Log $id "rejected: bad manifest"; Log $id "done exit=1"; break }
                    # 24th review: $env:TEMP of SYSTEM is C:\Windows\Temp, where standard users may create folders.
                    # A fixed name ("devsetup") could be pre-created by a user, who then owns it and can swap setup.exe
                    # after the hash check. Use a fresh random folder, fail if it already exists, and cut ACL inheritance
                    # right away: Windows\Temp grants Users create-file/create-folder with (CI), so a SYSTEM-made subfolder
                    # would still let a user who guesses the name drop a file (e.g. a DLL) next to setup.exe (L023 review).
                    $dl = Join-Path $env:TEMP ("sfdev-" + [guid]::NewGuid().ToString("N"))
                    try { New-Item -ItemType Directory -Path $dl -ErrorAction Stop | Out-Null } catch { Log $id "rejected: temp dir exists"; Log $id "done exit=1"; break }
                    & icacls.exe $dl /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0) { Log $id ("rejected: icacls exit=" + $LASTEXITCODE); Remove-Item -Recurse -Force $dl -ErrorAction SilentlyContinue; Log $id "done exit=1"; break }
                    $zip = Join-Path $dl "s.zip"
                    & $git -C $repo archive --format=zip -o $zip $ref story-firewall-dev-setup.exe 2>&1 | Out-Null
                    # Zip-slip guard: no Expand-Archive. Accept exactly one entry with the exact expected name and copy
                    # that entry's bytes to a fixed path inside $dl.
                    $setup = Join-Path $dl "story-firewall-dev-setup.exe"
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    $za = [System.IO.Compression.ZipFile]::OpenRead($zip)
                    try {
                        $names = @($za.Entries | ForEach-Object { $_.FullName })
                        if ($names.Count -ne 1 -or $names[0] -cne "story-firewall-dev-setup.exe") { $setup = $null }
                        else { [System.IO.Compression.ZipFileExtensions]::ExtractToFile($za.Entries[0], $setup, $false) }
                    } finally { $za.Dispose() }
                    if (-not $setup) { Log $id ("rejected: unexpected archive entries: " + ($names -join ",")); Log $id "done exit=1"; break }
                    $got = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLower()
                    if ($got -ne $want) { Log $id ("rejected: setup sha256 " + $got + " != manifest " + $want); Log $id "done exit=1"; break }
                    Log $id ("dev build commit=" + $built + " pin=" + $pin)
                    # L073 (Sandbox, 2026-11-07): keep a copy of the VERIFIED setup + pin for Windows Sandbox. The folder is
                    # recreated with inheritance cut (SYSTEM/Admins full, Users read) and mapped READ-ONLY into the sandbox,
                    # so nothing inside the sandbox can write back to the host.
                    $sb = Join-Path $Base "sandbox"
                    if (-not (Test-Path $sb)) { New-Item -ItemType Directory -Path $sb | Out-Null }
                    & icacls.exe $sb /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" 2>&1 | Out-Null
                    Copy-Item $setup (Join-Path $sb "story-firewall-dev-setup.exe") -Force
                    Set-Content -Path (Join-Path $sb "pin.txt") -Value $pin -Encoding ascii
                    foreach ($n in @("sandbox-setup.ps1", "sysmon.xml", "sf-sandbox.wsb", "sf-sandbox-net.wsb")) {
                        $src = Join-Path $repo ("poc\sandbox\" + $n)
                        if (Test-Path $src) { Copy-Item $src (Join-Path $sb $n) -Force }
                    }
                    Log $id ("sandbox staged " + $sb)
                    # L070 (install-95, 2026-11-07): setup aborts (exit 2) when the UI is running, but the service step
                    # below still swapped the service -> new service + old UI = signature_failed. Close the UI first.
                    $ui = @(Get-Process -Name "story-firewall-ui" -ErrorAction SilentlyContinue)
                    if ($ui.Count -gt 0) {
                        Log $id ("ui running: closing " + $ui.Count + " process(es) before setup")
                        $ui | ForEach-Object { try { $_.CloseMainWindow() | Out-Null } catch {} }
                        Start-Sleep -Seconds 2
                        Get-Process -Name "story-firewall-ui" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 1
                    }
                    $p = Start-Process -FilePath $setup -ArgumentList "/S" -Wait -PassThru
                    Log $id ("setup exit=" + $p.ExitCode)
                    Remove-Item -Recurse -Force $dl -ErrorAction SilentlyContinue
                    Log $id ("temp removed=" + (-not (Test-Path $dl)))
                    $svcExe = Join-Path $env:ProgramFiles "Story Firewall\story-firewall-svc.exe"
                    if (-not (Test-Path $svcExe)) { Log $id "done exit=1 (service exe missing)"; break }
                    # L065 (install-95, 2026-11-07): setup aborted (exit 2 = the UI was open) left the OLD binaries, but the
                    # service was still re-registered with the NEW build's signer pin, so the old UI could no longer pass the
                    # pipe check. On a failed setup keep the service exactly as it was and only report.
                    if ($p.ExitCode -ne 0) { Log $id ("done exit=1 (setup exit=" + $p.ExitCode + ", old build kept; service pin unchanged - close the UI and retry)"); break }
                    foreach ($a in @(@("install", "--test-signer-sha256", $pin), @("stop"), @("start"))) {
                        $o = & $svcExe @a 2>&1 | Out-String
                        Log $id ("svc " + $a[0] + ": " + $o.Trim())
                    }
                    # L013 R4: the pipe name is published a few seconds after start; wait (max 15 s) so the log is not misread
                    for ($w = 0; $w -lt 15; $w++) {
                        $o = (& $svcExe status 2>&1 | Out-String).Trim()
                        if ($o -match 'published=\\\\') { break }
                        Start-Sleep -Seconds 1
                    }
                    Log $id ("svc status (after " + $w + " s): " + $o)
                    # The UI is not started here: this runs as SYSTEM in session 0. The laptop session (the logged-on user)
                    # starts "story-firewall-ui.exe --tray" itself after an install (L013 R3); HKLM Run covers later logons.
                    # L049: a non-zero setup exit (e.g. 2 = aborted because the UI was running) is a failed install even
                    # though the old service is restarted above; report it so the job does not look successful.
                    if ($p.ExitCode -ne 0) { Log $id ("done exit=1 (setup exit=" + $p.ExitCode + ", old build may still be installed)") }
                    else { Log $id "done exit=0" }
                }
                "diag" {
                    # L028: read-only diagnosis of the installed service (counts, sizes, query timings, service.log tail).
                    # Prints no paths/addresses from the graph; the log tail is the service's own messages.
                    $svcExe = Join-Path $env:ProgramFiles "Story Firewall\story-firewall-svc.exe"
                    if (-not (Test-Path $svcExe)) { Log $id "not installed"; Log $id "done exit=1"; break }
                    # L059: svc prints UTF-8; decode it as UTF-8 (default console code page garbled Hangul names)
                    $prevEnc = [Console]::OutputEncoding
                    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
                    try { $o = & $svcExe diag 2>&1 | Out-String } finally { [Console]::OutputEncoding = $prevEnc }
                    foreach ($l in ($o -split "`r?`n")) { if ($l.Trim()) { Log $id ($l -replace '[^\x20-\x7E\u3131-\uD7A3]', '?') } }
                    Log $id "done exit=0"
                }
                "hostinfo" {
                    # L071 (VM setup, 2026-11-07): read-only host facts to choose the VM platform.
                    # Edition (Hyper-V needs Pro/Enterprise/Education), build, RAM, cores, firmware virtualization,
                    # Hyper-V / VirtualMachinePlatform feature state, free disk on C:, existing VMs.
                    $os = Get-CimInstance Win32_OperatingSystem
                    $cs = Get-CimInstance Win32_ComputerSystem
                    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
                    Log $id ("os " + $os.Caption + " build " + $os.BuildNumber + " arch " + $os.OSArchitecture)
                    Log $id ("edition " + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID)
                    Log $id ("ram_gb " + [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) + " free_gb " + [math]::Round($os.FreePhysicalMemory / 1MB, 1))
                    Log $id ("cpu " + $cpu.Name + " cores " + $cpu.NumberOfCores + " logical " + $cpu.NumberOfLogicalProcessors)
                    Log $id ("virt_firmware " + $cpu.VirtualizationFirmwareEnabled + " slat " + $cpu.SecondLevelAddressTranslationExtensions + " hypervisor_present " + $cs.HypervisorPresent)
                    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
                    Log $id ("disk_c free_gb " + [math]::Round($disk.FreeSpace / 1GB, 1) + " size_gb " + [math]::Round($disk.Size / 1GB, 1))
                    foreach ($f in @("Microsoft-Hyper-V-All", "Microsoft-Hyper-V", "Microsoft-Hyper-V-Management-PowerShell", "VirtualMachinePlatform", "HypervisorPlatform", "Microsoft-Windows-Subsystem-Linux")) {
                        try { $st = (Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction Stop).State; Log $id ("feature " + $f + " " + $st) }
                        catch { Log $id ("feature " + $f + " unknown") }
                    }
                    try { $vms = Get-VM -ErrorAction Stop; Log $id ("hyperv_vms " + (($vms | ForEach-Object { $_.Name + ":" + $_.State }) -join ",")) } catch { Log $id "hyperv_vms unavailable" }
                    foreach ($x in @("C:\Program Files\Oracle\VirtualBox\VBoxManage.exe", "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe", "C:\Program Files\VMware\VMware Workstation\vmrun.exe")) {
                        if (Test-Path $x) { Log $id ("found " + $x) }
                    }
                    Log $id "done exit=0"
                }
                "sandbox" {
                    # L072 (VM setup, user approved 2026-11-07 "runner + Sandbox", "reboot now"): enable Windows Sandbox
                    # (Containers-DisposableClientVM). Reboot only when THIS install reports RestartNeeded and the request
                    # says reboot=true - there is no standalone reboot job, so a request dropped by any local user cannot
                    # be used to reboot the PC repeatedly (feature already enabled -> no restart needed -> no reboot).
                    # Delay 120 s with a visible message so open work can be saved; "shutdown /a" cancels.
                    $f = "Containers-DisposableClientVM"
                    $before = (Get-WindowsOptionalFeature -Online -FeatureName $f).State
                    Log $id ("feature " + $f + " before " + $before)
                    if ([string]$before -eq "Enabled") { Log $id "already enabled, no reboot"; Log $id "done exit=0"; break }
                    $res = Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart
                    Log $id ("enable restart_needed " + $res.RestartNeeded)
                    if ($res.RestartNeeded -and ([string]$r.reboot -eq "true")) {
                        & "$sys\System32\shutdown.exe" /r /t 120 /c "Story Firewall dev: Windows Sandbox installed. Restarting in 2 minutes. Save your work. (shutdown /a to cancel)" /d p:2:4
                        Log $id ("reboot scheduled in 120s exit=" + $LASTEXITCODE)
                    }
                    Log $id "done exit=0"
                }
                "sysmon" {
                    # L073: fetch Sysmon for the Sandbox / VM only (Sysinternals licence: use, no redistribution - it is
                    # never shipped in the product). Only Sysmon64.exe is taken from the zip, and it must carry a valid
                    # Microsoft Authenticode signature before it is placed in the read-only sandbox folder.
                    $sb = Join-Path $Base "sandbox"
                    if (-not (Test-Path $sb)) { Log $id "rejected: run install first (sandbox folder missing)"; Log $id "done exit=1"; break }
                    $dl = Join-Path $env:TEMP ("sfsm-" + [guid]::NewGuid().ToString("N"))
                    try { New-Item -ItemType Directory -Path $dl -ErrorAction Stop | Out-Null } catch { Log $id "rejected: temp dir exists"; Log $id "done exit=1"; break }
                    & icacls.exe $dl /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" 2>&1 | Out-Null
                    $zip = Join-Path $dl "s.zip"
                    try { Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip -UseBasicParsing -ErrorAction Stop }
                    catch { Log $id ("download failed: " + $_.Exception.Message); Remove-Item -Recurse -Force $dl -ErrorAction SilentlyContinue; Log $id "done exit=1"; break }
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    $za = [System.IO.Compression.ZipFile]::OpenRead($zip)
                    $exe = $null
                    try {
                        $e = $za.Entries | Where-Object { $_.FullName -ceq "Sysmon64.exe" } | Select-Object -First 1
                        if ($e) { $exe = Join-Path $dl "Sysmon64.exe"; [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $exe, $false) }
                    } finally { $za.Dispose() }
                    if (-not $exe) { Log $id "rejected: Sysmon64.exe not in zip"; Remove-Item -Recurse -Force $dl -ErrorAction SilentlyContinue; Log $id "done exit=1"; break }
                    $sig = Get-AuthenticodeSignature $exe
                    $subj = [string]$sig.SignerCertificate.Subject
                    Log $id ("sysmon sig " + $sig.Status + " " + $subj)
                    if ($sig.Status -ne "Valid" -or $subj -notmatch "O=Microsoft Corporation") { Log $id "rejected: signature"; Remove-Item -Recurse -Force $dl -ErrorAction SilentlyContinue; Log $id "done exit=1"; break }
                    Copy-Item $exe (Join-Path $sb "Sysmon64.exe") -Force
                    Remove-Item -Recurse -Force $dl -ErrorAction SilentlyContinue
                    Log $id ("sysmon staged sha256=" + (Get-FileHash (Join-Path $sb "Sysmon64.exe") -Algorithm SHA256).Hash.ToLower())
                    Log $id "done exit=0"
                }
                "selfupdate" {
                    if (-not (Update-Repo $id)) { Log $id "done exit=1"; break }
                    $src = Join-Path $repo "poc\devhost\job-runner.ps1"
                    Copy-Item $src (Join-Path $Base "bin\job-runner.ps1") -Force
                    Log $id ("runner updated sha256=" + (Get-FileHash $src -Algorithm SHA256).Hash.ToLower())
                    Log $id "done exit=0"
                }
                "uninstall" {
                    $un = Join-Path $env:ProgramFiles "Story Firewall\uninstall.exe"
                    if (-not (Test-Path $un)) { Log $id "not installed"; Log $id "done exit=0"; break }
                    # silent uninstall keeps the data folder (user records)
                    $p = Start-Process -FilePath $un -ArgumentList "/S" -Wait -PassThru
                    Log $id ("uninstall exit=" + $p.ExitCode)
                    Log $id "done exit=0"
                }
                default { Log $id "rejected: unknown job" }
            }
        } catch {
            Log $id ("error: " + $_.Exception.Message)
        }
        $ErrorActionPreference = "Stop"
    }
} finally {
    $lockStream.Close()
}
