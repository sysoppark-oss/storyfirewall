# B2: story-firewall collector vs Sysmon miss-rate measurement (dev machine only).
# Collection only - no WFP filters, no policy changes.
#
# Usage (elevated PowerShell, repo already pulled):
#   powershell -ExecutionPolicy Bypass -File C:\fw\story-firewall\poc\b2\b2-run.ps1 -InstallSysmon
#   powershell -ExecutionPolicy Bypass -File C:\fw\story-firewall\poc\b2\b2-run.ps1 -Seconds 1800
#
# Output: C:\fw\logs\b2-<stamp>\ (summary.txt, report-2s.txt, report-10s.txt, *.json,
#         collector.out, sysmon.jsonl, collector.db, transcript.txt)
#
# Sysmon (Sysinternals) is a measurement tool here only; it is never shipped with the product.

param(
    [int]$Seconds = 600,
    [switch]$InstallSysmon,
    [switch]$ApplyConfig,
    [switch]$NoScenario,
    [string]$Root = "C:\fw"
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[b2] run this from an elevated (Administrator) PowerShell"
    exit 2
}

# A click in the console window turns on QuickEdit selection and PAUSES this script until a key is pressed
# (first laptop run 2026-11-02 sat paused for 2h19m between build and collector start). Turn QuickEdit off.
try {
    $sig = '[DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int h);' +
           '[DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr h, out uint m);' +
           '[DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr h, uint m);'
    $k = Add-Type -MemberDefinition $sig -Name ConMode -Namespace B2 -PassThru
    $hIn = $k::GetStdHandle(-10)
    $mode = [uint32]0
    if ($k::GetConsoleMode($hIn, [ref]$mode)) {
        # clear ENABLE_QUICK_EDIT_MODE (0x40), set ENABLE_EXTENDED_FLAGS (0x80)
        $null = $k::SetConsoleMode($hIn, (($mode -band (-bnot 0x40)) -bor 0x80))
    }
} catch { Write-Host "[b2] could not turn off QuickEdit (continuing)" }

$repo  = Join-Path $Root "story-firewall"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$out   = Join-Path $Root ("logs\b2-" + $stamp)
New-Item -ItemType Directory -Force -Path $out | Out-Null
Start-Transcript -Path (Join-Path $out "transcript.txt") | Out-Null

function Utc([datetime]$t) { return $t.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff") }

try {
    # ---------------------------------------------------------------- 1. Sysmon
    $cfg = Join-Path $repo "poc\b2\sysmon-b2.xml"
    $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    $sysmonExe = Join-Path $env:SystemRoot "Sysmon64.exe"
    if (-not $svc) {
        if (-not $InstallSysmon) {
            Write-Host "[b2] Sysmon is not installed. Rerun with -InstallSysmon (downloads Sysmon.zip from download.sysinternals.com)."
            exit 3
        }
        $tools = Join-Path $Root "tools\sysmon"
        New-Item -ItemType Directory -Force -Path $tools | Out-Null
        $zip = Join-Path $tools "Sysmon.zip"
        Write-Host "[b2] downloading Sysmon"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $tools -Force
        $dl = Join-Path $tools "Sysmon64.exe"
        $sig = Get-AuthenticodeSignature -FilePath $dl
        if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") {
            throw ("Sysmon64.exe signature check failed: " + $sig.Status + " " + $sig.SignerCertificate.Subject)
        }
        Write-Host ("[b2] signature ok: " + $sig.SignerCertificate.Subject)
        & $dl -accepteula -i $cfg
        if ($LASTEXITCODE -ne 0) { throw "Sysmon install failed (exit $LASTEXITCODE) - config schema may be rejected" }
    } elseif ($ApplyConfig) {
        & $sysmonExe -c $cfg
        if ($LASTEXITCODE -ne 0) { throw "Sysmon config update failed (exit $LASTEXITCODE)" }
    } else {
        Write-Host "[b2] Sysmon already installed - keeping its current config (use -ApplyConfig to load sysmon-b2.xml)"
    }
    # bigger log so a long run does not roll over (256 MB)
    & wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:268435456 | Out-Null
    $sysmonVer = (Get-Item $sysmonExe).VersionInfo.FileVersion

    # ---------------------------------------------------------------- 2. build
    Push-Location $repo
    Write-Host "[b2] building collector-poc and b2-compare (release)"
    # cargo writes progress to stderr; Windows PowerShell 5.1 turns redirected native stderr into errors
    # (fatal under ErrorActionPreference=Stop), so let cmd.exe do the redirection.
    $buildLog = Join-Path $out "build.txt"
    & cmd.exe /d /c "cargo build --release --locked -p collector --bin collector-poc -p b2 --bin b2-compare > `"$buildLog`" 2>&1"
    if ($LASTEXITCODE -ne 0) { throw "build failed (see build.txt)" }
    $commit = (& git rev-parse --short HEAD)
    Pop-Location
    $collector = Join-Path $repo "target\release\collector-poc.exe"
    $compare   = Join-Path $repo "target\release\b2-compare.exe"
    $db        = Join-Path $out "collector.db"

    # ---------------------------------------------------------------- 3. run
    Write-Host ("[b2] collecting for " + $Seconds + " s. Use the PC normally meanwhile (browser, updates, etc.).")
    $launch = Get-Date
    $p = Start-Process -FilePath $collector -ArgumentList "$Seconds", "`"$db`"", "--experimental" `
            -RedirectStandardOutput (Join-Path $out "collector.out") -RedirectStandardError (Join-Path $out "collector.err") `
            -PassThru -WindowStyle Hidden
    $null = $p.Handle  # keep a handle so ExitCode is readable after exit
    # L013 R6: this laptop runs with 0.4-0.9 GB free; record memory so results can be read against it
    $freeStart = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)
    $maxWs = 0
    Start-Sleep -Seconds 10
    $from = Get-Date

    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $work = Join-Path $env:TEMP ("sf-b2-" + $stamp)
    if (-not $NoScenario) {
        # native tools below write to stderr; keep going on such output
        $ErrorActionPreference = "Continue"
        try {
            Write-Host "[b2] scenario: curl chain, renamed download with MOTW + Run key, DoH, nslookup, PowerShell web request"
            New-Item -ItemType Directory -Force -Path $work | Out-Null
            & curl.exe -s -o NUL https://www.rust-lang.org/
            Start-Sleep -Seconds 2
            $tmp = Join-Path $work "payload.tmp"
            Copy-Item (Join-Path $env:SystemRoot "System32\curl.exe") $tmp
            Set-Content -Path $tmp -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://example.com/payload.exe`r`n"
            Rename-Item -Path $tmp -NewName "payload.exe"
            $pl = Join-Path $work "payload.exe"
            New-ItemProperty -Path $runKey -Name "sf_b2_test" -Value $pl -PropertyType String -Force | Out-Null
            & $pl -s -o NUL https://api.github.com/
            Start-Sleep -Seconds 2
            & curl.exe -s -o NUL --doh-url https://cloudflare-dns.com/dns-query https://example.com/ 2>&1 | Out-Null
            & nslookup.exe example.org 2>&1 | Out-Null
            Invoke-WebRequest -Uri "https://www.microsoft.com/" -UseBasicParsing -TimeoutSec 20 | Out-Null
            # inbound: local TCP listener on 47556, connected 5 times via this PC's own LAN address
            # (run 3 had no inbound traffic at all, so the accept local/remote fix could not be checked)
            $lan = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
                    Select-Object -First 1).IPAddress
            if ($lan) {
                $lsn = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any, 47556)
                $lsn.Start()
                for ($j = 0; $j -lt 5; $j++) {
                    $c = New-Object Net.Sockets.TcpClient
                    $ar = $c.BeginConnect($lan, 47556, $null, $null)
                    if ($ar.AsyncWaitHandle.WaitOne(3000)) {
                        $c.EndConnect($ar)
                        if ($lsn.Pending()) { $s = $lsn.AcceptTcpClient(); $s.Close() }
                    }
                    $c.Close()
                    Start-Sleep -Milliseconds 500
                }
                $lsn.Stop()
                Write-Host ("[b2] inbound: 5 connects to " + $lan + ":47556")
            }
            for ($i = 0; $i -lt 20; $i++) {
                & cmd.exe /d /c "exit 0"
                & curl.exe -s -o NUL -m 5 ("https://example.com/?b2=" + $i)
            }
        } catch {
            Write-Host ("[b2] scenario step failed (continuing): " + $_.Exception.Message)
        } finally {
            Remove-ItemProperty -Path $runKey -Name "sf_b2_test" -ErrorAction SilentlyContinue
            $ErrorActionPreference = "Stop"
        }
    }

    while (-not $p.HasExited) {
        try { $p.Refresh(); if ($p.WorkingSet64 -gt $maxWs) { $maxWs = $p.WorkingSet64 } } catch {}
        Start-Sleep -Seconds 5
    }
    $p.WaitForExit()
    $end = Get-Date
    $freeEnd = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)
    $svcProc = Get-Process -Name story-firewall-svc -ErrorAction SilentlyContinue | Select-Object -First 1
    $svcWs = if ($svcProc) { [math]::Round($svcProc.WorkingSet64 / 1MB) } else { "-" }
    $to = $launch.AddSeconds($Seconds - 3)
    if ($to -gt $end) { $to = $end }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue

    # ---------------------------------------------------------------- 4. export Sysmon
    Write-Host "[b2] exporting Sysmon events"
    $events = Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-Sysmon/Operational"; StartTime = $launch; EndTime = $end.AddSeconds(5) } -ErrorAction SilentlyContinue
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($e in $events) {
        $x = [xml]$e.ToXml()
        $h = [ordered]@{ id = [int]$e.Id }
        foreach ($d in $x.Event.EventData.Data) {
            $n = $d.Name
            $v = [string]$d.'#text'
            if ($n -eq "ProcessId") { $h[$n] = [uint32]$v } else { $h[$n] = $v }
        }
        $lines.Add(($h | ConvertTo-Json -Compress))
    }
    $jsonl = Join-Path $out "sysmon.jsonl"
    [IO.File]::WriteAllLines($jsonl, $lines)

    # ---------------------------------------------------------------- 5. compare
    $f = Utc $from
    $t = Utc $to
    & $compare $db $jsonl $f $t --tolerance-ms 2000 --json (Join-Path $out "report-2s.json") --out (Join-Path $out "report-2s.txt") | Out-Null
    & $compare $db $jsonl $f $t --tolerance-ms 10000 --json (Join-Path $out "report-10s.json") --out (Join-Path $out "report-10s.txt") | Out-Null

    # ---------------------------------------------------------------- 6. summary
    $os  = Get-CimInstance Win32_OperatingSystem
    $cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
    $sum = @(
        "b2 run $stamp",
        "commit=$commit",
        ("os=" + $os.Caption + " build=" + $os.BuildNumber),
        ("ram_gb=" + [math]::Round($os.TotalVisibleMemorySize / 1MB, 1) + " free_gb=" + [math]::Round($os.FreePhysicalMemory / 1MB, 1)),
        "cpu=$cpu",
        "sysmon=$sysmonVer",
        ("seconds=" + $Seconds + " scenario=" + (-not $NoScenario)),
        ("window_utc=" + $f + " .. " + $t),
        ("sysmon_events_exported=" + $lines.Count),
        ("collector_exit=" + $p.ExitCode),
        ("mem_free_mb_start=" + $freeStart + " mem_free_mb_end=" + $freeEnd + " collector_ws_max_mb=" + [math]::Round($maxWs / 1MB) + " product_svc_ws_mb=" + $svcWs)
    )
    $sum | Out-File (Join-Path $out "summary.txt") -Encoding utf8
    Write-Host ""
    Get-Content (Join-Path $out "summary.txt")
    Get-Content (Join-Path $out "report-2s.txt") -Encoding UTF8 | Select-Object -First 12
    Write-Host ""
    Write-Host ("[b2] done -> " + $out)
} catch {
    Write-Host ("[b2] FAILED: " + $_.Exception.Message)
    $_ | Out-File (Join-Path $out "error.txt") -Encoding utf8
    exit 1
} finally {
    Stop-Transcript | Out-Null
}
