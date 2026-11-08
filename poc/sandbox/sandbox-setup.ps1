# Story Firewall dev - Windows Sandbox logon script (L073, 2026-11-07). ASCII + CRLF only.
# Runs as WDAGUtilityAccount (administrator inside the sandbox). C:\sf is the host folder mapped READ-ONLY;
# it holds the setup that the host job runner already verified against the CI manifest (sha256) and its signer pin.
# Same order as the host install job: setup /S -> svc install --test-signer-sha256 <pin> -> stop -> start.
$ErrorActionPreference = "Continue"
# L074: log to the writable data-only share so the host (dev session) can read it; desktop copy as fallback
$log = if (Test-Path "C:\sfout") { "C:\sfout\sf-setup.log" } else { Join-Path $env:USERPROFILE "Desktop\sf-setup.log" }
if (Test-Path $log) { Remove-Item $log -Force }
function L([string]$m) { Add-Content -Path $log -Value ((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ssZ") + " " + $m) -Encoding ascii }
L "start"
$setup = "C:\sf\story-firewall-dev-setup.exe"
$pinFile = "C:\sf\pin.txt"
if (-not (Test-Path $setup) -or -not (Test-Path $pinFile)) { L "missing setup or pin - run an install job on the host first"; exit 1 }
$pin = (Get-Content $pinFile -Raw).Trim()
# L074: the sandbox has no WebView2 runtime and no network; the installer's embedBootstrapper downloads it, so the UI
# could not start (sandbox-1). Install the offline runtime that the host job "webview2" staged (Microsoft-signed).
$wv = "C:\sf\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
if (Test-Path $wv) {
    $s = Get-AuthenticodeSignature $wv
    if ($s.Status -eq "Valid" -and [string]$s.SignerCertificate.Subject -match "O=Microsoft Corporation") {
        $q = Start-Process -FilePath $wv -ArgumentList "/silent", "/install" -Wait -PassThru
        L ("webview2 offline install exit=" + $q.ExitCode)
    } else { L ("webview2 signature rejected: " + $s.Status) }
} else { L "webview2: not staged (host job webview2) - UI will not start offline" }
if ($pin -notmatch '^[0-9a-f]{64}$') { L "bad pin"; exit 1 }
# copy out of the read-only share first (setup writes next to itself in some NSIS builds)
$work = Join-Path $env:TEMP "sf"
New-Item -ItemType Directory -Path $work -Force | Out-Null
Copy-Item $setup (Join-Path $work "setup.exe") -Force
$p = Start-Process -FilePath (Join-Path $work "setup.exe") -ArgumentList "/S" -Wait -PassThru
L ("setup exit=" + $p.ExitCode)
$svc = Join-Path $env:ProgramFiles "Story Firewall\story-firewall-svc.exe"
if (-not (Test-Path $svc)) { L "svc not found after setup"; exit 1 }
foreach ($a in @(@("install", "--test-signer-sha256", $pin), @("stop"), @("start"))) {
    $o = & $svc @a 2>&1 | Out-String
    L ("svc " + $a[0] + ": " + $o.Trim())
}
Start-Sleep -Seconds 2
L ("svc status: " + ((& $svc status 2>&1 | Out-String).Trim()))
L ("os: " + (Get-CimInstance Win32_OperatingSystem).Caption + " build " + [Environment]::OSVersion.Version.Build + " free_mb " + [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB))
# Sysmon: ground truth for the miss-rate comparison (B1/B2). Only if the host job "sysmon" staged it.
$sm = "C:\sf\Sysmon64.exe"
if ((Test-Path $sm) -and (Test-Path "C:\sf\sysmon.xml")) {
    $o = & $sm -accepteula -i "C:\sf\sysmon.xml" 2>&1 | Out-String
    L ("sysmon: " + ($o.Trim() -replace "\s+", " "))
} else { L "sysmon: not staged (host job sysmon)" }
$ui = Join-Path $env:ProgramFiles "Story Firewall\story-firewall-ui.exe"
if (Test-Path $ui) { Start-Process -FilePath $ui; L "ui started" } else { L "ui not found" }
Start-Sleep -Seconds 15
L ("ui running: " + [bool](Get-Process story-firewall-ui -ErrorAction SilentlyContinue))
L "done"
