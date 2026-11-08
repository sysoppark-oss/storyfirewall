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
# L076: the offline WebView2 installer fails inside the sandbox (exit 0x80040902, sandbox-2). Use the host runtime
# mapped read-only at C:\wv2 through WEBVIEW2_BROWSER_EXECUTABLE_FOLDER (honoured by the WebView2 loader).
$wvExe = Get-ChildItem "C:\wv2" -Filter msedgewebview2.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if ($wvExe) {
    # L077: pointing at the mapped share still failed (sandbox-3); copy the runtime to the sandbox disk first
    $wvLocal = Join-Path $env:ProgramData "wv2"
    Copy-Item $wvExe.DirectoryName $wvLocal -Recurse -Force
    [Environment]::SetEnvironmentVariable("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", $wvLocal, "Machine")
    $env:WEBVIEW2_BROWSER_EXECUTABLE_FOLDER = $wvLocal
    L ("webview2 folder " + $wvLocal + " exe=" + (Test-Path (Join-Path $wvLocal "msedgewebview2.exe")))
} else { L "webview2: host runtime not mapped - UI will not start" }
# L076: clean-image dependency check (sandbox-2: the service binary printed nothing at all)
foreach ($d in @("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll")) {
    L ("dll " + $d + " present=" + (Test-Path (Join-Path $env:SystemRoot ("System32\" + $d))))
}
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
    L ("svc " + $a[0] + " exit=" + $LASTEXITCODE + ": " + $o.Trim())
}
Start-Sleep -Seconds 2
$o = (& $svc status 2>&1 | Out-String).Trim()
L ("svc status exit=" + $LASTEXITCODE + ": " + $o)
L ("os: " + (Get-CimInstance Win32_OperatingSystem).Caption + " build " + [Environment]::OSVersion.Version.Build + " free_mb " + [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB))
# Sysmon: ground truth for the miss-rate comparison (B1/B2). Only if the host job "sysmon" staged it.
$sm = "C:\sf\Sysmon64.exe"
if ((Test-Path $sm) -and (Test-Path "C:\sf\sysmon.xml")) {
    $null = & $sm -accepteula -i "C:\sf\sysmon.xml" 2>&1
    L ("sysmon exit=" + $LASTEXITCODE + " service=" + [bool](Get-Service Sysmon64 -ErrorAction SilentlyContinue))
} else { L "sysmon: not staged (host job sysmon)" }
$ui = Join-Path $env:ProgramFiles "Story Firewall\story-firewall-ui.exe"
if (Test-Path $ui) { Start-Process -FilePath $ui; L "ui started" } else { L "ui not found" }
Start-Sleep -Seconds 15
L ("ui running: " + [bool](Get-Process story-firewall-ui -ErrorAction SilentlyContinue))
L "done"
