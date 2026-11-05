# UI probe for the dev laptop (L013 R1). Runs as the LOGGED-ON STANDARD USER (no admin), from the laptop session.
# No CDP / remote debugging: it uses Windows UI Automation (same as a screen reader) and screen capture only, so it
# opens no new way to drive the signed UI (a debugging port would let any local process act as our signed client).
#
#   powershell -ExecutionPolicy Bypass -File C:\fw\story-firewall\poc\devhost\ui-probe.ps1
#
# Output: C:\fw\logs\ui-probe-<stamp>\ : probe.txt, 1-dashboard.png, 2-story.png
# What it checks: UI process up (starts it if not), window found, "story view" buttons counted (dashboard list),
# first one invoked, screenshot before/after. The mind map is a canvas, so node counts are not visible to UIA.
param([string]$Out = "C:\fw\logs")

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Drawing, System.Windows.Forms
Add-Type -Name Win -Namespace SfProbe -MemberDefinition @"
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
public struct RECT { public int Left, Top, Right, Bottom; }
"@
[void][SfProbe.Win]::SetProcessDPIAware()

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$dir = Join-Path $Out ("ui-probe-" + $stamp)
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$log = Join-Path $dir "probe.txt"
function Log($s) { $s | Tee-Object -FilePath $log -Append }

# label "story view" built from code points (this file must stay ASCII)
$storyLabel = -join ([char[]](@(0xC774,0xC57C,0xAE30,0x0020,0xBCF4,0xAE30)))

$exe = Join-Path $env:ProgramFiles "Story Firewall\story-firewall-ui.exe"
$proc = Get-Process -Name story-firewall-ui -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $proc) {
    if (-not (Test-Path $exe)) { Log "FAIL ui not installed ($exe)"; exit 1 }
    Start-Process -FilePath $exe | Out-Null
    Start-Sleep -Seconds 6
    $proc = Get-Process -Name story-firewall-ui -ErrorAction SilentlyContinue | Select-Object -First 1
}
Log ("ui pid=" + $proc.Id + " session=" + $proc.SessionId)

# The window may be hidden in the tray: start the exe again (single instance shows the existing window) if needed
$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "Story Firewall")
$win = $null
for ($i = 0; $i -lt 10 -and -not $win; $i++) {
    $win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
    if (-not $win) {
        if ($i -eq 2) { Start-Process -FilePath $exe | Out-Null }
        Start-Sleep -Seconds 1
    }
}
if (-not $win) { Log "FAIL window 'Story Firewall' not found (tray only?)"; exit 1 }
$h = [IntPtr]$win.Current.NativeWindowHandle
[void][SfProbe.Win]::ShowWindow($h, 9)
[void][SfProbe.Win]::SetForegroundWindow($h)
Start-Sleep -Seconds 2

function Shot([string]$name) {
    $r = New-Object SfProbe.Win+RECT
    [void][SfProbe.Win]::GetWindowRect($h, [ref]$r)
    $w = $r.Right - $r.Left; $hh = $r.Bottom - $r.Top
    if ($w -le 0 -or $hh -le 0) { Log "WARN empty window rect"; return }
    $bmp = New-Object System.Drawing.Bitmap $w, $hh
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($r.Left, $r.Top, 0, 0, $bmp.Size)
    $p = Join-Path $dir $name
    $bmp.Save($p, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Log ("screenshot " + $p + " " + $w + "x" + $hh)
}

$btnCond = New-Object System.Windows.Automation.AndCondition(
    (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)),
    (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $storyLabel)))
$btns = $null
for ($i = 0; $i -lt 10; $i++) {
    $btns = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $btnCond)
    if ($btns.Count -gt 0) { break }
    Start-Sleep -Seconds 1
}
Log ("story_view_buttons=" + $btns.Count)
Shot "1-dashboard.png"
if ($btns.Count -gt 0) {
    $inv = $btns[0].GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
    $inv.Invoke()
    Start-Sleep -Seconds 3
    $all = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    Log ("after_invoke_uia_elements=" + $all.Count)
    Shot "2-story.png"
    Log "PASS opened first story"
} else {
    Log "WARN no stories listed yet (nothing to open)"
}
Log ("done -> " + $dir)
