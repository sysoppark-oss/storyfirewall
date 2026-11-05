# Push CI logs from Azure Pipelines to the GitHub ci-logs branch (the dev session reads results there).
# Usage: pwsh .azure/push-log.ps1 -Name <pipeline> -Files a.log,b.txt  (or -Dir <folder>: copy its contents)   (needs env GH_PUSH_TOKEN, contents:write on this repo only)
param([string]$Name, [string]$Files, [string]$Dir)
$ErrorActionPreference = "Continue"
if (-not $env:GH_PUSH_TOKEN) { Write-Host "no GH_PUSH_TOKEN - skip"; exit 0 }
$d = Join-Path $env:AGENT_TEMPDIRECTORY "cilogs"
Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue
$url = "https://x-access-token:$($env:GH_PUSH_TOKEN)@github.com/sysoppark-oss/story-firewall.git"
git clone -q --depth 1 --branch ci-logs $url $d 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "clone ci-logs failed"; exit 0 }
$sub = Join-Path $d ("azure/" + $Name + "/run-" + $env:BUILD_BUILDID)
New-Item -ItemType Directory -Force $sub | Out-Null
foreach ($f in ($Files -split ',')) { if (Test-Path $f) { Copy-Item $f $sub } }
if ($Dir -and (Test-Path $Dir)) { Copy-Item (Join-Path $Dir '*') $sub -Recurse -Force }
# job_start: the agent worker process starts once per job (approximate job start, for the free-minutes report .azure/minutes.py)
$js = ""
try { $w = Get-Process -Name "Agent.Worker" -ErrorAction Stop | Sort-Object StartTime | Select-Object -First 1; $js = $w.StartTime.ToUniversalTime().ToString('s') + "Z" } catch { }
@("commit=$env:BUILD_SOURCEVERSION", "status=$env:AGENT_JOBSTATUS", "reason=$env:BUILD_REASON", "time=$((Get-Date).ToUniversalTime().ToString('s'))Z", "job_start=$js", "agent=$env:AGENT_NAME", "job=$env:SYSTEM_JOBDISPLAYNAME") | Set-Content (Join-Path $sub "meta.txt") -Encoding ascii
git -C $d add -A
git -C $d -c user.name="azure-ci" -c user.email="azure-ci@users.noreply.github.com" commit -q -m "azure $Name run $env:BUILD_BUILDID" 2>&1 | Out-Null
for ($i = 0; $i -lt 3; $i++) {
  git -C $d push -q origin ci-logs 2>&1 | Out-Null
  if ($LASTEXITCODE -eq 0) { Write-Host "pushed $sub"; exit 0 }
  git -C $d pull -q --rebase origin ci-logs 2>&1 | Out-Null
}
Write-Host "push failed"
exit 0
