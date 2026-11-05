# Pick which PoC jobs to run (Azure win-tests). Output variables p.<job> = true/false.
# Rules: manual or scheduled run -> all; commit message [skip-poc] -> none; [poc-all] -> all; [<job>] -> that job;
# [poc] -> jobs whose path globs match a file changed in the last commit. No tag -> none (free 1800 min/month).
param([string]$Rules)
$ErrorActionPreference = "Stop"
$msg = "$env:COMMIT_MSG"
$reason = "$env:BUILD_REASON"
$changed = @(git diff --name-only HEAD~1 HEAD 2>$null)
if ($LASTEXITCODE -ne 0) { $changed = @(); $reason = "NoParent" }
"reason=$reason changed=$($changed.Count)"
function GlobToRegex([string]$g) {
  $r = [regex]::Escape($g) -replace '\\\*\\\*', '.*' -replace '\\\*', '[^/]*'
  return "^$r$"
}
foreach ($line in ($Rules -split "`r?`n")) {
  if ($line -notmatch '^\s*([a-z0-9]+)=(.*)$') { continue }
  $job = $Matches[1]
  $globs = $Matches[2] -split ','
  $run = $false
  $why = ""
  if ($msg -match '\[skip-poc\]') { $why = "skip-poc" }
  elseif ($reason -in @("Manual", "Schedule", "NoParent")) { $run = $true; $why = $reason }
  elseif ($msg -match '\[poc-all\]') { $run = $true; $why = "poc-all" }
  elseif ($msg -match ('\[' + $job + '\]')) { $run = $true; $why = "tag" }
  elseif ($msg -match '\[poc\]') {
    foreach ($f in $changed) {
      foreach ($g in $globs) { if ($f -match (GlobToRegex $g.Trim())) { $run = $true; $why = "path $f"; break } }
      if ($run) { break }
    }
  }
  else { $why = "no tag" }
  "$job=$run ($why)"
  Write-Host "##vso[task.setvariable variable=$job;isOutput=true]$($run.ToString().ToLower())"
}
