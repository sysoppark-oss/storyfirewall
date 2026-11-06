# Release signing for Tauri bundle.windows.signCommand (CI only; see .github/workflows/release-windows.yml).
# Signs one file with the per-release self-signed certificate whose thumbprint is in SF_REL_CERT_THUMB.
# The private key lives only inside that one CI job and is deleted at the end. The service has the leaf SHA-256
# compiled in (SF_RELEASE_PIN), so only this release's UI is accepted. Not trusted as a root anywhere.
param([Parameter(Mandatory = $true)][string]$Path)
$ErrorActionPreference = "Stop"
$cert = Get-Item ("Cert:\CurrentUser\My\" + $env:SF_REL_CERT_THUMB)
$r = Set-AuthenticodeSignature -FilePath $Path -Certificate $cert -HashAlgorithm SHA256
if (-not $r.SignerCertificate) { throw ("signing failed: " + $Path + " " + $r.StatusMessage) }
Write-Host ("signed " + $Path + " status=" + $r.Status)
