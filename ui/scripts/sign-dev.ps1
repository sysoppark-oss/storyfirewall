# Dev-build signing for Tauri bundle.windows.signCommand (CI only; see .github/workflows/devbuild-windows.yml).
# Signs one file with the per-run self-signed test certificate whose thumbprint is in SF_DEV_CERT_THUMB.
# The certificate is NOT trusted as a root anywhere: the dev service pins its SHA-256 instead
# (story-firewall-svc --test-signer-sha256). Never used for release builds.
param([Parameter(Mandatory = $true)][string]$Path)
$ErrorActionPreference = "Stop"
$cert = Get-Item ("Cert:\CurrentUser\My\" + $env:SF_DEV_CERT_THUMB)
$r = Set-AuthenticodeSignature -FilePath $Path -Certificate $cert -HashAlgorithm SHA256
if (-not $r.SignerCertificate) { throw ("signing failed: " + $Path + " " + $r.StatusMessage) }
Write-Host ("signed " + $Path + " status=" + $r.Status)
