# Builds the web vault and admin console from ..\common\web into webdist\,
# which the server embeds (rebuild the server afterwards).
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$web = Resolve-Path (Join-Path $repo '..\common\web')
. (Join-Path $repo '..\common\scripts\release-lib.ps1')
Push-Location $web
try {
    if (-not (Test-Path node_modules)) { Invoke-Checked npm @('ci', '--no-audit', '--no-fund') }
    Invoke-Checked npm @('run', 'build')
} finally { Pop-Location }
$dist = Join-Path $repo 'webdist'
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
Copy-Item (Join-Path $web 'dist') $dist -Recurse
Write-Host "web UI copied to $dist" -ForegroundColor Green
