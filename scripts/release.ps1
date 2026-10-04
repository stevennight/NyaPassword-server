# Make a server release: set the version (VERSION + Cargo.toml), pin the common
# commit the build uses (COMMON_REF), commit and tag v<version>. Pushing the tag
# makes GitHub Actions build the Docker image and publish the release.
#
#   .\scripts\release.ps1 0.1.1           # then: git push origin HEAD v0.1.1
#   .\scripts\release.ps1 0.2.0-beta.1 -Push
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Version,
    [switch]$Push
)
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $repo '..\common\scripts\release-lib.ps1')
Publish-NpwVersion -Repo $repo -Product 'NyaPassword Server' -Tomls @('Cargo.toml') -Version $Version -Push:$Push
