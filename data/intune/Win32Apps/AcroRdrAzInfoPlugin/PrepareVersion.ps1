Write-Host "    Preparing version"
$packageRoot = "$PSScriptRoot"
$versionFile = Join-Path $packageRoot "version.json"
if ((Test-Path $versionFile))
{
    $versionObj = Get-Content -Path $versionFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $version = $versionObj.version
}
else
{
    $versionObj = @{}
    $versionObj.version = "1.0"
    $versionObj.regPath = "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{ProductGuid}"
    $versionObj.regValue = "DisplayVersion"
    $version = $versionObj.version
}
Write-Host "      actual: $version"

$contentPath = Join-Path $packageRoot "Content"
$patch = Get-ChildItem -Path $contentPath -Filter "*.msi"
$versionStr =  $patch[0].Name -replace '\D+(\d+)\D+','$1'
$version =  $versionStr.Insert(2,".").Insert(6,".")

Write-Host "      new: $version"
$versionObj.version = $version
$versionObj | ConvertTo-Json | Set-Content -Path $versionFile -Encoding UTF8 -Force
