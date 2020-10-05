Write-Host "    Preparing version"
$packageRoot = "$PSScriptRoot"
$versionFile = Join-Path $packageRoot "version.json"
$versionObj = Get-Content -Path $versionFile -Raw -Encoding UTF8 | ConvertFrom-Json
$version = [Version]$versionObj.version
Write-Host "      actual: $version"

$contentPath = Join-Path $packageRoot "Content"
$patch = Get-ChildItem -Path $contentPath -Filter "*.msp"
$versionStr =  $patch[0].Name -replace '\D+(\d+)\D+','$1'
$versionStr =  $versionStr.Insert(2,".").Insert(6,".")
$version = [Version]$versionStr

Write-Host "      new: $version"
$versionObj.version = $version.ToString()
$versionObj | ConvertTo-Json | Set-Content -Path $versionFile -Encoding UTF8 -Force
