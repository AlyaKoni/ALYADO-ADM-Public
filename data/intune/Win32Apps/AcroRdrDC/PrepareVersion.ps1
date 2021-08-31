Write-Host "    Preparing version"
$packageRoot = "$PSScriptRoot"
$versionFile = Join-Path $packageRoot "version.json"
if ((Test-Path $versionFile))
{
    $versionObj = Get-Content -Path $versionFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $version = [Version]$versionObj.version
}
else
{
    $versionObj = @{}
    $versionObj.version = "1.0"
    $version = [Version]$versionObj.version
}
Write-Host "      actual: $version"

$contentPath = Join-Path $packageRoot "Content"
$setupTxtPath = (Join-Path $contentPath "SetupName.txt")
$setupName = Get-Content -Path $setupTxtPath -Encoding UTF8 -Force
$patch = Get-ChildItem -Path $contentPath -Filter "*.msp"
if ($patch)
{
    $versionStr =  $patch[0].Name -replace '\D+(\d+)\D+','$1'
    $versionStr =  $versionStr.Insert(2,".").Insert(6,".")
    $version = [Version]$versionStr
}
else
{
    $setup = Get-ChildItem -Path $contentPath -Filter "*.msi"
    $versionStr =  $setupName -replace '\D+(\d+)\D+','$1'
    $versionStr =  $versionStr.Insert(2,".").Insert(6,".")
    $version = [Version]$versionStr
}
#$null = Remove-Item -Path $setupTxtPath -Force -ErrorAction SilentlyContinue
Write-Host "      new: $version"
$versionObj.version = $version.ToString()
$versionObj | ConvertTo-Json | Set-Content -Path $versionFile -Encoding UTF8 -Force
