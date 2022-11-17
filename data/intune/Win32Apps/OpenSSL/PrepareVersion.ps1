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
    $version = $versionObj.version
}
Write-Host "      actual: $version"

$contentPath = Join-Path $packageRoot "Content"
$bin = Get-ChildItem -Path $contentPath -Filter "*.msi"
[regex]$regex = "-(.*?)\."
$versionStr = [regex]::Match($bin[0].Name, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Groups[1].Value
$versionStr = $versionStr.Replace("_", ".")

Write-Host "      new: $versionStr"
$versionObj.version = $versionStr
$versionObj | ConvertTo-Json | Set-Content -Path $versionFile -Encoding UTF8 -Force
Copy-Item -Path $versionFile -Destination $contentPath
