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

$pageUrl = "https://www.scribus.net/downloads/stable-branch/"
$req = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*http://sourceforge.net/projects/scribus[^`"]*"
$prjUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
$req = Invoke-WebRequest -Uri $prjUrl -UseBasicParsing -Method Get
[regex]$regex = "http[^`"]*scribus[^`"]*windows-x64.exe"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
[regex]$regex = "scribus-([^-]*)-windows-x64.exe"
$matches = [regex]::Matches($newUrl, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant')
$version = [Version]$matches[0].Groups[1].Value
Write-Host "      new: $version"
$versionObj.version = $version.ToString()
$versionObj | ConvertTo-Json | Set-Content -Path $versionFile -Encoding UTF8 -Force
