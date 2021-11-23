#
# Downloading Setup Msi
#

$pageUrl = "https://mobaxterm.mobatek.net/download-home-edition.html"
$req = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*/MobaXterm_Installer[^`"]*.zip"
$newUrl = ([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)

$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "Content"
if (-Not (Test-Path $contentRoot))
{
    $tmp = New-Item -Path $contentRoot -ItemType Directory -Force
}
$zipFile = Join-Path $contentRoot (Split-Path -Path $newUrl -Leaf)
Start-BitsTransfer -Source $newUrl -Destination $zipFile

Expand-Archive -Path $zipFile -OutputPath $contentRoot -Force
Remove-Item -Path $zipFile -Force
