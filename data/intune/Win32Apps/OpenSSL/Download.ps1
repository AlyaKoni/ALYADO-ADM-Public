$pageUrl = "https://slproweb.com/products/Win32OpenSSL.html"

$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "Content"
if (-Not (Test-Path $contentRoot))
{
    $tmp = New-Item -Path $contentRoot -ItemType Directory -Force
}

$req = Invoke-WebRequest -SkipHttpErrorCheck -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*/Win64OpenSSL-[^`"]*.msi"
$newUrl = "https://slproweb.com" + [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
$outfile = Join-Path $contentRoot (Split-Path $newUrl -Leaf)
$dreq = Invoke-WebRequest -SkipHttpErrorCheck -Uri $newUrl -Method Get -OutFile $outfile
