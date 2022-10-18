$pageUrl = "https://tortoisegit.org/download/"

$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "Content"
if (-Not (Test-Path $contentRoot))
{
    $tmp = New-Item -Path $contentRoot -ItemType Directory -Force
}

$req = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -Method Get

[regex]$regex = "//[^`"]*TortoiseGit[^`"]*64bit.msi"
$newUrl = "https:"+([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$outfile = Join-Path $contentRoot (Split-Path $newUrl -Leaf)
$dreq = Invoke-WebRequest -Uri $newUrl -Method Get -OutFile $outfile

[regex]$regex = "//[^`"]*TortoiseGit[^`"]*LanguagePack[^`"]*64bit-de.msi"
$newUrl = "https:"+([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$outfile = Join-Path $contentRoot (Split-Path $newUrl -Leaf)
$dreq = Invoke-WebRequest -Uri $newUrl -Method Get -OutFile $outfile

[regex]$regex = "//[^`"]*TortoiseGit[^`"]*LanguagePack[^`"]*64bit-fr.msi"
$newUrl = "https:"+([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$outfile = Join-Path $contentRoot (Split-Path $newUrl -Leaf)
$dreq = Invoke-WebRequest -Uri $newUrl -Method Get -OutFile $outfile

[regex]$regex = "//[^`"]*TortoiseGit[^`"]*LanguagePack[^`"]*64bit-it.msi"
$newUrl = "https:"+([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$outfile = Join-Path $contentRoot (Split-Path $newUrl -Leaf)
$dreq = Invoke-WebRequest -Uri $newUrl -Method Get -OutFile $outfile
