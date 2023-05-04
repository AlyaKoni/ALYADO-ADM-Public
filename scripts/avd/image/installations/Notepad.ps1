$pageUrl = "https://notepad-plus-plus.org/downloads/"
$req = Invoke-WebRequest -SkipHttpErrorCheck -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*/downloads/v[^`"]*"
$newUrl = "https://notepad-plus-plus.org"+([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$req = Invoke-WebRequest -SkipHttpErrorCheck -Uri $newUrl -UseBasicParsing -Method Get
[regex]$regex = "http[^`"]*npp[^`"]*Installer[^`"]*x64.exe"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
$newUrl
pause
