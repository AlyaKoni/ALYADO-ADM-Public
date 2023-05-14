$pageUrl = "https://inkscape.org/release"
$req = Invoke-WebRequestIndep -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*/release[^`"]*windows/[^`"]*"
$newUrl = "https://inkscape.org"+([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$req = Invoke-WebRequestIndep -Uri $newUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*/release[^`"]*windows/64-bit/[^`"]*"
$newUrl = "https://inkscape.org"+([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$req = Invoke-WebRequestIndep -Uri $newUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*/release[^`"]*windows/64-bit/[^`"]*msi[^`"]*"
$newUrl = "https://inkscape.org"+([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrl
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
