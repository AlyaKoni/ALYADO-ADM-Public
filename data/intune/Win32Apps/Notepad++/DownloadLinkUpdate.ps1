$pageUrl = "https://notepad-plus-plus.org/downloads/"
$req = Invoke-WebRequestIndep -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*/downloads/v[^`"]*"
$newUrl = "https://notepad-plus-plus.org"+([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$req = Invoke-WebRequestIndep -Uri $newUrl -UseBasicParsing -Method Get
[regex]$regex = "http[^`"]*npp[^`"]*Installer[^`"]*x64.exe"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrl
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
