$pageUrl = "https://keepass.info/download.html"
$req = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*KeePass[^`"]*Setup[^`"]*download"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
$req = Invoke-WebRequest -Uri $newUrl -UseBasicParsing -Method Get
[regex]$regex = "http[^`"]*KeePass[^`"]*KeePass[^`"]*Setup[^`"]*.exe"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrl
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
