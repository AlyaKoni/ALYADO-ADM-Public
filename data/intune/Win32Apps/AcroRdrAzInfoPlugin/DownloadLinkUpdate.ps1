$pageUrl = "https://helpx.adobe.com/acrobat/kb/mip-plugin-download.html"
$req = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -Method Get
#Only version 20 can be downloaded. Newer versions have to be downloaded via licensed download
[regex]$regex = "[^`"]*AIPPlugin[^`"]*_Rdr_DC.msi"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
$newUrl
$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrl
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
