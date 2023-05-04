$pageUrl = "https://www.videolan.org/vlc/download-windows.html"
$req = Invoke-WebRequest -SkipHttpErrorCheck -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*VLC[^`"]*win64.exe"
$newUrl = "https:"+[regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrl
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
