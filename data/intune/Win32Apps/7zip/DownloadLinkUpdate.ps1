$pageUrl = "https://www.7-zip.org/download.html"
$req = Invoke-WebRequestIndep -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*7z[^`"]*x64[^`"]*.msi"
$newUrl = "https://www.7-zip.org/"+([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
#$content = Get-Content -Path "$PSScriptRoot\Download.url" -Raw -Encoding UTF8
#[regex]$regex = "URL=.*"
#$actUrl = [regex]::Match($content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value.Substring(4)
#$content -replace $actUrl, $newUrl | Set-Content -Path "$PSScriptRoot\Download.url" -Encoding UTF8 -Force
$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrl
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
