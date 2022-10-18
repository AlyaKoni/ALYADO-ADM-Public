$pageUrl = "https://filezilla-project.org/download.php?show_all=1"
$headers = @{
    "accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
    "accept-encoding" = "gzip, deflate, br"
    "accept-language" = "de,de-DE;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"
    "cache-control" = "max-age=0"
    "upgrade-insecure-requests" = "1"
    "user-agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/"
}
$req = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -Method Get -Headers $headers
[regex]$regex = "[^`"]*FileZilla[^`"]*win64[^`"]*.exe[^`"]*"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrl
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
