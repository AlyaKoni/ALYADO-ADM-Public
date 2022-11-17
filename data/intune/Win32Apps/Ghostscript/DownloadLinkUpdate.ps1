Write-Host "    Updating download link"
$settings = Invoke-RestMethod -Method Get -Uri "https://ghostscript.com/json/settings.json"
$newUrl = "https://github.com/ArtifexSoftware/ghostpdl-downloads/releases/download/gs$($settings.GS_SHORT_VER)/gs$($settings.GS_SHORT_VER)w64.exe"
$Shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut("$PSScriptRoot\Download.url")
$sc.TargetPath = $newUrl
$sc.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Shell) | Out-Null
