$pageUrl = "https://deployhappiness.com/resources/tool-downloads/"
$req = Invoke-WebRequest -SkipHttpErrorCheck -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*ussf.zip"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value

$actDir = $PSScriptRoot
$fileName = Split-Path -Path $newUrl -Leaf
$filePath = Join-Path $actDir $fileName
$exePath = Join-Path $actDir "ussf.exe"
$req = Invoke-WebRequest -SkipHttpErrorCheck -Uri $newUrl -UseBasicParsing -Method Get -OutFile $filePath

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($filePath)
$entry = $zip.Entries | Where-Object { $_.Name -eq "ussf.exe" }
[System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $exePath, $true)
$zip.Dispose()
Remove-Item -Path $filePath -Force

Write-Host "Downloaded ussf.exe"
& "$exePath"
