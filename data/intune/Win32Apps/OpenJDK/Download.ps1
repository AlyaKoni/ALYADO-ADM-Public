#
# Downloading Setup Exe
#

$pageUrl = "https://www.oracle.com/java/technologies/javase-downloads.html"
$req = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"']*javase-(?!server)[^`"']*jre[^`"']*downloads.html"
$newUrl = "https://www.oracle.com"+([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$req = Invoke-WebRequest -Uri $newUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"']*jre[^`"']*windows-x64.exe"
$fileUrl = ([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$fileName = $fileUrl.SubString($fileUrl.LastIndexOf("/")+1)

Write-Host "`n`n"
Write-Host "JRE download"
Write-Host "====================="

Write-Host "`n`n"
Write-Host "We browse now to:"
Write-Host "  $newUrl"
Write-Host "Please download the following file:"
Write-Host "  $fileName"
Write-Host "`n"
pause
Write-Host "`n"

$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "Content"
if (-Not (Test-Path $contentRoot))
{
    $tmp = New-Item -Path $contentRoot -ItemType Directory -Force
}
$profile = [Environment]::GetFolderPath("UserProfile")
$downloads = $profile+"\downloads"
$lastfilename = $null
$file = Get-ChildItem -path $downloads | sort LastWriteTime | select -last 1
if ($file)
{
    $lastfilename = $file.Name
}
$filename = $null
$attempts = 10
while ($attempts -ge 0)
{
    Write-Host "Downloading setup file from $newUrl"
    Write-Warning "Please don't start any other download!"
    try {
        start $newUrl
        do
        {
            Start-Sleep -Seconds 10
            $file = Get-ChildItem -path $downloads | sort LastWriteTime | select -last 1
            if ($file)
            {
                $filename = $file.Name
                if ($filename.Contains("crdownload")) { $filename = $lastfilename }
                if ($filename.Contains("partial")) { $filename = $lastfilename }
            }
        } while ($lastfilename -eq $filename)
        $attempts = -1
    } catch {
        Write-Host "Catched exception $($_.Exception.Message)"
        Write-Host "Retrying $attempts times"
        $attempts--
        if ($attempts -lt 0) { throw }
        Start-Sleep -Seconds 10
    }
}
Start-Sleep -Seconds 3
if ($filename)
{
    $sourcePath = $downloads+"\"+$filename
    $patch = Get-ChildItem -Path $contentRoot -Filter "*.exe"
    if ($patch)
    {
        $patch | Remove-Item -Force
    }
    Move-Item -Path $sourcePath -Destination $contentRoot -Force
}
else
{
    throw "We were not able to download the setup file"
}
