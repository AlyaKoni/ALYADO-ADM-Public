#Requires -Version 2

<#
    Copyright (c) Alya Consulting, 2019-2024

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Loesungen/BasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Loesungen/BasisKonfiguration
    Die Alya Basis Konfiguration ist eine Freie Software: Sie können sie unter den
    Bedingungen der GNU General Public License, wie von der Free Software
    Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veröffentlichten Version, weiter verteilen und/oder modifizieren.
    Die Alya Basis Konfiguration wird in der Hoffnung, dass sie nützlich sein wird,
    aber OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
    https://www.gnu.org/licenses/gpl-3.0.txt


#>

Write-Host "`n`n"
Write-Host "Adobe Reader download"
Write-Host "====================="
Write-Host "Please provide the Reader download URLs provided with your adobe distribution agreement"
$setupDownloadUrl = Read-Host -Prompt 'setupDownloadUrl'
Write-Host "`n`n"
Write-Host "We launch now a browser with the Adobe Reader setup download page."
Write-Host " - Select 'Mac OS 10.15 - 13.x'"
Write-Host " - Select 'Your language'"
Write-Host " - Select 'Latest version"
Write-Host " - Choose 'Download now / Jetzt herunterladen'"
Write-Host "`n"
pause
Write-Host "`n"

$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "Content"
if (-Not (Test-Path $contentRoot))
{
    $null = New-Item -Path $contentRoot -ItemType Directory -Force
}
$profile = [Environment]::GetFolderPath("UserProfile")
$downloads = $profile + "/Downloads"
$lastfilename = $null
$file = Get-ChildItem -path $downloads | Sort-Object LastWriteTime | Select-Object -last 1
if ($file)
{
    $lastfilename = $file.Name
}
$filename = $null
$attempts = 10
while ($attempts -ge 0)
{
    Write-Host "Downloading setup file from $setupDownloadUrl"
    Write-Warning "Please don't start any other download!"
    try {
        Start-Process "$setupDownloadUrl"
        do
        {
            Start-Sleep -Seconds 10
            $file = Get-ChildItem -path $downloads | Sort-Object LastWriteTime | Select-Object -last 1
            if ($file)
            {
                $filename = $file.Name
                if ($null -ne $filename -and $filename.Contains(".crdownload")) { $filename = $lastfilename }
                if ($null -ne $filename -and $filename.Contains(".partial")) { $filename = $lastfilename }
                if ($null -ne $filename -and $filename.Contains(".tmp")) { $filename = $lastfilename }
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
    Move-Item -Path (Join-Path $downloads $filename) -Destination $contentRoot
    hdiutil attach -nobrowse -readonly "$contentRoot/$fileName"
    $dirName = $filename.Replace(".dmg","")
    $volume = "/Volumes/$dirName"
    Copy-Item -Path (Join-Path $volume $filename.Replace(".dmg",".pkg")) -Destination $contentRoot -Force
    hdiutil detach $volume
    Remove-Item -Path "$contentRoot/$fileName" -Force

    [regex]$regex = "(\d{2})(\d{3})(\d{5})"
    $grps = [regex]::Match($fileName, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Groups
    $bundleVersion = $grps[1].Value+"."+$grps[2].Value+"."+$grps[3].Value

    $versionFile = Join-Path $packageRoot "version.json"
    $versionObj = @{}
    $versionObj.version = ([Version]$bundleVersion).ToString()
    $versionObj | ConvertTo-Json | Set-Content -Path $versionFile -Encoding UTF8 -Force
}
else
{
    throw "We were not able to download the reader setup"
}

<#
$dirName = $filename.Replace(".dmg","")
New-Item -Path (Join-Path $contentRoot $dirName) -ItemType Directory -Force
pushd (Join-Path $contentRoot $dirName)
xar -xf (Join-Path $contentRoot $filename.Replace(".dmg",".pkg"))
popd

com.adobe.Reader
24.002.20759
#>
