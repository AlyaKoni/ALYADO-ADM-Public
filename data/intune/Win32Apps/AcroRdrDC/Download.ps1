#Requires -Version 2

<#
    Copyright (c) Alya Consulting, 2019-2023

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

#
# Downloading Setup Exe
#

Write-Host "`n`n"
Write-Host "Adobe Reader download"
Write-Host "====================="
Write-Host "Please provide the Reader download URLs provided with your adobe distribution agreement"
$setupDownloadUrl = Read-Host -Prompt 'setupDownloadUrl'
$updateDownloadUrl = Read-Host -Prompt 'updateDownloadUrl'
Write-Host "`n`n"
Write-Host "We launch now a browser with the Adobe Reader setup download page."
Write-Host " - Select 'Windows 10'"
Write-Host " - Select 'All LAnguages (MUI)'"
Write-Host " - Select 'Latest 32bit' <--***"
Write-Host " - Choose 'Download now / Jetzt herunterladen'"
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
$file = Get-ChildItem -path $downloads | sort LastWriteTime | Select-Object -last 1
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
            $file = Get-ChildItem -path $downloads | sort LastWriteTime | Select-Object -last 1
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
    $setupTxtPath = (Join-Path $contentRoot "SetupName.txt")
    $filename | Set-Content -Path $setupTxtPath -Encoding UTF8 -Force
    $sourcePath = $downloads+"\"+$filename
    $tmpPath = (Join-Path $contentRoot "Tmp")
    & "$sourcePath" -sfx_o"$tmpPath" -sfx_ne
    do
    {
        Start-Sleep -Seconds 5
        $process = Get-Process -Name $filename.Replace(".exe","") -ErrorAction SilentlyContinue
    } while ($process)
    Move-Item -Path (Join-Path $tmpPath "AcroRead.msi") -Destination $contentRoot -Force
    Move-Item -Path (Join-Path $tmpPath "Data1.cab") -Destination $contentRoot -Force
    Move-Item -Path (Join-Path $tmpPath "*.msp") -Destination $contentRoot -Force
    Remove-Item -Path $tmpPath -Recurse -Force
    Remove-Item -Path $sourcePath -Force
}
else
{
    throw "We were not able to download the reader setup"
}

#
# Downloading Update
#

Write-Host "`n`n"
Write-Host "At the time we wrote this script, there was no update available"
Write-Host "Please visit $updateDownloadUrl"
Write-Host "Call us to update this script, if an update is now available"
Write-Host "`n`n"

exit

Write-Host "`n`n"
Write-Host "We launch now a browser with the Adobe Reader update download page."
Write-Host " - TODO"
Write-Host " - TODO"
Write-Host " - TODO"
Write-Host " - TODO"
Write-Host "`n"
pause
Write-Host "`n"
$lastfilename = $null
$file = Get-ChildItem -path $downloads | sort LastWriteTime | Select-Object -last 1
if ($file)
{
    $lastfilename = $file.Name
}
$filename = $null
$attempts = 10
while ($attempts -ge 0)
{
    Write-Host "Downloading setup file from $updateDownloadUrl"
    Write-Warning "Please don't start any other download!"
    try {
        Start-Process "$updateDownloadUrl"
        do
        {
            Start-Sleep -Seconds 10
            $file = Get-ChildItem -path $downloads | sort LastWriteTime | Select-Object -last 1
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
    $patch = Get-ChildItem -Path $contentRoot -Filter "*.msp"
    if ($patch)
    {
        $patch | Remove-Item -Force
    }
    Move-Item -Path $sourcePath -Destination $contentRoot -Force
}
else
{
    throw "We were not able to download the reader update"
}
