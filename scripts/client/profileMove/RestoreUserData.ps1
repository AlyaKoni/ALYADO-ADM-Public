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

#Preparation
$userName = $env:USERNAME
$hostName = $env:COMPUTERNAME
$localAppData = $env:LOCALAPPDATA
$appData = $env:APPDATA
$userprofile = $env:USERPROFILE
if (-Not $PSScriptRoot)
{
	$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
}
$userHostDir = "$PSScriptRoot\$userName\$hostName"
if (-Not (Test-Path $userHostDir))
{
    Write-Host "No saved user data found." -ForegroundColor Red
    $hosts = Get-ChildItem -Path "$PSScriptRoot\$userName"
    if ($hosts.Length -gt 1)
    {
        $hostDir = $hosts | Out-GridView -Title 'Select settings to be restored' -OutputMode Single
        if (-Not $hostDir) { exit }
        $hostName = $hostDir.Name
        $userHostDir = "$PSScriptRoot\$userName\$hostName"
    }
    else
    {
        $hostName = $hosts[0].Name
        $userHostDir = "$PSScriptRoot\$userName\$hostName"
    }
}
$timeString = (Get-Date).ToString("yyyyMMddHHmmss")
Start-Transcript -Path "$userHostDir\RestoreUserData-$timeString.log" | Out-Null

#Restoring MRU
Write-Host "MRU Restore" -ForegroundColor Cyan
$mrus = Get-ChildItem -Path "$userHostDir\Microsoft\RegistryMRU" -Filter "*.reg"
foreach($mru in $mrus)
{
    Write-Host "  Importing $($mru.FullName)"
    reg import "$($mru.FullName)"
}

#Restoring Taskbar
Write-Host "Taskbar Restore" -ForegroundColor Cyan
$taskbarDir = "$userHostDir\Microsoft\TaskBar"
if (Test-Path $taskbarDir)
{
    if (-Not (Test-Path "$appData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"))
    {
        $null = New-Item -Path "$appData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" -ItemType Directory -Force
    }
    xcopy /d /e /v /i /r /k /y "$taskbarDir\*" "$appData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
}
else
{
    Write-Host "  No taskbar shortcuts found in $taskbarDir"
}

#Restoring Signatures
Write-Host "Outlook Signatures Restore" -ForegroundColor Cyan
$signaturesDir = "$userHostDir\Microsoft\Signatures"
if (Test-Path $signaturesDir)
{
    if (-Not (Test-Path "$appData\Microsoft\Signatures"))
    {
        $null = New-Item -Path "$appData\Microsoft\Signatures" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $signaturesDir "$appData\Microsoft\Signatures"
}
else
{
    Write-Host "  No signatures found in $signaturesDir"
}

#Restoring Firefox
Write-Host "Firefox Backup" -ForegroundColor Cyan
$firefoxDir = "$userHostDir\Firefox"
if (Test-Path $firefoxDir)
{
    do
    {
        $process = Get-Process -Name "Firefox.exe" -ErrorAction SilentlyContinue
        if ($process)
        {
            Write-Warning "Bitte den Firefox Browser schliessen!"
            pause
        }
    }
    while ($process -ne $null)
    if (-Not (Test-Path "$appData\Mozilla\Firefox"))
    {
        $null = New-Item -Path "$appData\Mozilla\Firefox" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $firefoxDir "$appData\Mozilla\Firefox"
}
else
{
    Write-Host "  No Firefox configuration found in $firefoxDir"
}

#Restoring Edge
Write-Host "Edge Restore" -ForegroundColor Cyan
$edgeDir = "$userHostDir\Edge"
if (Test-Path $edgeDir)
{
    do
    {
        $process = Get-Process -Name "edge.exe" -ErrorAction SilentlyContinue
        if (-Not $process)
        {
			$process = Get-Process -Name "msedge.exe" -ErrorAction SilentlyContinue
			if ($process)
			{
				Write-Warning "Bitte den Edge Browser schliessen!"
				pause
			}
        }
    }
    while ($process -ne $null)
    if (-Not (Test-Path "$localAppData\Microsoft\Edge\User Data"))
    {
        $null = New-Item -Path "$localAppData\Microsoft\Edge\User Data" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $edgeDir "$localAppData\Microsoft\Edge\User Data"
}
else
{
    Write-Host "  No Edge configuration found in $edgeDir"
}

#Restoring Chrome
Write-Host "Chrome Restore" -ForegroundColor Cyan
$chromeDir = "$userHostDir\Chrome"
if (Test-Path $chromeDir)
{
    do
    {
        $process = Get-Process -Name "chrome.exe" -ErrorAction SilentlyContinue
        if ($process)
        {
            Write-Warning "Bitte den Chrome Browser schliessen!"
            pause
        }
    }
    while ($process -ne $null)
    if (-Not (Test-Path "$localAppData\Google\Chrome\User Data"))
    {
        $null = New-Item -Path "$localAppData\Google\Chrome\User Data" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $chromeDir "$localAppData\Google\Chrome\User Data"
}
else
{
    Write-Host "  No Chrome configuration found in $chromeDir"
}

#Restoring Downloads
Write-Host "Downloads Restore" -ForegroundColor Cyan
$downloadsDir = "$userHostDir\Downloads"
if (Test-Path $downloadsDir)
{
    if (-Not (Test-Path "$userprofile\Downloads"))
    {
        $null = New-Item -Path "$userprofile\Downloads" -ItemType Directory -Force
    }
    xcopy /d /e /v /i /r /k /y "$downloadsDir\*" "$userprofile\Downloads"
}
else
{
    Write-Host "  No Downloads dir found"
}

#Restoring Music
Write-Host "Music Restore" -ForegroundColor Cyan
$musicDir = "$userHostDir\Music"
if (Test-Path $musicDir)
{
    if (-Not (Test-Path "$userprofile\Music"))
    {
        $null = New-Item -Path "$userprofile\Music" -ItemType Directory -Force
    }
    xcopy /d /e /v /i /r /k /y "$musicDir\*" "$userprofile\Music"
}
else
{
    Write-Host "  No Music dir found"
}

#Restoring Videos
Write-Host "Videos Restore" -ForegroundColor Cyan
$videosDir = "$userHostDir\Videos"
if (Test-Path $videosDir)
{
    if (-Not (Test-Path "$userprofile\Videos"))
    {
        $null = New-Item -Path "$userprofile\Videos" -ItemType Directory -Force
    }
    xcopy /d /e /v /i /r /k /y "$videosDir\*" "$userprofile\Videos"
}
else
{
    Write-Host "  No Videos dir found"
}

#Restoring Desktop
Write-Host "Desktop Restore" -ForegroundColor Cyan
$desktopDir = "$userHostDir\Desktop"
if (Test-Path $desktopDir)
{
    if (-Not (Test-Path "$userprofile\Desktop"))
    {
        $null = New-Item -Path "$userprofile\Desktop" -ItemType Directory -Force
    }
    xcopy /d /e /v /i /r /k /y "$desktopDir\*" "$userprofile\Desktop"
}
else
{
    Write-Host "  No Desktop dir found"
}

#Restoring Documents
Write-Host "Documents Restore" -ForegroundColor Cyan
$documentsDir = "$userHostDir\Documents"
if (Test-Path $documentsDir)
{
    if (-Not (Test-Path "$userprofile\Documents"))
    {
        $null = New-Item -Path "$userprofile\Documents" -ItemType Directory -Force
    }
    xcopy /d /e /v /i /r /k /y "$documentsDir\*" "$userprofile\Documents"
}
else
{
    Write-Host "  No Documents dir found"
}

#Restoring Pictures
Write-Host "Pictures Restore" -ForegroundColor Cyan
$picturesDir = "$userHostDir\Pictures"
if (Test-Path $picturesDir)
{
    if (-Not (Test-Path "$userprofile\Pictures"))
    {
        $null = New-Item -Path "$userprofile\Pictures" -ItemType Directory -Force
    }
    xcopy /d /e /v /i /r /k /y "$picturesDir\*" "$userprofile\Pictures"
}
else
{
    Write-Host "  No Pictures dir found"
}

Stop-Transcript
