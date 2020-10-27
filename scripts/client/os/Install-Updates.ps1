#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2020

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
    Alya Basis Konfiguration ist Freie Software: Sie koennen es unter den
	Bedingungen der GNU General Public License, wie von der Free Software
	Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veroeffentlichten Version, weiter verteilen und/oder modifizieren.
    Alya Basis Konfiguration wird in der Hoffnung, dass es nuetzlich sein wird,
	aber OHNE JEDE GEWAEHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewaehrleistung der MARKTFAEHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
	https://www.gnu.org/licenses/gpl-3.0.txt

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    16.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [int]$retryCount = 0
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\client\os\Install-Updates-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PSWindowsUpdate"

#Main
Write-Host "Last result" -ForegroundColor $CommandInfo
$result = Get-WULastResults
$result | fl

if ($retryCount -gt 5)
{
    Write-Error "Too much tetries, stopping" -ErrorAction Continue
    Exit 99
}

$restartScript = [io.path]::GetFullPath($env:AllUsersProfile) + "\Start Menu\Programs\Startup\AlyaUpdateRestart.cmd"

Write-Host "Checking for updates" -ForegroundColor $CommandInfo
$availableUpdates = Get-WUlist -MicrosoftUpdate
$availableUpdates
if ($availableUpdates.Count -gt 0)
{
    Write-Host "We have $($availableUpdates.Count) updates to install"
    Write-Host "Preparing restart after reboot"
    "powershell.exe -NoLogo -ExecutionPolicy Bypass -Command `"Start-Process powershell.exe -ArgumentList '-NoLogo -ExecutionPolicy Bypass -File \`"$PSCommandPath\`" -retryCount $($retryCount+1)' -Verb RunAs`"" | Set-Content -Path $restartScript -Force
    Write-Host "Installing updates"
    $serviceMgrs = Get-WUServiceManager | Select -Property ServiceID
    if ($serviceMgrs.ServiceID -notcontains "7971f918-a847-4430-9279-4a52d1efe18d")
    {
        Add-WUServiceManager -ServiceID "7971f918-a847-4430-9279-4a52d1efe18d" -AddServiceFlag 7
    }
    if ($serviceMgrs.ServiceID -notcontains "9482f4b4-e343-43b6-b170-9a65bc822c77")
    {
        Add-WUServiceManager -ServiceID "9482f4b4-e343-43b6-b170-9a65bc822c77"
    }
    Start-WUScan #-SearchCriteria "IsInstalled=0 and IsHidden=0"
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot -RootCategories 'Critical Updates', 'Definition Updates', 'Drivers', 'Microsoft', 'Security Updates', 'Updates', 'Feature Packs', 'Service Packs', 'Tools', 'Update Rollups', 'Upgrades'
    cmd /c shutdown /r /t 0
}
else
{
    Write-Host "Checking for upgrades" -ForegroundColor $CommandInfo
    $toolsDir = "$AlyaTools\Win10Upgrade"
    $exeFile = "$toolsDir\Win10Upgrade.exe"
    if (-Not (Test-Path $toolsDir))
    {
        New-Item -Path $toolsDir -ItemType Directory -Force | Out-Null
    }
    if ((Test-Path $exeFile))
    {
        Remove-Item -Path $exeFile -Force | Out-Null
    }
    $url = "https://go.microsoft.com/fwlink/?LinkID=799445"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $exeFile
    $file = Get-Item -Path $exeFile -Force
    $toBeUpgraded = $true
    if ((Test-Path "$exeFile.$($env:COMPUTERNAME).txt"))
    {
        $actVersion = Get-Content -Path "$exeFile.$($env:COMPUTERNAME).txt" -Raw -Encoding UTF8
        if ($file.VersionInfo.ProductVersion.Trim() -eq $actVersion.Trim())
        {
            $toBeUpgraded = $false
        }
    }
    if ($toBeUpgraded)
    {
        Write-Host "Launching $exeFile"
        cmd /c $exeFile /quiet /skipeula /auto upgrade /telemetry Disable /copylogs "$toolsDir"
        $file.VersionInfo.ProductVersion | Set-Content -Path "$exeFile.$($env:COMPUTERNAME).txt" -Force -Encoding UTF8
        Wait-UntilProcessEnds "Windows10UpgraderApp"
    }
    else
    {
    if ((Test-Path $restartScript))
    {
        $tmp = Remove-Item -Path $restartScript -Force
    }
    Write-Host "Device has all actual updates installed!" -ForegroundColor $CommandSuccess
    }
}

#Stopping Transscript
Stop-Transcript