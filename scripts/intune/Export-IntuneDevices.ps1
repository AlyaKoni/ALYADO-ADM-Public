#Requires -Version 2.0

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


    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    27.05.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$outputDirectory = $null #Defaults to "$AlyaData\intune"
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Export-IntuneDevices-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

#Members
if (-Not $outputDirectory)
{
    $outputDirectory = "$AlyaData\intune"
}
if (-Not (Test-Path $outputDirectory))
{
    New-Item -Path $outputDirectory -ItemType Directory -Force
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "Directory.Read.All",
    "DeviceManagementManagedDevices.Read.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Export-IntuneDevices | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$uri = "/beta/deviceManagement/managedDeviceOverview"
$managedDeviceOverview = Get-MsGraphCollection -Uri $uri
$managedDeviceOverview | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path "$outputDirectory\managedDeviceOverview.json" -Force

$uri = "/beta/deviceManagement/managedDevices"
$managedDevices = Get-MsGraphCollection -Uri $uri
foreach($device in $managedDevices)
{
    $device | Add-Member -Name "managedDeviceUser" -Value @() -MemberType NoteProperty
    $uri = "/beta/deviceManagement/manageddevices('$($device.id)')?`$select=userId"
    $managedDeviceUser = Get-MsGraphObject -Uri $uri
    $device.managedDeviceUser = $managedDeviceUser
    $uri = "/beta/deviceManagement/manageddevices('$($device.id)')?`$select=hardwareinformation,iccid,udid,ethernetMacAddress"
    $hardwareinformation = Get-MsGraphObject -Uri $uri
    $device.hardwareinformation = $hardwareinformation
    $device | Add-Member -Name "primaryUsers" -Value @() -MemberType NoteProperty
    $uri = "/beta/deviceManagement/manageddevices('$($device.id)')/users"
    $primaryUsers = Get-MsGraphObject -Uri $uri
    $device.primaryUsers = $primaryUsers
    $device | Add-Member -Name "detectedApps" -Value @() -MemberType NoteProperty
    $uri = "/beta/deviceManagement/manageddevices('$($device.id)')?`$expand=detectedApps"
    $detectedApps = Get-MsGraphObject -Uri $uri
    $device.detectedApps = $detectedApps
}
$managedDevices | ConvertTo-Json -Depth 50 | Set-Content -Encoding UTF8 -Path "$outputDirectory\managedDevices.json" -Force

#Stopping Transscript
Stop-Transcript
