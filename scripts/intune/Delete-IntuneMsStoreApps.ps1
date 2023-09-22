#Requires -Version 2.0

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


    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    21.09.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Delete-IntuneMsStoreApps-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$AppPrefix = "Win10 "
if (-Not [string]::IsNullOrEmpty($AlyaAppPrefix)) {
    $AppPrefix = "$AlyaAppPrefix "
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "Directory.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementApps.ReadWrite.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Delete-IntuneMsStoreApps | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting list of all ms store apps
Write-Host "Getting list of all ms store apps" -ForegroundColor $CommandInfo
$uri = "/beta/deviceAppManagement/mobileApps"
$apps = (Get-MsGraphCollection -Uri $uri)
if (-Not $apps -or $apps.Count -eq 0)
{
    throw "No apps found!."
}

$langApps = $apps | Where-Object { $_.displayName -like "$($AppPrefix)WindowsLanguage*" }
if (-Not $langApps -or $langApps.Count -eq 0)
{
    Write-Warning "No language apps found!."
}

foreach($langApp in $langApps)
{
    # Deleting app
    Write-Host "Deleting app $($langApp.displayName) $($langApp.id)" -ForegroundColor $CommandInfo
    $uri = "/beta/deviceAppManagement/mobileApps/$($langApp.id)"
    $null = Delete-MsGraphObject -Uri $uri
}

$storeApps = $apps | Where-Object { $_."@odata.type" -eq "#microsoft.graph.microsoftStoreForBusinessApp" }
if (-Not $storeApps -or $storeApps.Count -eq 0)
{
    Write-Warning "No ms store apps found!."
}

foreach($storeApp in $storeApps)
{
    # Deleting app
    Write-Host "Deleting app $($storeApp.displayName) $($storeApp.id)" -ForegroundColor $CommandInfo
    $uri = "/beta/deviceAppManagement/mobileApps/$($storeApp.id)"
    $null = Delete-MsGraphObject -Uri $uri
}

#Stopping Transscript
Stop-Transcript
