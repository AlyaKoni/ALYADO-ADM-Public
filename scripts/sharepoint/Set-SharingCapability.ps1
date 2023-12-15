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
    06.03.2020 Konrad Brunner       Initial Version
    23.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Set-SharingCapability-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logging in
LoginTo-MgGraph -Scopes "SharePointTenantSettings.ReadWrite.All"

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Set-SharingCapability | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Configuring sharing capability
Write-Host "Configuring sharing capability" -ForegroundColor $CommandInfo
$setting = Invoke-MgGraphRequest -Method "Get" -Uri "$AlyaGraphEndpoint/beta/admin/sharepoint/settings"

# Checking sharing capability
$SharingOption = "externalUserAndGuestSharing"
if ($AlyaSharingPolicy -eq "KnownAccountsOnly")
{
    $SharingOption = "externalUserSharingOnly"
}
if ($AlyaSharingPolicy -eq "AdminOnly")
{
    $SharingOption = "existingExternalUserSharingOnly"
}
if ($AlyaSharingPolicy -eq "None")
{
    $SharingOption = "disabled"
}

# Checking sharing capability value
if ($setting.sharingCapability -ne $SharingOption){
    Write-Warning "Sharing capability was set to '$($setting.sharingCapability)', setting to '$SharingOption'"
    $newSettings = @{
        "sharingCapability" = $SharingOption
    }
    Invoke-MgGraphRequest -Method "Patch" -Uri "$AlyaGraphEndpoint/beta/admin/sharepoint/settings" -Body ($newSettings | ConvertTo-Json)
}
else {
    Write-host "Sharing capability was alreadyset to '$SharingOption'"
}

#Stopping Transscript
Stop-Transcript
