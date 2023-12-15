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
    23.04.2023 Konrad Brunner       Added Graph options

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Disable-SiteCreation-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Online.Sharepoint.PowerShell"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logging in
LoginTo-SPO
LoginTo-MgGraph -Scopes "SharePointTenantSettings.ReadWrite.All"

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Disable-SiteCreation | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Disabling site creation
Write-Host "Disabling site creation" -ForegroundColor $CommandInfo
$setting = Invoke-MgGraphRequest -Method "Get" -Uri "$AlyaGraphEndpoint/beta/admin/sharepoint/settings"

# Checking site creation value
if ($setting.isSiteCreationUIEnabled -ne $false){
    Write-Warning "Site creation UI was set to '$($setting.isSiteCreationUIEnabled)', setting to '$false'"
    $newSettings = @{
        "isSiteCreationUIEnabled" = $false
    }
    Invoke-MgGraphRequest -Method "Patch" -Uri "$AlyaGraphEndpoint/beta/admin/sharepoint/settings" -Body ($newSettings | ConvertTo-Json)
}
else {
    Write-host "Site creation UI was alreadyset to '$false'"
}

# Checking site creation value
if ($setting.isSiteCreationEnabled -ne $false){
    Write-Warning "Site creation was set to '$($setting.isSiteCreationEnabled)', setting to '$false'"
    $newSettings = @{
        "isSiteCreationEnabled" = $false
    }
    Invoke-MgGraphRequest -Method "Patch" -Uri "$AlyaGraphEndpoint/beta/admin/sharepoint/settings" -Body ($newSettings | ConvertTo-Json)
}
else {
    Write-host "Site creation was alreadyset to '$false'"
}

# Checking site page creation value
if ($setting.isSitePagesCreationEnabled -ne $false){
    Write-Warning "Site page creation was set to '$($setting.isSitePagesCreationEnabled)', setting to '$false'"
    $newSettings = @{
        "isSitePagesCreationEnabled" = $false
    }
    Invoke-MgGraphRequest -Method "Patch" -Uri "$AlyaGraphEndpoint/beta/admin/sharepoint/settings" -Body ($newSettings | ConvertTo-Json)
}
else {
    Write-host "Site page creation was alreadyset to '$false'"
}

$TenantConfig = Get-SPOTenant
if ($TenantConfig.DisplayStartASiteOption)
{
    Write-Warning "Site creation was enabled. Disabling it now"
    Set-SPOTenant -DisplayStartASiteOption $false
}
else
{
    Write-Host "Site creation was already disabled" -ForegroundColor $CommandSuccess
}

#Stopping Transscript
Stop-Transcript
