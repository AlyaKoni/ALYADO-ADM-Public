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
    11.10.2020 Konrad Brunner       Initial Version
    22.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\groups\Set-OfficeGroupExternalSharingEnabled-$($AlyaTimeString).log" | Out-Null

# Constants
$StorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdPublicStorage)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Groups"
    
# Logins
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

# =============================================================
# Graph stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-OfficeGroupExternalSharingEnabled | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking usage guidelines for externals
Write-Host "Checking usage guidelines for externals" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$AlyaData\azure\publicStorage\pages\OfficeGroupsNutzungExterne.html"))
{
    throw "Please prepare Office Groups usage guidelines for externals: $AlyaData\azure\publicStorage\pages\OfficeGroupsNutzungExterne.html"
}
try {
    $resp = $null
    ($resp = Invoke-WebRequestIndep -Method "Get" -Uri "https://$StorageAccountName.blob.core.windows.net/pages/OfficeGroupsNutzungExterne.html") | Out-Null
    if (-Not $resp -or $resp.StatusCode -ne 200) { throw }
}
catch {
    throw "Checking prepare Office Groups usage guidelines for externals: $AlyaData\azure\publicStorage\pages\OfficeGroupsNutzungExterne.html and upload it"
}

# Configuring settings template
Write-Host "Configuring settings template" -ForegroundColor $CommandInfo
$SettingTemplate = Get-MgDirectorySettingTemplate | Where-Object { $_.DisplayName -eq "Group.Unified" }
$Setting = Get-MgDirectorySetting | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
if (-Not $Setting)
{
    Write-Warning "Setting not yet created. Creating one based on template."
    $Values = @()
    foreach($dval in $SettingTemplate.Values) {
	    $Values += @{Name = $dval.Name; Value = $dval.DefaultValue}
    }
    $Setting = New-MgDirectorySetting -DisplayName "Group.Unified" -TemplateId $SettingTemplate.Id -Values $Values
    $Setting = Get-MgDirectorySetting | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
}

$Value = $Setting.Values | Where-Object { $_.Name -eq "GuestUsageGuidelinesUrl" }
if ($Value.Value -eq "https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzungExterne.html") {
    Write-Host "Setting 'GuestUsageGuidelinesUrl' was already set to 'https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzungExterne.html'"
} 
else {
    Write-Warning "Setting 'GuestUsageGuidelinesUrl' was set to '$($Value.Value)' updating to 'https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzungExterne.html'"
    ($Setting.Values | Where-Object { $_.Name -eq "GuestUsageGuidelinesUrl" }).Value = "https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzungExterne.html"
}

$Value = $Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }
if ($Value.Value -eq $true) {
    Write-Host "Setting 'AllowToAddGuests' was already set to '$true'"
} 
else {
    Write-Warning "Setting 'AllowToAddGuests' was set to '$($Value.Value)' updating to '$true'"
    ($Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }).Value = $true
}

$Value = $Setting.Values | Where-Object { $_.Name -eq "AllowGuestsToBeGroupOwner" }
if ($Value.Value -eq $true) {
    Write-Host "Setting 'AllowGuestsToBeGroupOwner' was already set to '$true'"
} 
else {
    Write-Warning "Setting 'AllowGuestsToBeGroupOwner' was set to '$($Value.Value)' updating to '$true'"
    ($Setting.Values | Where-Object { $_.Name -eq "AllowGuestsToBeGroupOwner" }).Value = $true
}

$Value = $Setting.Values | Where-Object { $_.Name -eq "AllowGuestsToAccessGroups" }
if ($Value.Value -eq $true) {
    Write-Host "Setting 'AllowGuestsToAccessGroups' was already set to '$true'"
} 
else {
    Write-Warning "Setting 'AllowGuestsToAccessGroups' was set to '$($Value.Value)' updating to '$true'"
    ($Setting.Values | Where-Object { $_.Name -eq "AllowGuestsToAccessGroups" }).Value = $true
}

Update-MgDirectorySetting -DirectorySettingId $Setting.Id -Values $Setting.Values

#Stopping Transscript
Stop-Transcript
