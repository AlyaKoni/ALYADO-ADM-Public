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
    28.02.2020 Konrad Brunner       Initial Version
    22.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\groups\Set-OfficeGroupManagers-$($AlyaTimeString).log" | Out-Null

# Constants
$StorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdPublicStorage)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Groups"
Install-ModuleIfNotInstalled "Microsoft.Graph.Identity.DirectoryManagement"
    
# Logins
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Groups | Set-OfficeGroupManagers | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Check group name
if ([string]::IsNullOrEmpty($AlyaGroupManagerGroupName) -or $AlyaGroupManagerGroupName -eq "PleaseSpecify")
{
    Write-Error "AlyaGroupManagerGroupName variable is not defined in 01_ConfigureEnv.ps1. Nothing to do!" -ErrorAction Continue
    exit
}

# Checking group
Write-Host "Checking group" -ForegroundColor $CommandInfo
$Group = Get-MgGroup -Filter "DisplayName eq '$AlyaGroupManagerGroupName'"
if (-Not $Group)
{
    throw "Group '$AlyaGroupManagerGroupName' not found"
}

# Checking usage guidelines for internals
Write-Host "Checking usage guidelines for internals" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$AlyaData\azure\publicStorage\pages\OfficeGroupsNutzung.html"))
{
    throw "Please prepare Office Groups usage guidelines for internals: $AlyaData\azure\publicStorage\pages\OfficeGroupsNutzung.html"
}
try {
    $resp = $null
    ($resp = Invoke-WebRequestIndep -Method "Get" -Uri "https://$StorageAccountName.blob.core.windows.net/pages/OfficeGroupsNutzung.html") | Out-Null
    if (-Not $resp -or $resp.StatusCode -ne 200) { throw }
}
catch {
    throw "Checking prepare Office Groups usage guidelines for internals: $AlyaData\azure\publicStorage\pages\OfficeGroupsNutzung.html and upload it"
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

$Value = $Setting.Values | Where-Object { $_.Name -eq "UsageGuidelinesUrl" }
if ($Value.Value -eq "https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzung.html") {
    Write-Host "Setting 'UsageGuidelinesUrl' was already set to 'https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzung.html'"
} 
else {
    Write-Warning "Setting 'UsageGuidelinesUrl' was set to '$($Value.Value)' updating to 'https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzung.html'"
    ($Setting.Values | Where-Object { $_.Name -eq "UsageGuidelinesUrl" }).Value = "https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzung.html"
}

$Value = $Setting.Values | Where-Object { $_.Name -eq "EnableGroupCreation" }
if ($Value.Value -eq $false) {
    Write-Host "Setting 'EnableGroupCreation' was already set to '$false'"
} 
else {
    Write-Warning "Setting 'EnableGroupCreation' was set to '$($Value.Value)' updating to '$false'"
    ($Setting.Values | Where-Object { $_.Name -eq "EnableGroupCreation" }).Value = $false
}

$Value = $Setting.Values | Where-Object { $_.Name -eq "GroupCreationAllowedGroupId" }
if ($Value.Value -eq $Group.Id) {
    Write-Host "Setting 'GroupCreationAllowedGroupId' was already set to '$($Group.Id)'"
} 
else {
    Write-Warning "Setting 'GroupCreationAllowedGroupId' was set to '$($Value.Value)' updating to '$($Group.Id)'"
    ($Setting.Values | Where-Object { $_.Name -eq "GroupCreationAllowedGroupId" }).Value = $Group.Id
}

Update-MgDirectorySetting -DirectorySettingId $Setting.Id -Values $Setting.Values

#Stopping Transscript
Stop-Transcript
