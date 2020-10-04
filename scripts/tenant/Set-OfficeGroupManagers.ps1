#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

    This file is part of the Alya Base Configuration.
    The Alya Base Configuration is free software: you can redistribute it
	and/or modify it under the terms of the GNU General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
	Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
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
    28.02.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-OfficeGroupManagers-$($AlyaTimeString).log" | Out-Null

# Constants

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "AzureAdPreview"
Install-ModuleIfNotInstalled "MSOnline"
    
# Logins
LoginTo-Ad
LoginTo-Msol

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-OfficeGroupManagers | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Check group name
if ([string]::IsNullOrEmpty($AlyaGroupManagerGroupName))
{
    Write-Error "AlyaGroupManagerGroupName variable is not defined in 01_ConfigureEnv.ps1. Nothing to do!" -ErrorAction Continue
    exit
}

# Preparing usage guidelines
Write-Host "Preparing usage guidelines" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$AlyaData\azure\publicStorage\pages\OfficeGroupsNutzung.html"))
{
    throw "Please prepare Office Groups usage guidelines"
}
if (-Not (Test-Path "$AlyaData\azure\publicStorage\pages\OfficeGroupsNutzungExterne.html"))
{
    throw "Please prepare Office Groups usage guidelines for externals"
}

# Configuring group setting
Write-Host "Configuring group setting" -ForegroundColor $CommandInfo
$MsolCompanySettings = Get-MsolCompanyInformation
if ($MsolCompanySettings.UsersPermissionToCreateGroupsEnabled)
{
    Write-Warning "UsersPermissionToCreateGroupsEnabled was enabled. Disabling it now."
    Set-MsolCompanySettings -UsersPermissionToCreateGroupsEnabled $False
}
else
{
    Write-Host "UsersPermissionToCreateGroupsEnabled was already disabled." -ForegroundColor $CommandSuccess
}

#TODO $AlyaGroupManagerMembers

# Preparing security group
Write-Host "Preparing security group" -ForegroundColor $CommandInfo
$GrpManGrp = Get-MsolGroup -SearchString $AlyaGroupManagerGroupName
if (-Not $GrpManGrp)
{
    Write-Warning "GroupManager group not found. Creating the GroupManager group $AlyaGroupManagerGroupName"
    $GrpManGrp = New-MsolGroup -DisplayName $AlyaGroupManagerGroupName -Description "Members of this group can manage O365 groups"
}

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-OfficeGroupManagers | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Configuring settings template
Write-Host "Configuring settings template" -ForegroundColor $CommandInfo
$SettingTemplate = Get-AzureADDirectorySettingTemplate | where { $_.DisplayName -eq "Group.Unified" }
$Setting = Get-AzureADDirectorySetting | where { $_.DisplayName -eq "Group.Unified" }
if (-Not $Setting)
{
    Write-Warning "Setting not yet created. Creating one based on template."
    $Setting = $SettingTemplate.CreateDirectorySetting()
    $Setting["UsageGuidelinesUrl"] = "https://alyainfpstrg001.blob.core.windows.net/public/pages/OfficeGroupsNutzung.html"
    $Setting["GuestUsageGuidelinesUrl"] = "https://alyainfpstrg001.blob.core.windows.net/public/pages/OfficeGroupsNutzungExterne.html"
    $Setting["EnableGroupCreation"] = $false
    $Setting["GroupCreationAllowedGroupId"] = $GrpManGrp.ObjectId
    $Setting["EnableMIPLabels"] = $true
    $Setting["AllowToAddGuests"] = $true
    $Setting["AllowGuestsToAccessGroups"] = $true
    $Setting["AllowGuestsToBeGroupOwner"] = $true
    New-AzureADDirectorySetting -DirectorySetting $Setting
}
else
{
    $Setting["UsageGuidelinesUrl"] = "https://alyainfpstrg001.blob.core.windows.net/public/pages/OfficeGroupsNutzung.html"
    $Setting["GuestUsageGuidelinesUrl"] = "https://alyainfpstrg001.blob.core.windows.net/public/pages/OfficeGroupsNutzungExterne.html"
    $Setting["EnableGroupCreation"] = $false
    $Setting["GroupCreationAllowedGroupId"] = $GrpManGrp.ObjectId
    $Setting["EnableMIPLabels"] = $true
    $Setting["AllowToAddGuests"] = $true
    $Setting["AllowGuestsToAccessGroups"] = $true
    $Setting["AllowGuestsToBeGroupOwner"] = $true
    Set-AzureADDirectorySetting -Id $Setting.Id -DirectorySetting $Setting
}

#Stopping Transscript
Stop-Transcript
