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
    15.10.2020 Konrad Brunner       Initial Version
    06.09.2023 Konrad Brunner       Move to Graph

#>

[CmdletBinding()]
Param(
    [string]$inputLabelFile = $null, #Defaults to "$AlyaData\aip\Labels.xlsx"
    [string]$defaultLabel = $null #Defaults to Internal.External
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aip\Configure-SharePointClassification-$($AlyaTimeString).log" | Out-Null

# Constants
$StorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdPublicStorage)"
if (-Not $inputLabelFile)
{
    $inputLabelFile = "$AlyaData\aip\Labels.xlsx"
}
if (-Not $defaultLabel)
{
    $defaultLabel = "Internal.Internal"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"
Install-ModuleIfNotInstalled "ImportExcel"

# Logins
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AIP | Configure-SharePointClassification | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

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

# Reading inputLabelFile file
Write-Host "Reading label file from '$inputLabelFile'" -ForegroundColor $CommandInfo
if (-Not (Test-Path $inputLabelFile))
{
    throw "'$inputLabelFile' not found!"
}
$labelDefs = Import-Excel $inputLabelFile -ErrorAction Stop
$labelList = $labelDefs.NameEn -join ", " -replace ", ,", ","

Write-Host "Configuring following labels" -ForegroundColor $CommandInfo
$labelList

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Configure-SharePointClassification | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Configuring settings template
Write-Host "Configuring settings template" -ForegroundColor $CommandInfo
$SettingTemplate = Get-MgBetaDirectorySettingTemplate | Where-Object { $_.DisplayName -eq "Group.Unified" }
$Setting = Get-MgBetaDirectorySetting | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
if (-Not $Setting)
{
    Write-Warning "Setting not yet created. Creating one based on template."
    $Values = @()
    foreach($dval in $SettingTemplate.Values) {
	    $Values += @{Name = $dval.Name; Value = $dval.DefaultValue}
    }
    $Setting = New-MgBetaDirectorySetting -DisplayName "Group.Unified" -TemplateId $SettingTemplate.Id -Values $Values
    $Setting = Get-MgBetaDirectorySetting | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
}

$Value = $Setting.Values | Where-Object { $_.Name -eq "UsageGuidelinesUrl" }
if ($Value.Value -eq "https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzung.html") {
    Write-Host "Setting 'UsageGuidelinesUrl' was already set to 'https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzung.html'"
} 
else {
    Write-Warning "Setting 'UsageGuidelinesUrl' was set to '$($Value.Value)' updating to 'https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzung.html'"
    ($Setting.Values | Where-Object { $_.Name -eq "UsageGuidelinesUrl" }).Value = "https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzung.html"
}

$Value = $Setting.Values | Where-Object { $_.Name -eq "GuestUsageGuidelinesUrl" }
if ($Value.Value -eq "https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzungExterne.html") {
    Write-Host "Setting 'GuestUsageGuidelinesUrl' was already set to 'https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzungExterne.html'"
} 
else {
    Write-Warning "Setting 'GuestUsageGuidelinesUrl' was set to '$($Value.Value)' updating to 'https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzungExterne.html'"
    ($Setting.Values | Where-Object { $_.Name -eq "GuestUsageGuidelinesUrl" }).Value = "https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzungExterne.html"
}

$Value = $Setting.Values | Where-Object { $_.Name -eq "ClassificationList" }
if ($Value.Value -eq $labelList) {
    Write-Host "Setting 'ClassificationList' was already set to '$labelList'"
} 
else {
    Write-Warning "Setting 'ClassificationList' was set to '$($Value.Value)' updating to '$labelList'"
    ($Setting.Values | Where-Object { $_.Name -eq "ClassificationList" }).Value = $labelList
}

$Value = $Setting.Values | Where-Object { $_.Name -eq "DefaultClassification" }
if ($Value.Value -eq $defaultLabel) {
    Write-Host "Setting 'DefaultClassification' was already set to '$defaultLabel'"
} 
else {
    Write-Warning "Setting 'DefaultClassification' was set to '$($Value.Value)' updating to '$defaultLabel'"
    ($Setting.Values | Where-Object { $_.Name -eq "DefaultClassification" }).Value = $defaultLabel
}

Update-MgBetaDirectorySetting -DirectorySettingId $Setting.Id -Values $Setting.Values

#Stopping Transscript
Stop-Transcript
