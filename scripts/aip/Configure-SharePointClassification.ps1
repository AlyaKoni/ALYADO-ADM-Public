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
    15.10.2020 Konrad Brunner       Initial Version

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
    $defaultLabel = "Internal.External"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "AzureAdPreview"
Install-ModuleIfNotInstalled "ImportExcel"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AIP | Configure-SharePointClassification | Azure" -ForegroundColor $CommandInfo
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
Write-Host "Tenant | Configure-SharePointClassification | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Configuring settings template
Write-Host "Configuring settings template" -ForegroundColor $CommandInfo
$SettingTemplate = Get-AzureADDirectorySettingTemplate | Where-Object { $_.DisplayName -eq "Group.Unified" }
$Setting = Get-AzureADDirectorySetting | Where-Object { $_.DisplayName -eq "Group.Unified" }
if (-Not $Setting)
{
    Write-Warning "Setting not yet created. Creating one based on template."
    $Setting = $SettingTemplate.CreateDirectorySetting()
    $Setting["UsageGuidelinesUrl"] = "https://alyainfpstrg001.blob.core.windows.net/public/pages/OfficeGroupsNutzung.html"
    $Setting["GuestUsageGuidelinesUrl"] = "https://alyainfpstrg001.blob.core.windows.net/public/pages/OfficeGroupsNutzungExterne.html"
    $setting["ClassificationList"] = $labelList
    $setting["DefaultClassification"] = $defaultLabel
    New-AzureADDirectorySetting -DirectorySetting $Setting
}
else
{
    $Setting["UsageGuidelinesUrl"] = "https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzung.html"
    $Setting["GuestUsageGuidelinesUrl"] = "https://$StorageAccountName.blob.core.windows.net/public/pages/OfficeGroupsNutzungExterne.html"
    $setting["ClassificationList"] = $labelList
    $setting["DefaultClassification"] = $defaultLabel
    Set-AzureADDirectorySetting -Id $Setting.Id -DirectorySetting $Setting
}

#Stopping Transscript
Stop-Transcript
