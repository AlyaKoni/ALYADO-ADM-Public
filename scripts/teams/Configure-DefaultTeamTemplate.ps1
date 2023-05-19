#Requires -Version 7.0

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
    11.04.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [bool]$assignedGroups = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\teams\Configure-DefaultTeamTemplate-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MicrosoftTeams"

# Logins
LoginTo-Teams

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Teams | Configure-DefaultTeamTemplate | Teams" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking team

$TemplateListEn = Get-CsTeamTemplateList -PublicTemplateLocale "en-US"
$TemplateListDe = Get-CsTeamTemplateList -PublicTemplateLocale "de-DE"
$ProjectTemplateEn = $TemplateListEn | Where-Object { $_.Name -eq "Manage a Project" }
$ProjectTemplateDe = $TemplateListDe | Where-Object { $_.Name -eq "Ein Projekt verwalten" }
$ProjectTemplateJsonEn = Get-CsTeamTemplate -OdataId $ProjectTemplateEn.OdataId
$ProjectTemplateJsonDe = Get-CsTeamTemplate -OdataId $ProjectTemplateDe.OdataId

$ProjectTemplateJsonEn.DisplayName = "$($AlyaCompanyNameShortM365.ToUpper())TM Project"
$ProjectTemplateJsonEn.Category = $null
New-CsTeamTemplate -Locale "en-US" -Body $ProjectTemplateJsonEn

$ProjectTemplateJsonDe.DisplayName = "$($AlyaCompanyNameShortM365.ToUpper())TM Projekt"
$ProjectTemplateJsonDe.Category = $null
New-CsTeamTemplate -Locale "de-DE" -Body $ProjectTemplateJsonDe

<#
$TemplateListEn | Where-Object { $_.Name -like "$($AlyaCompanyNameShortM365.ToUpper())*" }
$TemplateListDe | Where-Object { $_.Name -like "$($AlyaCompanyNameShortM365.ToUpper())*" }
Remove-CsTeamTemplate -OdataId /api/teamtemplates/v1.0/09750b21-1b50-4f81-a9bf-1071fdd46931/Tenant/de-DE
Remove-CsTeamTemplate -OdataId /api/teamtemplates/v1.0/5b26980c-0691-46da-b9e9-1dbee63794fb/Tenant/en-US
Remove-CsTeamTemplate -OdataId /api/teamtemplates/v1.0/09750b21-1b50-4f81-a9bf-1071fdd46931/Tenant/de-DE
Remove-CsTeamTemplate -OdataId /api/teamtemplates/v1.0/5b26980c-0691-46da-b9e9-1dbee63794fb/Tenant/en-US
#>

#Stopping Transscript
Stop-Transcript
