#Requires -Version 7.0

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
    05.08.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$spSiteUrl
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\teams\Configure-DefaultTeamSharePointAccess-$($AlyaTimeString).log" | Out-Null

# Constants
[string]$TitleAndGroupName = "$($AlyaCompanyNameShortM365.ToUpper())TM"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Logins
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Teams | Configure-DefaultTeamSharePointAccess | Teams" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking team
Write-Host "Checking team site" -ForegroundColor $CommandInfo
$site = Get-PnPTenantSite -Connection $adminCon -Url $spSiteUrl -ErrorAction SilentlyContinue
if (-Not $site)
{
    throw "Site $($spSiteUrl) not found."
}

# Setting SharePoint access
Write-Host "Setting SharePoint access" -ForegroundColor $CommandInfo
$siteCon = LoginTo-PnP -Url $spSiteUrl
$mGroup = Get-PnPGroup -Connection $siteCon -AssociatedMemberGroup
Set-PnPGroupPermissions -Connection $siteCon -Identity $mGroup -AddRole @("Read") -RemoveRole @("Contributor","Editor") -ErrorAction SilentlyContinue
Set-PnPGroupPermissions -Connection $siteCon -Identity $mGroup -AddRole @("Lesen") -RemoveRole @("Bearbeiten","Mitwirken") -ErrorAction SilentlyContinue

#Stopping Transscript
Stop-Transcript
