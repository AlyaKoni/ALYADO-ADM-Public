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
    06.03.2020 Konrad Brunner       Initial Version
    23.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Add-SharePointDefaultDesign-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Logging in
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

# Constants
$ThemeName = "$($AlyaCompanyNameShortM365.ToUpper())SP Default Theme"
$SiteScriptName = "$($AlyaCompanyNameShortM365.ToUpper())SP Default Script"
$SiteDesignNameTeam = "$($AlyaCompanyNameShortM365.ToUpper())SP Default Team Site"
$SiteDesignNameComm = "$($AlyaCompanyNameShortM365.ToUpper())SP Default Communication Site"
$SiteScriptDef = @"
{
  "`$schema": "https://developer.microsoft.com/json-schemas/sp/site-design-script-actions.schema.json",
  "actions": [
    {
      "verb": "applyTheme",
      "themeName": "$ThemeName"
    }
  ],
  "version": 1
}
"@

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Add-SharePointDefaultDesign | PnP" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting theme
Write-Host "Getting theme" -ForegroundColor $CommandInfo
$Theme = Get-PnPTenantTheme -Connection $adminCon -Name $ThemeName -ErrorAction SilentlyContinue
if (-Not $Theme)
{
    throw "Theme does not exist. Please create it first with the script Add-SharePointDefaultTheme.ps1"
}

# Checking site script
Write-Host "Checking site script" -ForegroundColor $CommandInfo
$SiteScript = Get-PnPSiteScript -Connection $adminCon | Where-Object { $_.Title -eq "$SiteScriptName"}
if (-Not $SiteScript)
{
    Write-Warning "Site script not found. Creating now site script $SiteScriptName"
    $SiteScript = Add-PnPSiteScript -Connection $adminCon -Title $SiteScriptName -Content $SiteScriptDef -Description "Fügt das $AlyaCompanyName Design hinzu"
}
else
{
    Write-Host "Updating site script $SiteScriptName"
    $SiteScript = Set-PnPSiteScript -Connection $adminCon -Identity $SiteScript -Title $SiteScriptName -Content $SiteScriptDef -Description "Fügt das $AlyaCompanyName Design hinzu"
}
$SiteScript = Get-PnPSiteScript -Connection $adminCon | Where-Object { $_.Title -eq "$SiteScriptName"}

# Checking team site design
Write-Host "Checking team site design" -ForegroundColor $CommandInfo
$SiteDesignTeam = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SiteDesignNameTeam"}
if (-Not $SiteDesignTeam)
{
    Write-Warning "Team site design not found. Creating now team site design $SiteDesignNameTeam"
    $SiteDesignTeam = Add-PnPSiteDesign -Connection $adminCon -Title $SiteDesignNameTeam -WebTemplate "64" -SiteScript $SiteScript -Description "Fügt das $AlyaCompanyName Design hinzu"
}
else
{
    Write-Host "Updating Team site design $SiteDesignNameTeam"
    $SiteDesignTeam = Set-PnPSiteDesign -Connection $adminCon -Identity $SiteDesignTeam.Id -Title $SiteDesignNameTeam -WebTemplate "64" -SiteScriptIds $SiteScript.Id -Description "Fügt das $AlyaCompanyName Design hinzu"
}
$SiteDesignTeam = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SiteDesignNameTeam"}

# Checking communication site design
Write-Host "Checking communication site design" -ForegroundColor $CommandInfo
$SiteDesignComm = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SiteDesignNameComm"}
if (-Not $SiteDesignComm)
{
    Write-Warning "Communication site design not found. Creating now Communication site design $SiteDesignNameComm"
    $SiteDesignComm = Add-PnPSiteDesign -Connection $adminCon -Title $SiteDesignNameComm -WebTemplate "68" -SiteScript $SiteScript -Description "Fügt das $AlyaCompanyName Design hinzu"
}
else
{
    Write-Host "Updating Communication site design $SiteDesignNameComm"
    $SiteDesignComm = Set-PnPSiteDesign -Connection $adminCon -Identity $SiteDesignComm.Id -Title $SiteDesignNameComm -WebTemplate "68" -SiteScriptIds $SiteScript.Id -Description "Fügt das $AlyaCompanyName Design hinzu"
}
$SiteDesignComm = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SiteDesignNameComm"}

#Stopping Transscript
Stop-Transcript
