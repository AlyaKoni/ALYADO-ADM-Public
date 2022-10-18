#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2021

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
    06.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Add-SharePointDesign-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Online.Sharepoint.PowerShell"

# Logging in
LoginTo-SPO

# Constants

$ThemeName = "$($AlyaCompanyNameShortM365.ToUpper())SP Default Theme"
$SiteScriptName = "$($AlyaCompanyNameShortM365.ToUpper())SP Default Script"
$SiteDesignNameTeam = "$($AlyaCompanyNameShortM365.ToUpper())SP Default Team Site"
$SiteDesignNameComm = "$($AlyaCompanyNameShortM365.ToUpper())SP Default Communication Site"
$SiteScriptDef = @"
{
  "$schema": "https://developer.microsoft.com/json-schemas/sp/site-design-script-actions.schema.json",
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
Write-Host "SharePoint | Add-SharePointDesign | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting theme
Write-Host "Getting theme" -ForegroundColor $CommandInfo
try { $Theme = Get-SPOTheme -Name $ThemeName -ErrorAction SilentlyContinue } catch {}
if (-Not $Theme)
{
    throw "Theme does not exist. Please create it first"
}

# Checking site script
Write-Host "Checking site script" -ForegroundColor $CommandInfo
$SiteScript = Get-SPOSiteScript | where { $_.Title -eq "$SiteScriptName"}
if (-Not $SiteScript)
{
    Write-Warning "Site script not found. Creating now site script $SiteScriptName"
    $SiteScript = Add-SPOSiteScript -Title $SiteScriptName -Content $SiteScriptDef -Description "Fügt das AlyaConsulting Design hinzu"
}

# Checking site design
Write-Host "Checking team site design" -ForegroundColor $CommandInfo
$SiteDesignTeam = Get-SPOSiteDesign | where { $_.Title -eq "$SiteDesignNameTeam"}
if (-Not $SiteDesignTeam)
{
    Write-Warning "Team site design not found. Creating now team site design $SiteDesignNameTeam"
    $SiteDesignTeam = Add-SPOSiteDesign -Title $SiteDesignNameTeam -WebTemplate "64" -SiteScripts $SiteScript.Id -Description "Fügt das AlyaConsulting Design hinzu"
}

# Checking site design
Write-Host "Checking communication site design" -ForegroundColor $CommandInfo
$SiteDesignComm = Get-SPOSiteDesign | where { $_.Title -eq "$SiteDesignNameComm"}
if (-Not $SiteDesignComm)
{
    Write-Warning "Communication site design not found. Creating now Communication site design $SiteDesignNameComm"
    $SiteDesignComm = Add-SPOSiteDesign -Title $SiteDesignNameComm -WebTemplate "68" -SiteScripts $SiteScript.Id -Description "Fügt das AlyaConsulting Design hinzu"
}

#Stopping Transscript
Stop-Transcript
