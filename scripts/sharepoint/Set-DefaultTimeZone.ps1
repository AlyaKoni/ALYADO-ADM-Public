#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2021-2023

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

    To design your own SharePoint Theme use the UI Fabric Theme Designer
    https://fabricweb.z5.web.core.windows.net/pr-deploy-site/refs/heads/master/theming-designer/index.html

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    22.10.2021 Konrad Brunner       Initial Version
    23.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Set-DefaultTimeZone-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logging in
LoginTo-MgGraph -Scopes "SharePointTenantSettings.ReadWrite.All"

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Set-DefaultTimeZone | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Configuring default time zone
Write-Host "Configuring default time zone" -ForegroundColor $CommandInfo
$setting = Invoke-MgGraphRequest -Method "Get" -Uri "https://graph.microsoft.com/beta/admin/sharepoint/settings"
$timeZoneEn = "(UTC) Dublin, Edinburgh, Lisbon, London"
$timeZoneDe = "(UTC) Dublin, Edinburgh, Lisbon, London"
switch ($AlyaTimeZone)
{
    "W. Europe Standard Time" {
        $timeZoneEn = "(UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna"
        $timeZoneDe = "(UTC+01:00) Amsterdam, Berlin, Bern, Rom, Stockholm, Wien"
    }
}

if ($setting.tenantDefaultTimezone -ne $timeZoneEn -and $setting.tenantDefaultTimezone -ne $timeZoneDe){
    Write-Warning "Default TimeZone was set to '$($setting.tenantDefaultTimezone)', setting to '$timeZoneEn'"
    $newSettings = @{
        "tenantDefaultTimezone" = $AlyaTimeZone
    }
    Invoke-MgGraphRequest -Method "Patch" -Uri "https://graph.microsoft.com/beta/admin/sharepoint/settings" -Body ($newSettings | ConvertTo-Json)
}
else {
    Write-host "Default TimeZone was alreadyset to '$timeZoneEn'"
}

#Stopping Transscript
Stop-Transcript
