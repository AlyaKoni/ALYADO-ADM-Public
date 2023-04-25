#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2023

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
    23.04.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Disable-SharingForExternalUsers-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logging in
LoginTo-MgGraph -Scopes "SharePointTenantSettings.ReadWrite.All"

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Disable-SharingForExternalUsers | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Disable sharing for external users
Write-Host "Disable sharing for external users" -ForegroundColor $CommandInfo
$setting = Invoke-MgGraphRequest -Method "Get" -Uri "https://graph.microsoft.com/beta/admin/sharepoint/settings"

if ($setting.isResharingByExternalUsersEnabled -ne $false){
    Write-Warning "Sharing for external users was set to '$($setting.isResharingByExternalUsersEnabled)', setting to '$false'"
    $newSettings = @{
        "isResharingByExternalUsersEnabled" = $false
    }
    Invoke-MgGraphRequest -Method "Patch" -Uri "https://graph.microsoft.com/beta/admin/sharepoint/settings" -Body ($newSettings | ConvertTo-Json)
}
else {
    Write-host "Sharing for external users was alreadyset to '$false'"
}

#Stopping Transscript
Stop-Transcript
