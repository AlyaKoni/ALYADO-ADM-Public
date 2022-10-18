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
    15.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string] [Parameter(Mandatory=$true)]
    $Url
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Set-ModernSiteEnableScripts-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Online.Sharepoint.PowerShell"

# Logging in
LoginTo-SPO

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Set-ModernSiteEnableScripts | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking site
Write-Host "Checking site" -ForegroundColor $CommandInfo
$Site = Get-SPOSite -Identity $Url -ErrorAction SilentlyContinue
if (-Not $Site)
{
    throw "Site not found on url $($Url)!"
}
Write-Host "Atcual DenyAddAndCustomizePages setting: $($Site.DenyAddAndCustomizePages)"

if ($Site.DenyAddAndCustomizePages)
{
    Set-SPOSite -Identity $Url -DenyAddAndCustomizePages $false
    $Site = Get-SPOSite -Identity $Url
    Write-Host "New DenyAddAndCustomizePages setting: $($Site.DenyAddAndCustomizePages)"
}
else
{
    Write-Host "  Setting was already disabled"
}

#Stopping Transscript
Stop-Transcript
