#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2021

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
    10.08.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$SiteUrl
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Export-SiteScript-$($AlyaTimeString).log" | Out-Null

# Checking modules
Install-ModuleIfNotInstalled "Microsoft.Online.Sharepoint.PowerShell"
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Logins
LoginTo-PnP -Url $SiteUrl

# Export site script
$site = Get-PnPWeb
$lists = Get-PnPList -Includes RootFolder.ServerRelativeUrl
$expLists = @()
foreach($list in $lists)
{
    if ($list.RootFolder.ServerRelativeUrl -notlike "*_catalogs*")
    {
        $expLists += $list.RootFolder.ServerRelativeUrl.Replace($site.ServerRelativeUrl+"/", "")
    }
}

# Logins
LoginTo-SPO

# Export
$extracted = Get-SPOSiteScriptFromWeb -WebUrl $SiteUrl -IncludedLists $expLists -IncludeBranding -IncludeTheme -IncludeRegionalSettings -IncludeSiteExternalSharingCapability -IncludeLinksToExportedItems
$scriptFile = "$AlyaData\sharepoint\SiteScript_" + $SiteUrl.Replace("https://", "").Replace("/", "_") + ".json"
Set-Content -Path $scriptFile -Value $extracted

Write-Host "SiteScript exported to $scriptFile" -ForegroundColor $CommandSuccess

#Stopping Transscript
Stop-Transcript