#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2022

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
    24.03.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Update-AllSitesSiteDesigns-$($AlyaTimeString).log" | Out-Null

# Checking modules
Install-ModuleIfNotInstalled "Microsoft.Online.Sharepoint.PowerShell"

# Logins
LoginTo-SPO

# Getting existing site designs
Write-Host "Getting existing site designs" -ForegroundColor $CommandInfo
$SiteDesigns = Get-SPOSiteDesign

# Walk through
Write-Host "Updating site designs on all sharepoint sites" -ForegroundColor $CommandInfo
$sites = Get-SPOSite -Limit 9999999
foreach($site in $sites)
{
    Write-Host "$($site.Url)" -ForegroundColor $CommandInfo
    Write-Host "  Template: $($site.Template)"
    $runs = Get-SPOSiteDesignRun -WebUrl $site.Url
    $toRuns = @()
    Write-Host "  Used site designs"
    foreach($run in $runs)
    {
        Write-Host "    '$($run.SiteDesignTitle)' v$($run.SiteDesignVersion) $($run.SiteDesignId)"
        $SiteDesign = $SiteDesigns | where { $_.Title -eq $run.SiteDesignTitle }
        if (-Not $SiteDesign)
        {
            Write-Host "    Can't find site design. Not able to update it!"
        }
        else
        {
            if (-Not ($toRuns | where { $_.Title -eq $SiteDesign.Title }))
            {
                $toRuns += $SiteDesign
            }
        }
    }
    Write-Host "  Updating site designs"
    foreach($toRun in $toRuns)
    {
        Write-Host "    '$($toRun.Title)' v$($toRun.Version) $($toRun.Id)"
        if ($toRun.WebTemplate -eq 64)
        {
            if ($site.Template.StartsWith("SITEPAGEPUBLISHING#"))
            {
                Write-Host "      Running '$($toRun.Title)' on this site does not make sense!" -ForegroundColor Yellow
                continue
            }
        }
        if ($toRun.WebTemplate -eq 68)
        {
            if ($site.Template.StartsWith("GROUP#"))
            {
                Write-Host "      Running '$($toRun.Title)' on this site does not make sense!" -ForegroundColor Yellow
                continue
            }
        }
        Write-Host "      Invoking" -ForegroundColor Green
        Invoke-SPOSiteDesign -Identity $toRun.Id -WebUrl $site.Url
    }
}

#Stopping Transscript
Stop-Transcript
