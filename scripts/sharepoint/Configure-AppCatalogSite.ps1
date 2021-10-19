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
    25.03.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    $siteLocale = "de-CH"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Configure-AppCatalogSite-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "AzureAdPreview"
Install-ModuleIfNotInstalled "Microsoft.Online.Sharepoint.PowerShell"
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Logging in
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad
LoginTo-SPO

# Constants
if ($siteLocale -eq "de-CH")
{
    $catalogTitle = "AppKatalog"
}
else
{
    $catalogTitle = "AppCatalog"
}

if ((Test-Path "$AlyaData\sharepoint\HubSitesConfiguration-$($siteLocale).ps1"))
{
    Write-Host "Using hub site configuration from: $($AlyaData)\sharepoint\HubSitesConfiguration-$($siteLocale).ps1"
    . $AlyaData\sharepoint\HubSitesConfiguration-$siteLocale.ps1
}
else
{
    Write-Host "Using hub site configuration from: $($PSScriptRoot)\HubSitesConfigurationTemplate-$($siteLocale).ps1"
    Write-Warning "We suggest to copy the HubSitesConfigurationTemplate-$($siteLocale).ps1 to your data\sharepoint directory"
    pause
    . $PSScriptRoot\HubSitesConfigurationTemplate-$siteLocale.ps1
}

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Configure-AppCatalogSite | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking ADM hub site
Write-Host "Checking ADM hub site" -ForegroundColor $CommandInfo
$hubSiteDef = $hubSites | where { $_.short -eq "ADM" }
$hubSiteName = $hubSiteDef.title
$admHubSite = $null
try { $admHubSite = Get-SPOSite -Identity "$($AlyaSharePointUrl)/sites/$hubSiteName" -Detailed -ErrorAction SilentlyContinue } catch {}
if (-Not $admHubSite)
{
    Write-Error "ADM Hub site $hubSiteName not found. Please crate it first"
}

# Checking app catalog site collection
Write-Host "Checking app catalog site collection" -ForegroundColor $CommandInfo
$catalogSiteName = "$prefix-ADM-$catalogTitle"
$site = $null
try { $site = Get-SPOSite -Identity "$($AlyaSharePointUrl)/sites/$catalogSiteName" -Detailed -ErrorAction SilentlyContinue } catch {}
if (-Not $site)
{
    Write-Warning "Checking existance of other App Catalog site"
    LoginTo-PnP -Url $AlyaSharePointAdminUrl
    $appCatalogUrl = Get-PnPTenantAppCatalogUrl
    if ($appCatalogUrl -and -not $appCatalogUrl.EndsWith($catalogSiteName))
    {
        throw "There is already an app catalog with different title registered!"
    }

    Write-Warning "App Catalog site not found. Creating now app catalog site $catalogSiteName"
    Register-PnPAppCatalogSite -Url "$($AlyaSharePointUrl)/sites/$catalogSiteName" -Owner $AlyaSharePointNewSiteOwner -TimeZoneId 4 -Force

    do {
        Start-Sleep -Seconds 15
        $site = Get-SPOSite -Identity "$($AlyaSharePointUrl)/sites/$catalogSiteName" -Detailed
    } while (-Not $site)

    # Adding site to hub
    Write-Host "Adding site to hub" -ForegroundColor $CommandInfo
    Add-SPOHubSiteAssociation -Site $site -HubSite $admHubSite

    # Login to app catalog
    Write-Host "Login to app catalog" -ForegroundColor $CommandInfo
    LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$catalogSiteName"

    # Setting site design
    <#

    Getting error: Die Website lässt keine Websitedesigns zu

    Write-Host "Setting site design" -ForegroundColor $CommandInfo
    if ($hubSiteDef.subSiteScript)
    {
        $SubSiteDesignNameTeam = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSiteDef.short) SubSite Team Site "+$siteLocale
        $SubSiteDesignTeam = Get-SPOSiteDesign | where { $_.Title -eq "$SubSiteDesignNameTeam"}
        if (-Not $SubSiteDesignTeam)
        {
            Write-Error "Site design $SubSiteDesignNameTeam not found. Please crate it first"
        }
        Invoke-SPOSiteDesign -Identity $SubSiteDesignTeam.Id -WebUrl "$($AlyaSharePointUrl)/sites/$catalogSiteName"
    }
    else
    {
		$SiteDesignNameTeam = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSiteDef.short) HubSite Team Site "+$siteLocale
        $SiteDesignTeam = Get-SPOSiteDesign | where { $_.Title -eq "$SiteDesignNameTeam"}
        if (-Not $SiteDesignTeam)
        {
            Write-Error "Site design $SiteDesignNameTeam not found. Please crate it first"
        }
        Invoke-SPOSiteDesign -Identity $SiteDesignTeam.Id -WebUrl "$($AlyaSharePointUrl)/sites/$catalogSiteName"
    }
    #>

    # Configuring access to catalog site for internals
    Write-Host "Configuring access to catalog site" -ForegroundColor $CommandInfo
    $mgroup = Get-PnPGroup -AssociatedMemberGroup
    Add-SPOUser -Site $site -Group $mgroup.Title -LoginName "$AlyaAllInternals@$AlyaDomainName"

    # Configuring permissions
    Write-Host "Configuring permissions" -ForegroundColor $CommandInfo
    $aRoles = Get-PnPRoleDefinition
    $eRole = $aRoles | where { $_.RoleTypeKind -eq "Editor" }
    $cRole = $aRoles | where { $_.RoleTypeKind -eq "Contributor" }
    $temp = Set-SPOSiteGroup -Site $site -Identity $mgroup.Title -PermissionLevelsToAdd $cRole.Name -PermissionLevelsToRemove $eRole.Name

    # Configuring access to catalog site
    Write-Host "Configuring access to catalog site" -ForegroundColor $CommandInfo
    $mgroup = Get-PnPGroup -AssociatedVisitorGroup
    Add-SPOUser -Site $site -Group $mgroup.Title -LoginName "$AlyaAllExternals@$AlyaDomainName"

    # Configuring site logo
    Write-Host "Configuring site logo" -ForegroundColor $CommandInfo
    $web = Get-PnPWeb -Includes SiteLogoUrl
    if ([string]::IsNullOrEmpty($web.SiteLogoUrl))
    {
        $fname = Split-Path -Path $AlyaLogoUrlQuad -Leaf
        $tempFile = [System.IO.Path]::GetTempFileName()+$fname
        Invoke-RestMethod -Method GET -UseBasicParsing -Uri $AlyaLogoUrlQuad -OutFile $tempFile
        Set-PnPSite -LogoFilePath $tempFile
        Remove-Item -Path $tempFile
    }

}

#TODO Logo

#Stopping Transscript
Stop-Transcript