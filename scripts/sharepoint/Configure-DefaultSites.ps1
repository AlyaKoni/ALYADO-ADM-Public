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
    25.03.2023 Konrad Brunner       Initial Version
    20.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules

#>

[CmdletBinding()]
Param(
    [string]$siteLocale = "de-CH",
    [bool]$overwritePages = $true,
    [string]$hubSitesConfigurationFile = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Configure-DefaultSites-$($AlyaTimeString).log" | Out-Null

# Constants
if ($hubSitesConfigurationFile)
{
    if ((Test-Path $hubSitesConfigurationFile))
    {
        Write-Host "Using hub site configuration from: $($hubSitesConfigurationFile)"
    }
    else
    {
        throw "Provided hub site configuration file $($hubSitesConfigurationFile) not found!"
    }
}
else
{
    if ((Test-Path "$AlyaData\sharepoint\HubSitesConfiguration-$($siteLocale).ps1"))
    {
        Write-Host "Using hub site configuration from: $($AlyaData)\sharepoint\HubSitesConfiguration-$($siteLocale).ps1"
        $hubSitesConfigurationFile = "$AlyaData\sharepoint\HubSitesConfiguration-$siteLocale.ps1"
    }
    else
    {
        Write-Host "Using hub site configuration from: $($PSScriptRoot)\HubSitesConfigurationTemplate-$($siteLocale).ps1"
        Write-Warning "We suggest to copy the HubSitesConfigurationTemplate-$($siteLocale).ps1 to your data\sharepoint directory"
        pause
        $hubSitesConfigurationFile = "$AlyaScripts\sharepoint\HubSitesConfigurationTemplate-$siteLocale.ps1"
    }
}
. $hubSitesConfigurationFile

$siteStrcuture = @(
    @{
        Hub = "ADM"
        Title = "$($AlyaCompanyNameShortM365)SP-ADM-Daten"
        ExtSharing = $false
        Description = "Interne Dateiablage"
        Type = "TeamSite"
        Template = $homePageTemplateDocumentSiteADM
        Logo = $AlyaLogoUrlQuad
        HeaderLayout = "Compact"
        HeaderEmphasis = "None"
        QuickLaunchEnabled = $false
    },
    @{
        Hub = "COL"
        Title = "$($AlyaCompanyNameShortM365)SP-COL-Oeffentlich"
        ExtSharing = $true
        Description = "Öffentliche Dateiablage"
        Type = "TeamSite"
        Template = $homePageTemplateDocumentSiteCOL
        Logo = $AlyaLogoUrlQuad
        HeaderLayout = "Compact"
        HeaderEmphasis = "None"
        QuickLaunchEnabled = $false
    }
)

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Configure-DefaultSites | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

foreach($siteDef in $siteStrcuture)
{
    $extSharing = $AlyaSharingPolicy
    if ($siteDef.ExtSharing -eq $false) { $extSharing = "None" }

    & "$($AlyaScripts)\sharepoint\Create-Site.ps1" `
        -title $siteDef.Title `
        -description $siteDef.Description `
        -hub $siteDef.Hub `
        -siteDesignName $null `
        -siteTemplate $siteDef.Type `
        -siteLocale $siteLocale `
        -externalSharing $extSharing `
        -homePageTemplate $siteDef.Template `
        -siteLogoUrl $siteDef.Logo `
        -overwritePages $overwritePages `
        -hubSitesConfigurationFile $hubSitesConfigurationFile `
        -siteOwners $AlyaSharePointNewSiteCollectionAdmins `
        -headerLayout $siteDef.HeaderLayout `
        -headerEmphasis $siteDef.HeaderEmphasis `
        -quickLaunchEnabled $siteDef.QuickLaunchEnabled
}

#Stopping Transscript
Stop-Transcript
