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
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Configure-Microsoft365LearningPathways-$($AlyaTimeString).log" | Out-Null

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
    $learningPathwaysTitle = "LearningPathways"
}
else
{
    $learningPathwaysTitle = "LearningPathways"
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
Write-Host "SharePoint | Configure-Microsoft365LearningPathways | O365" -ForegroundColor $CommandInfo
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

# Checking learning pathways site collection
Write-Host "Checking learning pathways site collection" -ForegroundColor $CommandInfo
$learningPathwaysSiteName = "$prefix-ADM-$learningPathwaysTitle"
$site = $null
try { $site = Get-SPOSite -Identity "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName" -Detailed -ErrorAction SilentlyContinue } catch {}
if (-Not $site)
{
    Write-Warning "Learning pathways site not found. Creating now learning pathways site $learningPathwaysSiteName"
    LoginTo-PnP -Url $AlyaSharePointAdminUrl
    $site = New-PnPSite -Type "CommunicationSite" -Title $learningPathwaysSiteName -Url "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName" -Description "Learning Pathways" -Wait
    do {
        Start-Sleep -Seconds 15
        $site = Get-SPOSite -Identity "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName" -Detailed
    } while (-Not $site)

    # Adding site to hub
    Write-Host "Adding site to hub" -ForegroundColor $CommandInfo
    Add-SPOHubSiteAssociation -Site $site -HubSite $admHubSite

    # Login to learning pathways
    Write-Host "Login to learning pathways" -ForegroundColor $CommandInfo
    LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName"

    # Setting site design
    Write-Host "Setting site design" -ForegroundColor $CommandInfo
    if ($hubSiteDef.subSiteScript)
    {
        $SubSiteDesignNameTeam = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) SubSite Team Site "+$siteLocale
        $SubSiteDesignTeam = Get-SPOSiteDesign | where { $_.Title -eq "$SubSiteDesignNameTeam"}
        if (-Not $SubSiteDesignTeam)
        {
            Write-Error "Site design $SubSiteDesignNameTeam not found. Please crate it first"
        }
        Invoke-SPOSiteDesign -Identity $SubSiteDesignTeam.Id -WebUrl "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName"
    }
    else
    {
		$SiteDesignNameTeam = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) HubSite Team Site "+$siteLocale
        $SiteDesignTeam = Get-SPOSiteDesign | where { $_.Title -eq "$SiteDesignNameTeam"}
        if (-Not $SiteDesignTeam)
        {
            Write-Error "Site design $SiteDesignNameTeam not found. Please crate it first"
        }
        Invoke-SPOSiteDesign -Identity $SiteDesignTeam.Id -WebUrl "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName"
    }

    # Configuring access to learningPathways site
    Write-Host "Configuring access to learningPathways site" -ForegroundColor $CommandInfo
    $vgroup = Get-PnPGroup -AssociatedVisitorGroup
    Add-SPOUser -Site $site -Group $vgroup.Title -LoginName "$AlyaAllInternals@$AlyaDomainName"

    # Configuring permissions
    Write-Host "Configuring permissions" -ForegroundColor $CommandInfo
    $aRoles = Get-PnPRoleDefinition
    $eRole = $aRoles | where { $_.RoleTypeKind -eq "Editor" }
    $cRole = $aRoles | where { $_.RoleTypeKind -eq "Contributor" }
    $temp = Set-SPOSiteGroup -Site $site -Identity $mgroup.Title -PermissionLevelsToAdd $cRole.Name -PermissionLevelsToRemove $eRole.Name

    # Configuring site theme
    Write-Host "Configuring site theme" -ForegroundColor $CommandInfo
    $web = Get-PnPWeb -Includes HeaderEmphasis,HeaderLayout,SiteLogoUrl,QuickLaunchEnabled
    $web.HeaderLayout = $hubSite.headerLayout
    $web.HeaderEmphasis = $hubSite.headerEmphasis
    $web.QuickLaunchEnabled = $false
    $web.Update()
    Invoke-PnPQuery
    if ([string]::IsNullOrEmpty($web.SiteLogoUrl))
    {
        $fname = Split-Path -Path $hubSite.siteLogoUrl -Leaf
        $tempFile = [System.IO.Path]::GetTempFileName()+$fname
        Invoke-RestMethod -Method GET -UseBasicParsing -Uri $hubSite.siteLogoUrl -OutFile $tempFile
        Set-PnPSite -LogoFilePath $tempFile
        Remove-Item -Path $tempFile
    }
    try { Disconnect-PnPOnline -ErrorAction SilentlyContinue } catch {}

}

# Checking app catalog
Write-Host "Checking app catalog" -ForegroundColor $CommandInfo
LoginTo-PnP -Url $AlyaSharePointAdminUrl
$appCatalogUrl = Get-PnPTenantAppCatalogUrl
if (-Not $appCatalogUrl)
{
    throw "There is no app catalog site registered! Please create it with the script Configure-AppCatalogSite.ps1"
}

# Downloading app package
Write-Host "Downloading app package" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$AlyaTemp"))
{
    New-Item -Path "$AlyaTemp" -ItemType Directory -Force | Out-Null
}
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/customlearning.sppkg" -Method GET -OutFile "$AlyaTemp\customlearning.sppkg"
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/M365lpConfiguration.ps1" -Method GET -OutFile "$AlyaTemp\M365lpConfiguration.ps1"
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/TelemetryOptOut.ps1" -Method GET -OutFile "$AlyaTemp\TelemetryOptOut.ps1"
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/UpdateM365lpCDN.ps1" -Method GET -OutFile "$AlyaTemp\UpdateM365lpCDN.ps1"
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/UpdateM365lpSiteUrl.ps1" -Method GET -OutFile "$AlyaTemp\UpdateM365lpSiteUrl.ps1"

# Login to app catalog
Write-Host "Login to app catalog" -ForegroundColor $CommandInfo
LoginTo-PnP -Url $appCatalogUrl

# Deploying app package
Write-Host "Deploying app package" -ForegroundColor $CommandInfo
$app = Add-PnPApp -Path "$AlyaTemp\customlearning.sppkg" -Scope Tenant -Overwrite -Publish
$app = Get-PnPApp -Identity $app.Id -Scope "Tenant"
if (-Not $app.Deployed)
{
    throw "Error deploying the app package"
}

# Login to learning pathways
Write-Host "Login to learning pathways" -ForegroundColor $CommandInfo
LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName"

# Installing app package
Write-Host "Installing app package" -ForegroundColor $CommandInfo
Install-PnPApp -Identity $app.Id -Scope "Tenant"

#
# TODO Some modules needs to be unloaded to make next script working!
#

# Running M365lpConfiguration.ps1
Write-Host "Running M365lpConfiguration.ps1" -ForegroundColor $CommandInfo
& "$AlyaTemp\M365lpConfiguration.ps1" -TenantName $AlyaTenantNameId -SiteCollectionName $learningPathwaysSiteName

# Running TelemetryOptOut.ps1
Write-Host "Running TelemetryOptOut.ps1" -ForegroundColor $CommandInfo
& "$AlyaTemp\TelemetryOptOut.ps1" -TenantName $AlyaTenantNameId -SiteCollectionName $learningPathwaysSiteName

# Setting homepage
Write-Host "Setting homepage" -ForegroundColor $CommandInfo
LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName"
Set-PnPHomePage -RootFolderRelativeUrl "SitePages/CustomLearningViewer.aspx"

# Launching custom configuration
Write-Host "Launching custom configuration" -ForegroundColor $CommandInfo
start "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName/SitePages/CustomLearningAdmin.aspx"

#Stopping Transscript
Stop-Transcript