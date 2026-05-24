#Requires -Version 7.0

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    25.03.2021 Konrad Brunner       Initial Version
    20.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules
    05.08.2023 Konrad Brunner       Added role admins and browser param
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Configures and deploys the Microsoft 365 Learning Pathways solution within a SharePoint Online environment.

.DESCRIPTION
This script automates the setup and configuration of the Microsoft 365 Learning Pathways site. It ensures necessary modules are installed, connects to SharePoint Online using PnP PowerShell, validates and configures hub sites, creates the learning pathways site if it does not exist, deploys the Learning Pathways app to the tenant app catalog and site, configures multilingual settings, permissions, and site designs, and establishes the correct homepage. It downloads the required PnP Learning Pathways app package and related configuration scripts from GitHub. Finally, it sets up start pages and launches the admin interface for manual configuration if required.

.PARAMETER siteLocale
Specifies the locale of the site to configure, e.g., "de-CH". Defaults to "de-CH".

.PARAMETER hubSitesConfigurationFile
Specifies the path to a custom hub site configuration file. If not provided, a default configuration file is used.

.PARAMETER seleniumBrowser
Provides an optional Selenium browser object to automate browser-based actions. If not supplied, a new browser instance may be created or a global instance reused.

.INPUTS
None. The script does not accept pipeline input.

.OUTPUTS
This script does not produce objects as output; it writes log entries and status messages to the console and transcript log file.

.EXAMPLE
PS> .\Configure-Microsoft365LearningPathways.ps1 -siteLocale "en-US" -hubSitesConfigurationFile "C:\Config\HubSites.ps1"

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$siteLocale = "de-CH",
    [Parameter(Mandatory=$false)]
    [string]$hubSitesConfigurationFile = $null,
    [Parameter(Mandatory=$false)]
    [object]$seleniumBrowser = $null
    )

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Configure-Microsoft365LearningPathways-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Logging in
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

# Constants
$learningPathwaysTitle = "M365LearningPathways"
if ($siteLocale -eq "de-CH")
{
    $learningPathwaysTitle = "M365LearningPathways"
}
$catalogTitle = "AppCatalog"
if ($siteLocale -eq "de-CH")
{
    $catalogTitle = "AppKatalog"
}

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


# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Configure-Microsoft365LearningPathways | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Configuring browser
if ($seleniumBrowser) {
    $browser = $seleniumBrowser
} else {
	if (-Not $browser)
	{
		if ($Global:AlyaSeleniumBrowser) {
			$browser = $Global:AlyaSeleniumBrowser
		} else {
			$browser = Get-SeleniumChromeBrowser
		}
	}
}

# Checking app catalog url
Write-Host "Checking app catalog url" -ForegroundColor $CommandInfo
$catalogSiteName = "$prefix-ADM-$catalogTitle"
$site = $null
$site = Get-PnPTenantSite -Connection $adminCon -Url "$($AlyaSharePointUrl)/sites/$catalogSiteName" -Detailed -ErrorAction SilentlyContinue
if (-Not $site)
{
    throw "App Catalog site collection not found!"
}
do {
    $appCatalogUrl = Get-PnPTenantAppCatalogUrl -Connection $adminCon -ErrorAction SilentlyContinue
    $appCatalogUrlApi = (Invoke-PnPSPRestMethod -Connection $adminCon -Method Get -Url "$($AlyaSharePointUrl)/_api/SP_TenantSettings_Current" -ErrorAction SilentlyContinue).CorporateCatalogUrl
    if ([string]::IsNullOrWhiteSpace($appCatalogUrl) -or [string]::IsNullOrWhiteSpace($appCatalogUrlApi) -or
        $appCatalogUrl -ne "$($AlyaSharePointUrl)/sites/$catalogSiteName" -or $appCatalogUrlApi -ne "$($AlyaSharePointUrl)/sites/$catalogSiteName")
    {
        Write-Warning "appCatalogUrl: $appCatalogUrl"
        Write-Warning "appCatalogUrlApi: $appCatalogUrlApi"
        Write-Warning "App Catalog URL not found or not correct!"
        Write-Warning "Please create app catalog site with the script Configure-AppCatalogSite.ps1 if not yet done."
        Write-Warning "If you have created the app catalog recently, it can take some time until the URL is available."
    }
    else
    {
        Write-Host "App Catalog URL is correct now."
        break
    }
    Read-Host "Press Enter to check again or Ctrl+C to stop waiting"
} while ($true)

# Checking ADM hub site
Write-Host "Checking ADM hub site" -ForegroundColor $CommandInfo
$hubSiteDef = $hubSites | Where-Object { $_.short -eq "ADM" }
$hubSiteName = $hubSiteDef.title
$admHubSite = Get-PnPHubSite -Connection $adminCon -Identity "$($AlyaSharePointUrl)/sites/$hubSiteName" -ErrorAction SilentlyContinue
if (-Not $admHubSite)
{
    Write-Error "ADM Hub site $hubSiteName not found. Please crate it first"
}
$hubCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$hubSiteName"

# Getting role groups
$siteCon = LoginTo-PnP -Url $AlyaSharePointUrl
$web = Get-PnPWeb -Connection $siteCon

$spAdminRoleName = "Company Administrator"
try {
    $gauser = $web.EnsureUser($spAdminRoleName)
    $gauser.Context.Load($gauser)
    Invoke-PnPQuery -Connection $siteCon
    $gauserLoginName = $gauser.LoginName
}
catch {
    $spAdminRoleName = "Global Administrator"
    try {
        $gauser = $web.EnsureUser($spAdminRoleName)
        $gauser.Context.Load($gauser)
        Invoke-PnPQuery -Connection $siteCon
        $gauserLoginName = $gauser.LoginName
    }
    catch {
        $gauserLoginName = $null
    }
}

$spAdminRoleName = "SharePoint Service Administrator"
try {
    $sauser = $web.EnsureUser($spAdminRoleName)
    $sauser.Context.Load($sauser)
    Invoke-PnPQuery -Connection $siteCon
    $sauserLoginName = $sauser.LoginName
}
catch {
    $spAdminRoleName = "SharePoint Administrator"
    try {
        $sauser = $web.EnsureUser($spAdminRoleName)
        $sauser.Context.Load($sauser)
        Invoke-PnPQuery -Connection $siteCon
        $sauserLoginName = $sauser.LoginName
    }
    catch {
        $sauserLoginName = $null
    }
}

# Checking learning pathways site collection
Write-Host "Checking learning pathways site collection" -ForegroundColor $CommandInfo
$learningPathwaysSiteName = "$prefix-ADM-$learningPathwaysTitle"
$site = $null
$site = Get-PnPTenantSite -Connection $adminCon -Url "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName" -Detailed -ErrorAction SilentlyContinue
if (-Not $site)
{
    Write-Warning "Learning pathways site not found. Creating now learning pathways site $learningPathwaysSiteName"
    $site = New-PnPSite -Connection $adminCon -Type "CommunicationSite" -Title $learningPathwaysSiteName -Url "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName" -Description "Microsoft 365 Learning Pathways" -Wait
    do {
        Start-Sleep -Seconds 15
        $site = Get-PnPTenantSite -Connection $adminCon -Url "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName" -Detailed -ErrorAction SilentlyContinue
    } while (-Not $site)
    Start-Sleep -Seconds 60

    # Login to learning pathways
    Write-Host "Login to learning pathways" -ForegroundColor $CommandInfo
	$siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName"

    # Adding site to hub
    Write-Host "Adding site to hub" -ForegroundColor $CommandInfo
    $hubSite = Get-PnPSite -Connection $hubCon
    $siteSite = Get-PnPSite -Connection $siteCon
    Add-PnPHubSiteAssociation -Connection $adminCon -Site $siteSite -HubSite $hubSite

    # Multilanguage settings
    $Web = Get-PnpWeb -Connection $siteCon -Includes Language, SupportedUILanguageIds
    $Web.IsMultilingual = $true
    foreach($id in @(1031,1033,1040,1036))
    {
        if ($id -ne $Web.Language -and $Web.SupportedUILanguageIds -notcontains $id)
        {
            $Web.AddSupportedUILanguage($id)
        }
    }
    $Web.Update()
    Invoke-PnPQuery -Connection $siteCon
    Enable-PnPFeature -Connection $siteCon -Identity "24611c05-ee19-45da-955f-6602264abaf8" -Force

    # Setting site design
    Write-Host "Setting site design" -ForegroundColor $CommandInfo
    if ($hubSiteDef.subSiteScript)
    {
        $SubSiteDesignNameComm = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSiteDef.short) SubSite Communication Site "+$siteLocale
        $siteDesign = Get-PnPSiteDesign -Connection $adminCon -Identity $SubSiteDesignNameComm
        Invoke-PnPSiteDesign -Connection $adminCon -Identity $siteDesign -WebUrl "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName"
    }
    else
    {
		$SiteDesignNameComm = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSiteDef.short) HubSite Communication Site "+$siteLocale
        $siteDesign = Get-PnPSiteDesign -Connection $adminCon -Identity $SiteDesignNameComm
        Invoke-PnPSiteDesign -Connection $adminCon -Identity $siteDesign -WebUrl "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName"
    }

    # Configuring access to learningPathways site
    Write-Host "Configuring access to learningPathways site" -ForegroundColor $CommandInfo
    $vgroup = Get-PnPGroup -Connection $siteCon -AssociatedVisitorGroup
    $agroup = Get-PnPMicrosoft365Group -Connection $adminCon -Identity $AlyaAllInternals
    Add-PnPGroupMember -Connection $siteCon -Group $vgroup -LoginName "c:0o.c|federateddirectoryclaimprovider|$($agroup.Id)"

    # Configuring permissions
    Write-Host "Configuring permissions" -ForegroundColor $CommandInfo
    $mgroup = Get-PnPGroup -Connection $siteCon -AssociatedMemberGroup
    $aRoles = Get-PnPRoleDefinition -Connection $siteCon
    $eRole = $aRoles | Where-Object { $_.RoleTypeKind -eq "Editor" }
    $cRole = $aRoles | Where-Object { $_.RoleTypeKind -eq "Contributor" }
    $perms = Get-PnPGroupPermissions -Connection $siteCon -Identity $mgroup
    if (-Not ($perms | Where-Object { $_.Id -eq $cRole.Id }))
    {
        Set-PnPGroupPermissions -Connection $siteCon -Identity $mgroup -AddRole $cRole.Name
    }
    if (($perms | Where-Object { $_.Id -eq $eRole.Id }))
    {
        Set-PnPGroupPermissions -Connection $siteCon -Identity $mgroup -RemoveRole $eRole.Name
    }

    # Configuring site logo
    Write-Host "Configuring site logo" -ForegroundColor $CommandInfo
    $web = Get-PnPWeb -Connection $siteCon -Includes SiteLogoUrl
    if ([string]::IsNullOrEmpty($web.SiteLogoUrl))
    {
        $web.SiteLogoUrl = $AlyaLogoUrlQuad
        $web.Update()
        Invoke-PnPQuery -Connection $siteCon
    }

    # Setting admin access
    Write-Host "Setting admin access" -ForegroundColor $CommandInfo
    $owners = @()
    if ($null -ne $sauserLoginName) { $owners += $sauserLoginName }
    foreach ($owner in $AlyaSharePointNewSiteCollectionAdmins)
    {
        if (-Not [string]::IsNullOrEmpty($owner) -and $owner -ne "PleaseSpecify")
        {
            $owners += $owner
        }
    }
    Set-PnPTenantSite -Connection $adminCon -Identity $site.Url -PrimarySiteCollectionAdmin $gauserLoginName -Owners $owners
}

# Checking app catalog
Write-Host "Checking app catalog" -ForegroundColor $CommandInfo
$appCatalogUrl = Get-PnPTenantAppCatalogUrl -Connection $adminCon
if (-Not $appCatalogUrl)
{
    $apiCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)"
    $res = Invoke-PnPSPRestMethod -Connection $apiCon -Method Get -Url "$($AlyaSharePointUrl)/_api/SP_TenantSettings_Current"
    $appCatalogUrl = $res.CorporateCatalogUrl
}
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
if (-Not (Test-Path "$AlyaTemp\LearningPathways"))
{
    New-Item -Path "$AlyaTemp\LearningPathways" -ItemType Directory -Force | Out-Null
}
Invoke-WebRequestIndep -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/customlearning.sppkg" -Method GET -OutFile "$AlyaTemp\LearningPathways\customlearning.sppkg"
Invoke-WebRequestIndep -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/M365lpConfiguration.ps1" -Method GET -OutFile "$AlyaTemp\LearningPathways\M365lpConfiguration.ps1"
Invoke-WebRequestIndep -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/TelemetryOptOut.ps1" -Method GET -OutFile "$AlyaTemp\LearningPathways\TelemetryOptOut.ps1"
Invoke-WebRequestIndep -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/UpdateM365lpCDN.ps1" -Method GET -OutFile "$AlyaTemp\LearningPathways\UpdateM365lpCDN.ps1"
Invoke-WebRequestIndep -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/UpdateM365lpSiteUrl.ps1" -Method GET -OutFile "$AlyaTemp\LearningPathways\UpdateM365lpSiteUrl.ps1"

# Login to app catalog
Write-Host "Login to app catalog" -ForegroundColor $CommandInfo
$appSiteCon = LoginTo-PnP -Url $appCatalogUrl

# Deploying app package
Write-Host "Deploying app package" -ForegroundColor $CommandInfo
$app = Add-PnPApp -Connection $appSiteCon -Path "$AlyaTemp\LearningPathways\customlearning.sppkg" -Scope "Tenant" -Overwrite -Publish
$appId = $app.Id
$retries = 20
$app = $null
do
{
    Start-Sleep -Seconds 10
    try
    {
        $app = Get-PnPApp -Connection $appSiteCon -Scope "Tenant" | Where-Object { $_.Id -eq $appId }
    } catch {}
    $retries--
    if ($retries -lt 0) { break }
} while (-Not $app -or -Not $app.Deployed)
if (-Not $app -or -Not $app.Deployed)
{
    throw "App package is not deployed!"
}

# Login to learning pathways
Write-Host "Login to learning pathways" -ForegroundColor $CommandInfo
$siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName"

# Installing app package on site
Write-Host "Installing app package on site" -ForegroundColor $CommandInfo
$retries = 20
$hasInstalled = $false
do
{
    $sapp = Get-PnPApp -Connection $siteCon | Where-Object { $_.Title -eq "Microsoft 365 learning pathways" }
    if (-Not $sapp.InstalledVersion -And -Not $hasInstalled)
    {
        Install-PnPApp -Connection $siteCon -Identity $appId -Scope "Tenant" -Wait
        $hasInstalled = $true
    }
    else
    {
        Start-Sleep -Seconds 10
    }
    $retries--
    if ($retries -lt 0) { break }
} while (-Not $sapp.InstalledVersion)
if (-Not $sapp.InstalledVersion)
{
    throw "Not able to deploy app package on site!"
}
$sapp = Get-PnPApp -Connection $siteCon | Where-Object { $_.Title -eq "Microsoft 365 learning pathways" }
if ($sapp.AppCatalogVersion -ne $sapp.InstalledVersion)
{
    Update-PnPApp -Connection $siteCon -Identity $appId -Scope "Tenant"
}

#Configuring learning setting
Write-Host "Configuring learning setting" -ForegroundColor $CommandInfo
$siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName"

#Remove-PnPStorageEntity -Connection $siteCon -Key MicrosoftCustomLearningTelemetryOn
Set-PnPStorageEntity -Connection $siteCon -Key MicrosoftCustomLearningTelemetryOn -Value $false -Description "Microsoft 365 learning pathways Telemetry Setting"
$retry = 10
do
{
    try
    {
        Start-Sleep -Seconds 10
        Set-PnPStorageEntity -Connection $siteCon -Key MicrosoftCustomLearningTelemetryOn -Value $false -Description "Microsoft 365 learning pathways Telemetry Setting" -ErrorAction Stop
        Get-PnPStorageEntity -Connection $siteCon -Key MicrosoftCustomLearningTelemetryOn
        Set-PnPStorageEntity -Connection $siteCon -Key MicrosoftCustomLearningCdn -Value "https://pnp.github.io/custom-learning-office-365/learningpathways/" -Description "Microsoft 365 learning pathways CDN source" -ErrorAction Stop
        Get-PnPStorageEntity -Connection $siteCon -Key MicrosoftCustomLearningCdn
        Set-PnPStorageEntity -Connection $siteCon -Key MicrosoftCustomLearningSite -Value "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName" -Description "Microsoft 365 learning pathways Site Collection" -ErrorAction Stop
        Get-PnPStorageEntity -Connection $siteCon -Key MicrosoftCustomLearningSite
        break
    }
    catch{
        $retry--
        if ($retry -lt 0)
        {
            throw $_.Exception
        }
    }
} while ($true)

# Denying site scripts
Write-Host "Denying site scripts" -ForegroundColor $CommandInfo
Set-PnPSite -Connection $siteCon -NoScriptSite $true

#Configuring start page
Write-Host "Configuring start page" -ForegroundColor $CommandInfo
$sitePagesList = Get-PnPList -Connection $siteCon -Identity "SitePages" -ErrorAction SilentlyContinue
if($null -eq $sitePagesList) {    
    $sitePagesList = Get-PnPList -Connection $siteCon -Identity "Websiteseiten" -ErrorAction SilentlyContinue
}
if($null -ne $sitePagesList) {    
    $clv = Get-PnPListItem -Connection $siteCon -List $sitePagesList -Query "<View><Query><Where><Eq><FieldRef Name='FileLeafRef'/><Value Type='Text'>CustomLearningViewer.aspx</Value></Eq></Where></Query></View>"
    if ($null -ne $clv) {
        Write-Host "Found an existing CustomLearningViewer.aspx page. Deleting it."
        Set-PnPListItem -Connection $siteCon -List $sitePagesList -Identity $clv.Id -Values @{"FileLeafRef" = "CustomLearningViewer$((Get-Date).Minute)$((Get-date).second).aspx" }
        Move-PnPListItemToRecycleBin -Connection $siteCon -List $sitePagesList -Identity $clv.Id -Force
    }
    $clvPage = Add-PnPPage -Connection $siteCon -Name "CustomLearningViewer"
    $clvSection = Add-PnPPageSection -Connection $siteCon -Page $clvPage -SectionTemplate OneColumn -Order 1
    $timeout = New-TimeSpan -Minutes 3 # wait for 3 minutes then time out
    $stopwatch = [diagnostics.stopwatch]::StartNew()
    Write-Host "." -NoNewline
    $WebPartsFound = $false
    while ($stopwatch.elapsed -lt $timeout) {
        $comps = Get-PnPPageComponent -Connection $siteCon -page CustomLearningViewer.aspx -ListAvailable
        if ($comps | Where-Object { $_.Name -eq "Microsoft 365 learning pathways administration"} ) {
            Write-Host "Microsoft 365 learning pathways web parts found"
            $WebPartsFound = $true
            break
        }
        Write-Host "." -NoNewline
    }
    if ($WebPartsFound -eq $false) {
        Write-Warning "Could not find Microsoft 365 learning pathways Web Parts."
        Write-Warning "Please verify the Microsoft 365 learning pathways Package is installed and run this installation script again."
        break 
    }
    Add-PnPPageWebPart -Connection $siteCon -Page $clvPage -Component "Microsoft 365 learning pathways"
    $clv = Get-PnPListItem -Connection $siteCon -List $sitePagesList -Query "<View><Query><Where><Eq><FieldRef Name='FileLeafRef'/><Value Type='Text'>CustomLearningViewer.aspx</Value></Eq></Where></Query></View>"
    $clv["PageLayoutType"] = "SingleWebPartAppPage"
    $clv.Update()
    $clv.File.Publish("Updated by Alya cloud configuration")
    Invoke-PnPQuery -Connection $siteCon

    $cla = Get-PnPListItem -Connection $siteCon -List $sitePagesList -Query "<View><Query><Where><Eq><FieldRef Name='FileLeafRef'/><Value Type='Text'>CustomLearningAdmin.aspx</Value></Eq></Where></Query></View>"
    if ($null -ne $cla) {
        Write-Host "Found an existing CustomLearningAdmin.aspx page. Deleting it."
        Set-PnPListItem -Connection $siteCon -List $sitePagesList -Identity $cla.Id -Values @{"FileLeafRef" = "CustomLearningAdmin$((Get-Date).Minute)$((Get-date).second).aspx" }
        Move-PnPListItemToRecycleBin -Connection $siteCon -List $sitePagesList -Identity $cla.Id -Force    
    }
    $claPage = Add-PnPPage -Connection $siteCon "CustomLearningAdmin" -Publish
    $claSection = Add-PnPPageSection -Connection $siteCon -Page $claPage -SectionTemplate OneColumn -Order 1
    Add-PnPPageWebPart -Connection $siteCon -Page $claPage -Component "Microsoft 365 learning pathways administration"
    $cla = Get-PnPListItem -Connection $siteCon -List $sitePagesList -Query "<View><Query><Where><Eq><FieldRef Name='FileLeafRef'/><Value Type='Text'>CustomLearningAdmin.aspx</Value></Eq></Where></Query></View>"
    $cla["PageLayoutType"] = "SingleWebPartAppPage"
    $cla.Update()
    $cla.File.Publish("Updated by Alya cloud configuration")
    Invoke-PnPQuery -Connection $siteCon

}
else { 
    Write-Warning "Could not find `"Site Pages`" library. Please make sure you are running this on a Modern SharePoint site"
    return
}

# Setting homepage
Write-Host "Setting homepage" -ForegroundColor $CommandInfo
$siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName"
Set-PnPHomePage -Connection $siteCon -RootFolderRelativeUrl "SitePages/CustomLearningViewer.aspx"

# Launching custom configuration
Write-Host "Launching custom configuration" -ForegroundColor $CommandInfo
Write-Host "  $($AlyaSharePointUrl)/sites/$learningPathwaysSiteName/SitePages/CustomLearningAdmin.aspx"
if (-Not $browser) {
    Start-Process "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName/SitePages/CustomLearningAdmin.aspx"
} else {
    $browser.Url =  "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName/SitePages/CustomLearningAdmin.aspx"
}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDuyFMjr9q0BhzQ
# s10V+TPGVKiRBTPqT7FEI9cSLvEfo6CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFhEPR0E
# 5tneuxelEBC6yE4aVQyRdWDXPllbIg7Yij70MA0GCSqGSIb3DQEBAQUABIICABqj
# K6nlVKMJIxHFR1SgZG6dBKFwfS3backdymmRgECUApk2nOrckcrmpQVQa74qSKwL
# FIpT9sjA4EjwfMkx0+c55r74BfUiw2OiIPSSFVG6CUFHaB6zJM5zblZq/+XUBmmk
# Sc1jhqcr46pJ0TA4RlGIOUzMunmtsolVAUvGEUdhhVggmhu3i9tXrLBunb0uXBpj
# DnVjfq+ls8g7DOcRrvMLnd8ns3sL0t3eAGqCuj9o9uRDlPUlGdUruWkNqEJ6fhYa
# chtmU9AUxD5l0B4EZ91KyHJPXCaUy/jc7oZJ/onwNMFeOZJwz6IX/TzwQWDbrWlZ
# ObjyeVqbd5srG2R4YQicTgIIwult8apKSISvbzjL0CDjI5OD+PEk3Trkme2qZwgA
# BaYzVa37QqfnW4vglgH4jHNz6b4E36r5hzNqrl8ndvPrEwXX3kYy6YAFWpqviL6j
# LYl9gQ/3tAxjmCDnmEMcJFaf1WDJ+UYfrhqvUXav+KYsboaWcPnpgSpeHfc8sMm2
# WD9j6cwfyuoglDG305dhjYZFIDrfLYY0A7VBv87aG7KtXLfRKJPAXuVEZ7l0jqeE
# DJ5sn3HdK28XXu+chKdV2xKKLBUS0j4fuipLh8GxAwRlvTXIdmmLYInL2no+i3Pa
# yAGrHqkclGWhZEDyNws7Z10V+FDa2JqGqx4nZNRNoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCADqHSZyB3jFemECNre/iWg0UxI1GsqLaWdfFRrxEzdzAIUeMg7
# YO1zatmtJZ5ZgcYPKsve21oYDzIwMjYwNTE1MTEwMjU4WjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDB4P5ZwaPI/i+PIGJC/IDzcYtLDRbX5ImMG9RqQtGzEpAyW+lQMMiDYzI7o
# 122ZI/kwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAaJDsrArKFYlUc/DGyvOmsf4184ewkCLhhKnbIafF+m24
# uK43Jn1mPni6MFB6z7fmY+ud4QMOPSiOgrP/My+gwC22GKHsV++uP6fLb0goGEky
# NGRwi8TaOi3Qb5SENAuEIhwBs6spN/Q0eeVrIWl2SpClQ65T/5jq25U6CS9Ma1C3
# kMrytmlualHjJbP34SnJ+JYGn5gaVXgs1KDlUpUV8FBC9qKoba8p5N6QWskciM6s
# UrRNG7oZVEMa00tRSgggrTrogq7w1n9IgBdoyHMz/CNvsMXQAXvjkBkKXcv9hMcV
# IT/Pr3VeF5tEtFDzrvNfP1TqtYgS9MFoGJT78P/BYk9QVLcNGbdD/Wp4QcmQ6V06
# USChho+0YPgescLTlE8ZebSY+QIM3STJIGG79oWCK83uqXvDdWAkeOhEoewUosai
# 8MbgTvNJZMZAEQWF+cun54dKkLxd2PgAhXSPTtjoxbMSCf4TKPg5qd9300GH/dvZ
# PEiKP2uW21YxXzN1gH6b
# SIG # End signature block
