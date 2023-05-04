#Requires -Version 7.0

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

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    25.03.2021 Konrad Brunner       Initial Version
    20.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules

#>

[CmdletBinding()]
Param(
    [string]$siteLocale = "de-CH",
    [string]$hubSitesConfigurationFile = $null
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
if ($siteLocale -eq "de-CH")
{
    $learningPathwaysTitle = "M365LearningPathways"
}
else
{
    $learningPathwaysTitle = "M365LearningPathways"
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
    Add-PnPGroupMember -Connection $siteCon -Group $vgroup -EmailAddress "$AlyaAllInternals@$AlyaDomainName" -SendEmail:$false

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
    Set-PnPTenantSite -Connection $adminCon -Identity "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName" -Owners $AlyaSharePointNewSiteCollectionAdmins
    Set-PnPTenantSite -Connection $adminCon -Identity "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName" -PrimarySiteCollectionAdmin $AlyaSharePointNewSiteOwner
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
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/customlearning.sppkg" -Method GET -OutFile "$AlyaTemp\LearningPathways\customlearning.sppkg"
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/M365lpConfiguration.ps1" -Method GET -OutFile "$AlyaTemp\LearningPathways\M365lpConfiguration.ps1"
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/TelemetryOptOut.ps1" -Method GET -OutFile "$AlyaTemp\LearningPathways\TelemetryOptOut.ps1"
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/UpdateM365lpCDN.ps1" -Method GET -OutFile "$AlyaTemp\LearningPathways\UpdateM365lpCDN.ps1"
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/pnp/custom-learning-office-365/raw/main/installation/UpdateM365lpSiteUrl.ps1" -Method GET -OutFile "$AlyaTemp\LearningPathways\UpdateM365lpSiteUrl.ps1"

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
Start-Process "$($AlyaSharePointUrl)/sites/$learningPathwaysSiteName/SitePages/CustomLearningAdmin.aspx"

#Stopping Transscript
Stop-Transcript
