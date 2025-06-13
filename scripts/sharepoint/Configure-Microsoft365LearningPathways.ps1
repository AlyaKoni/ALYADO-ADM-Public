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
    25.03.2021 Konrad Brunner       Initial Version
    20.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules
    05.08.2023 Konrad Brunner       Added role admins and browser param

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
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDcIcDiypH9W07/
# kw5gixC1CYfeoX4X1tC1b+dPUvxdOKCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIK/mPHNSDoHF8wYJ
# 9xoT+B7dG69/fFop7GRZnOS+mcVMMA0GCSqGSIb3DQEBAQUABIICAHiJPuZD4baC
# ZQqpDDRU9rPHNnNx+0imoFdxZXxU5kstYpKl98GLzjk9OPBNr/cECq0VwwiQYtfI
# J3Guribbe4JcpJpo2cmx4K6XFMiYNo6+Rg791tNXFe+LijseW3ttlesN8x9RYF/T
# LqIRdyE7th7Tll4vCN8f3UNC9NZ13QQVqJdxdqqVcthDyKXsmCEez1RvAtGoVjjh
# ZaQpN0WXAZXonCh99GARJpONJvBpA4UIxxw1YxueIzNfMw8zPyCVjwYiPGBYrvvm
# K69x+gxMAGtgif40n0Qjag5pU54qWztpS0DRWEycCbsd0ncBC3bvpaz0szffNXr8
# BautEUKfuLku853qGkMZsfDr8PZZJZCI7m91O/tcG3OkTRer/whBnL1KP0rbhmMj
# IOlFmyaCL+79MG3ONDIP6kFanOI2wfWxp0aTedtDGae/hUcrY31im+dVWI5jVkej
# tTPCZMjdF1Jk1e7+Pptg6smy69tLVb5fOJAbYxM7q64L8htT8eh0NJ7+e9q/ux5D
# 50lTTKRksXoJuCOkSah03GIdcaqJPRFr5Xha6VeR8e1njNnWka4a1PrEdC/G5u8l
# EkdB6JJG3so8N81j5nAa7yfTGdyn4CfAfNBZne7S/NsP6BOT42P4+lrLIyDQvWzA
# YU0yb9x2QV/N9I7Zs80ezVOsFTghAI2VoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCBm7pGA4pKEpLzHMCZ8YI3vL6vb43qEOfJhPr6QxBGUowIUCwtEIBEF0ulo
# l2KhRyBHIHyhkpMYDzIwMjUwNTI2MTkyMzU1WjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
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
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# IFAiwZfhK8LYM/cJ99MBtUVVCkPOb/atD4lrNHdxkAO0MIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAI2n15Tlfji2L
# RT0Gw+/Wv27vCTX0s1dXLfltr3HS7vDWYYJR0lPLfZcXLPXtQ2TK0B41t/eSOWW9
# 72q7ZYpvOFfcaxXrgfxoqOoU9KouMIrvsZbqSAQMJk4qLrI4Df1yYO3E3u3qpo9k
# tsZ//96PgErS11+jXIRLTCDw3PhuhkW91+9lk7t3vXn9EcuyLAhDd43SKpsGmAad
# bg09NuVL4uDhAt1ytLcEd6uU4HkdVdxkgK9toGT01X917Fct3k7m9hPowfv9zkqg
# mIjZxgjiOzg1s9Z40DEFH3C9Ioed1vAsqFtB/lI81b7SEm+rhlSPiS3npTZHJzns
# 1tp9ZrroSPwXmdz3COLN/6mgmbEQZVDSmnEriWz6mM9srTq6cal/VO/vliEz7dQq
# 4NqcIdLLF+lVpCtnNE1HosI4aaDp+w73okjjPnkKFJpBJg1ujIR+ANn72Frzxy2u
# 9FZ7iCCo0+jtCWD57xT77+L/3JR+0cNMLYNQl7NJqWz/tdMjOb4b
# SIG # End signature block
