#Requires -Version 7.0

<#
    Copyright (c) Alya Consulting, 2019-2023

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
    07.07.2022 Konrad Brunner       New PnP Login and some fixes
    20.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules
    05.08.2023 Konrad Brunner       Added role admins, changed internal access to visitors

#>

[CmdletBinding()]
Param(
    [string]$siteLocale = "de-CH",
    [string]$hubSitesConfigurationFile = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Configure-AppCatalogSite-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Logging in
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

# Constants
if ($siteLocale -eq "de-CH")
{
    $catalogTitle = "AppKatalog"
}
else
{
    $catalogTitle = "AppCatalog"
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
Write-Host "SharePoint | Configure-AppCatalogSite | O365" -ForegroundColor $CommandInfo
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

# Getting role groups
$siteCon = LoginTo-PnP -Url $AlyaSharePointUrl
$web = Get-PnPWeb -Connection $siteCon

$gauser = $web.EnsureUser("Company Administrator")
$gauser.Context.Load($gauser)
Invoke-PnPQuery -Connection $siteCon
$gauserLoginName = $gauser.LoginName

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

# Checking app catalog site collection
Write-Host "Checking app catalog site collection" -ForegroundColor $CommandInfo
$catalogSiteName = "$prefix-ADM-$catalogTitle"
$site = $null
$site = Get-PnPTenantSite -Connection $adminCon -Url "$($AlyaSharePointUrl)/sites/$catalogSiteName" -Detailed -ErrorAction SilentlyContinue
if (-Not $site)
{
    Write-Warning "Checking existance of other App Catalog site"
    $appCatalogUrl = Get-PnPTenantAppCatalogUrl -Connection $adminCon
    if (-Not $appCatalogUrl)
    {
        $apiCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)"
        $res = Invoke-PnPSPRestMethod -Connection $apiCon -Method Get -Url "$($AlyaSharePointUrl)/_api/SP_TenantSettings_Current"
        $appCatalogUrl = $res.CorporateCatalogUrl
    }
    if ($appCatalogUrl -and -not $appCatalogUrl.EndsWith($catalogSiteName))
    {
        throw "There is already an app catalog with different title registered!"
    }

    Write-Warning "App Catalog site not found. Creating now app catalog site $catalogSiteName"
    Register-PnPAppCatalogSite -Connection $adminCon -Url "$($AlyaSharePointUrl)/sites/$catalogSiteName" -Owner $gauserLoginName -TimeZoneId 4 -Force

    do {
        Start-Sleep -Seconds 15
        $site = Get-PnPTenantSite -Connection $adminCon -Url "$($AlyaSharePointUrl)/sites/$catalogSiteName" -Detailed -ErrorAction SilentlyContinue
    } while (-Not $site)

    # Login to app catalog
    Write-Host "Login to app catalog" -ForegroundColor $CommandInfo
	$siteCon = LoginTo-PnP "$($AlyaSharePointUrl)/sites/$catalogSiteName"

    # Adding site to hub
    Write-Host "Adding site to hub" -ForegroundColor $CommandInfo
    $hubSite = Get-PnPSite -Connection $hubCon
    $siteSite = Get-PnPSite -Connection $siteCon
    Add-PnPHubSiteAssociation -Connection $adminCon -Site $siteSite -HubSite $hubSite

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
    
    # Configuring access to catalog site for internals and externals
    Write-Host "Configuring access to catalog site" -ForegroundColor $CommandInfo
    $vgroup = Get-PnPGroup -Connection $siteCon -AssociatedVisitorGroup
    Add-PnPGroupMember -Connection $siteCon -Group $vgroup -EmailAddress "$AlyaAllInternals@$AlyaDomainName" -SendEmail:$false
    Add-PnPGroupMember -Connection $siteCon -Group $vgroup -EmailAddress "$AlyaAllExternals@$AlyaDomainName" -SendEmail:$false

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
        $fname = Split-Path -Path $AlyaLogoUrlQuad -Leaf
        $tempFile = [System.IO.Path]::GetTempFileName()+$fname
        Invoke-RestMethod -Method GET -UseBasicParsing -Uri $AlyaLogoUrlQuad -OutFile $tempFile
        Set-PnPSite -Connection $siteCon -LogoFilePath $tempFile
        Remove-Item -Path $tempFile
    }

    Write-Host "Configuring site title" -ForegroundColor $CommandInfo
	Set-PnPWeb -Connection $siteCon -Title "$catalogSiteName"
}

Write-Host "Configuring site title" -ForegroundColor $CommandInfo
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl
Set-PnPTenantSite -Connection $adminCon -Identity $site.Url -Title "$catalogSiteName"

#Stopping Transscript
Stop-Transcript
