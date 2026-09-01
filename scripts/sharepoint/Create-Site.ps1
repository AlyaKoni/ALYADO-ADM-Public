#Requires -Version 7.0

<#
    Copyright (c) Alya Consulting, 2019-2024

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
    17.10.2022 Konrad Brunner       Initial Version
    25.03.2023 Konrad Brunner       Permissions added
    06.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules
    05.08.2023 Konrad Brunner       Added role admins
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Creates and configures a new SharePoint Online site, assigns it to a hub, applies design templates, and sets permissions, external sharing, and various site properties.

.DESCRIPTION
The Create-Site.ps1 script automates the creation and configuration of SharePoint Online sites using the PnP.PowerShell module. It supports both Communication and Team Sites, allows for hub site association, external sharing settings, permissions configuration, and customization of various site properties such as headers, logos, and home pages. The script also manages Microsoft 365 group membership and guest sharing configuration.

.PARAMETER title
Specifies the title of the SharePoint site to create. This parameter is mandatory.

.PARAMETER siteUrl
Specifies the site URL. If not provided, it will be derived from the title.

.PARAMETER hub
Specifies the hub site short name to associate the new site with. This parameter is mandatory.

.PARAMETER siteDesignName
Specifies an optional custom site design to apply to the site.

.PARAMETER siteTemplate
Defines the type of site to create, either "CommunicationSite" or "TeamSite". This parameter is mandatory.

.PARAMETER siteLocale
Defines the locale to use when creating the site (e.g. "en-us", "de-de"). This parameter is mandatory.

.PARAMETER externalSharing
Specifies the external sharing capability for the site. Options include "None", "AdminOnly", "KnownAccountsOnly", or "ByLink". This parameter is mandatory.

.PARAMETER homePageTemplate
Specifies an optional template for the site's home page.

.PARAMETER description
Provides a description for the site.

.PARAMETER siteLogoUrl
URL of the logo image to set for the site.

.PARAMETER overwritePages
Indicates whether to overwrite existing pages when applying templates. Default is $true.

.PARAMETER hubSitesConfigurationFile
Specifies a custom path to the hub sites configuration file.

.PARAMETER groupOwners
Array of Microsoft 365 group owners to assign.

.PARAMETER groupMembers
Array of Microsoft 365 group members to assign.

.PARAMETER siteOwners
Array of SharePoint site owners to assign.

.PARAMETER siteMembers
Array of SharePoint site members to assign.

.PARAMETER siteReaders
Array of SharePoint site visitors/readers to assign.

.PARAMETER headerLayout
Specifies the header layout style for the site.

.PARAMETER headerEmphasis
Specifies the header emphasis style for the site.

.PARAMETER quickLaunchEnabled
Indicates whether the Quick Launch menu is enabled for the site.

.PARAMETER localesToHandle
Array of locales to apply for multilingual configuration. Default is @("en-us","de-de").

.PARAMETER allowSiteScripts
Indicates whether site scripts are allowed. Default is $false.

.INPUTS
None. You cannot pipe input to this script.

.OUTPUTS
None. The script writes progress and status information to the console and log files.

.EXAMPLE
PS> .\Create-Site.ps1 -title "Marketing Hub" -hub "Corp" -siteTemplate "CommunicationSite" -siteLocale "en-us" -externalSharing "ByLink" -description "Marketing department SharePoint site"

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$title,
    [string]$siteUrl = $null,
    [Parameter(Mandatory=$true)]
    [string]$hub,
    [string]$siteDesignName = $null,
    [Parameter(Mandatory=$true)]
    [ValidateSet("CommunicationSite","TeamSite")]
    [string]$siteTemplate,
    [Parameter(Mandatory=$true)]
    [string]$siteLocale,
    [Parameter(Mandatory=$true)]
    [ValidateSet("None","AdminOnly","KnownAccountsOnly","ByLink")]
    [string]$externalSharing,
    [string]$homePageTemplate = $null,
    [string]$description = "",
    [string]$siteLogoUrl = $null,
    [bool]$overwritePages = $true,
    [string]$hubSitesConfigurationFile = $null,
    [string[]]$groupOwners = $null,
    [string[]]$groupMembers = $null,
    [string[]]$siteOwners = $null,
    [string[]]$siteMembers = $null,
    [string[]]$siteReaders = $null,
    [string]$headerLayout = $null,
    [string]$headerEmphasis = $null,
    [bool]$quickLaunchEnabled = $null,
    [string[]]$localesToHandle = @("en-us","de-de"),
    [bool]$allowSiteScripts = $false
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Create-Site-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Login
#Set-PnPTraceLog -On -WriteToConsole -Level Debug -AutoFlush $true
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Create-Site | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking owners
if ($siteTemplate -eq "TeamSite" -and ($null -eq $siteOwners -or $siteOwners.Length -eq 0))
{
    throw "For TeamSites you need to specify at least one owner"
}

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

# =============================================================
# Functions
# =============================================================

function BuildUrlFromTitle($title)
{
    $siteUrl = $title -replace "[^a-zA-Z0-9-_]", ""
    return $siteUrl
}

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Create-Site | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

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

# Creating site
Write-Host "Creating site $($title)" -ForegroundColor $CommandInfo
if (-Not $siteUrl) { $siteUrl = BuildUrlFromTitle -title $title }
$absSiteUrl = "$($AlyaSharePointUrl)/sites/$($siteUrl)"

$site = Get-PnPTenantSite -Connection $adminCon -Url $absSiteUrl -ErrorAction SilentlyContinue
if (-Not $site)
{
    Write-Warning "Site not found. Creating now site $($title)"
    $spLang = $siteLocale.Split("-")[0]
    $spLocale = "$spLang-$spLang"
    $lcid = (Get-Culture -Name $spLocale).LCID
    $tmz = Get-TimeZone -Id $AlyaTimeZone
    $tmzP = $tmz.BaseUtcOffset.ToString().Split(":")
    $tmzOs = "UTC+$($tmzP[0]):$($tmzP[1])"
    $cities = $tmz.DisplayName.Split(" ,".ToCharArray(),[System.StringSplitOptions]::RemoveEmptyEntries) | Select-Object -Skip 1
    $cnt = 0
    $tmzId = $null
    while ($null -eq $tmzId)
    {
        $tmzId = Get-PnPTimeZoneId -Match $cities[$cnt]
        $cnt++
        if ($tmzId.Identifier -ne $tmzOs)
        {
            $tmzId = $null
        }
    }
    if ($null -eq $tmzId)
    {
        Write-Warning "Getting first timezone with identifier $tmzOs"
        $tmzId = Get-PnPTimeZoneId | Where-Object { $_.Identifier -eq $tmzOs } | Select-Object -First 1
    }
    if ($null -eq $tmzId)
    {
        throw "Can't find your configured timezone!"
    }

    if ($siteTemplate -eq "TeamSite")
    {
        <#Write-Warning "PnP has actually an issue. please createt he TeamSite by hand"
        Write-Warning "  Type: TeamSite"
        Write-Warning "  Title: $title"
        Write-Warning "  Url: $siteUrl"
        Write-Warning "  TimeZone: $tmzP"
        Write-Warning "  Description: $description"
        pause#>
        #Set-PnPTraceLog -On -LogFile "C:\Temp\traceoutput.txt" -WriteToConsole -Level "Debug" -AutoFlush $true
        $site = New-PnPSite -Connection $adminCon -Type "TeamSite" -Title $title -Alias "$($siteUrl)" -SiteAlias "$($siteUrl)" -Lcid $lcid -TimeZone $tmzId.Id -Description $description
        #$site = New-PnPSite -Connection $adminCon -Type "TeamSite" -Title $title -Alias "$($siteUrl)" -SiteAlias "$($siteUrl)" -Lcid $lcid -TimeZone $tmzId.Id -Description $description -Owners @($AlyaSharePointNewSiteOwner) -Wait -HubSiteId 
        #Set-PnPTraceLog -Off
    }
    else
    {
        $site = New-PnPSite -Connection $adminCon -Type $siteTemplate -Title $title -Url $absSiteUrl -Lcid $lcid -TimeZone $tmzId.Id -Description $description
    }
    do {
        Write-Host "Waiting for site ..."
        Start-Sleep -Seconds 15
        $site = Get-PnPTenantSite -Connection $adminCon -Url $absSiteUrl -ErrorAction SilentlyContinue
    } while (-Not $site)
    Write-Host "Site created. Waiting one minute."
    Start-Sleep -Seconds 60
}

# Updating site
Write-Host "Updating site" -ForegroundColor $CommandInfo
$siteCon = LoginTo-PnP -Url $absSiteUrl
$web = Get-PnPWeb -Connection $siteCon -Includes TitleResource,DescriptionResource
foreach($locale in $localesToHandle)
{
    $web.TitleResource.SetValueForUICulture($locale,$title)
    $web.DescriptionResource.SetValueForUICulture($locale,$description)
}
$web.Update()
Invoke-PnPQuery -Connection $siteCon

# Denying site scripts
Write-Host "Denying site scripts" -ForegroundColor $CommandInfo
Set-PnPSite -Connection $siteCon -NoScriptSite (-Not $allowSiteScripts)

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

# Assigning site to hub
if ($hub)
{
    Write-Host "Assigning site to hub $($hub)" -ForegroundColor $CommandInfo
    $hubSite = $hubSites | Where-Object { $_.short -eq $hub }
    if (-Not $hubSite)
    {
        throw "Hub site $($hub) not found"
    }
    $hubSiteUrl = "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
    $hubSiteObj = Get-PnPHubSite -Connection $adminCon -Identity $hubSiteUrl
    if (-Not $hubSiteObj)
    {
        throw "Hub site $($hub) not found"
    }
    try {
        $hubCon = LoginTo-PnP -Url $hubSiteUrl
        $hubSite = Get-PnPSite -Connection $hubCon
        $siteCon = LoginTo-PnP -Url $absSiteUrl
        $siteSite = Get-PnPSite -Connection $siteCon
        Add-PnPHubSiteAssociation -Connection $adminCon -Site $siteSite -HubSite $hubSite
    } catch {
        Write-Error $_ -ErrorAction Continue
    }
}

# Updating web properties
Write-Host "Updating web properties" -ForegroundColor $CommandInfo
$web = Get-PnPWeb -Connection $siteCon -Includes HeaderEmphasis,HeaderLayout,SiteLogoUrl,QuickLaunchEnabled
$dirty = $false
if (-Not [string]::IsNullOrEmpty($headerLayout) -and $web.HeaderLayout -ne $siteDef.HeaderLayout)
{
    $web.HeaderLayout = $siteDef.HeaderLayout
    $dirty = $true
}
if (-Not [string]::IsNullOrEmpty($headerEmphasis) -and $web.HeaderEmphasis -ne $siteDef.HeaderEmphasis)
{
    $web.HeaderEmphasis = $siteDef.HeaderEmphasis
    $dirty = $true
}
if ($null -ne $quickLaunchEnabled -and $web.QuickLaunchEnabled -ne $siteDef.QuickLaunchEnabled)
{
    $web.QuickLaunchEnabled = $siteDef.QuickLaunchEnabled
    $dirty = $true
}
if ($dirty)
{
    $web.Update()
    Invoke-PnPQuery -Connection $siteCon
}

# Updating site logo
Write-Host "Updating site logo" -ForegroundColor $CommandInfo
if (-Not $siteCon)
{
    $siteCon = LoginTo-PnP -Url $absSiteUrl
}
$web = Get-PnPWeb -Connection $siteCon -Includes HeaderEmphasis,HeaderLayout,SiteLogoUrl,QuickLaunchEnabled
if (([string]::IsNullOrEmpty($web.SiteLogoUrl) -or $web.SiteLogoUrl.ToLower().Contains("getgroupimage")) -and $siteLogoUrl)
{
    if ($siteTemplate -eq "TeamSite")
    {
        $fname = Split-Path -Path $siteLogoUrl -Leaf
        $tempFile = [System.IO.Path]::GetTempFileName()+$fname
        Invoke-RestMethod -Method GET -UseBasicParsing -Uri $siteLogoUrl -OutFile $tempFile
        $retries = 5
        do {
            $retries--
            try {
                Set-PnPSite -Connection $siteCon -LogoFilePath $tempFile
                $retries = -1
            } catch {
                Start-Sleep -Seconds 10
            }
        } while ($retries -ge 0)
        Remove-Item -Path $tempFile
    }
    if ($siteTemplate -eq "CommunicationSite")
    {
        $web.SiteLogoUrl = $siteLogoUrl
        $web.Update()
        Invoke-PnPQuery -Connection $siteCon
    }
}

# Setting admin access
Write-Host "Setting admin access" -ForegroundColor $CommandInfo
Set-PnPTenantSite -Connection $adminCon -Identity $absSiteUrl -PrimarySiteCollectionAdmin $gauserLoginName -Owners $owners

#Processing site design
Write-Host "Processing site design" -ForegroundColor $CommandInfo
if (-Not $siteDesignName)
{
    $hubSiteDef = $hubSites | Where-Object { $_.short -eq $hub }
    if ($siteTemplate -eq "TeamSite")
    {
        if ($hubSiteDef.subSiteScript)
        {
            $siteDesignName = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSiteDef.short) SubSite Team Site "+$siteLocale
        }
        else
        {
		    $siteDesignName = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSiteDef.short) HubSite Team Site "+$siteLocale
        }
    }
    else
    {
        if ($hubSiteDef.subSiteScript)
        {
            $siteDesignName = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSiteDef.short) SubSite Communication Site "+$siteLocale
        }
        else
        {
		    $siteDesignName = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSiteDef.short) HubSite Communication Site "+$siteLocale
        }
    }
}
$siteDesign = Get-PnPSiteDesign -Connection $adminCon -Identity $siteDesignName
Invoke-PnPSiteDesign -Connection $adminCon -Identity $siteDesign -WebUrl $absSiteUrl

# Processing external sharing
Write-Host "Processing external sharing" -ForegroundColor $CommandInfo
# None(Disabled), AdminOnly(ExistingExternalUserSharingOnly), KnownAccountsOnly(ExternalUserSharingOnly), ByLink(ExternalUserAndGuestSharing)
switch($externalSharing)
{
    "None" {
        Set-PnPTenantSite -Connection $adminCon -Identity $absSiteUrl -SharingCapability Disabled
    }
    "AdminOnly" {
        Set-PnPTenantSite -Connection $adminCon -Identity $absSiteUrl -SharingCapability  ExistingExternalUserSharingOnly
    }
    "KnownAccountsOnly" {
        Set-PnPTenantSite -Connection $adminCon -Identity $absSiteUrl -SharingCapability  ExternalUserSharingOnly
    }
    "ByLink" {
        Set-PnPTenantSite -Connection $adminCon -Identity $absSiteUrl -SharingCapability  ExternalUserAndGuestSharing
    }
}

# Setting siteOwners access
Write-Host "Setting siteOwners access" -ForegroundColor $CommandInfo
$siteCon = LoginTo-PnP -Url $absSiteUrl
$mgroup = Get-PnPGroup -Connection $siteCon -AssociatedOwnerGroup
foreach ($usrEmail in $siteOwners)
{
    if ([string]::IsNullOrWhiteSpace($usrEmail)) { continue }
    $agroup = $null
    try {
        $agroup = Get-PnPMicrosoft365Group -Connection $adminCon -Identity $usrEmail -ErrorAction SilentlyContinue
    }
    catch { }
    if ($agroup)
    {
        Add-PnPGroupMember -Connection $siteCon -Group $mgroup -LoginName "c:0o.c|federateddirectoryclaimprovider|$($agroup.Id)"
    }
    else
    {
        Add-PnPGroupMember -Connection $siteCon -Group $mgroup -LoginName $usrEmail
    }
}

# Setting siteMembers access
Write-Host "Setting siteMembers access" -ForegroundColor $CommandInfo
$mgroup = Get-PnPGroup -Connection $siteCon -AssociatedMemberGroup
foreach ($usrEmail in $siteMembers)
{
    if ([string]::IsNullOrWhiteSpace($usrEmail)) { continue }
    $agroup = $null
    try {
        $agroup = Get-PnPMicrosoft365Group -Connection $adminCon -Identity $usrEmail -ErrorAction SilentlyContinue
    }
    catch { }
    if ($agroup)
    {
        Add-PnPGroupMember -Connection $siteCon -Group $mgroup -LoginName "c:0o.c|federateddirectoryclaimprovider|$($agroup.Id)"
    }
    else
    {
        Add-PnPGroupMember -Connection $siteCon -Group $mgroup -LoginName $usrEmail
    }
}

# Configuring member permissions
Write-Host "Configuring member permissions" -ForegroundColor $CommandInfo
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

# Setting siteReaders access
Write-Host "Setting siteReaders access" -ForegroundColor $CommandInfo
$mgroup = Get-PnPGroup -Connection $siteCon -AssociatedVisitorGroup
foreach ($usrEmail in $siteReaders)
{
    if ([string]::IsNullOrWhiteSpace($usrEmail)) { continue }
    $agroup = $null
    try {
        $agroup = Get-PnPMicrosoft365Group -Connection $adminCon -Identity $usrEmail -ErrorAction SilentlyContinue
    }
    catch { }
    if ($agroup)
    {
        Add-PnPGroupMember -Connection $siteCon -Group $mgroup -LoginName "c:0o.c|federateddirectoryclaimprovider|$($agroup.Id)"
    }
    else
    {
        Add-PnPGroupMember -Connection $siteCon -Group $mgroup -LoginName $usrEmail
    }
}

# Setting group Owners
if ($null -ne $groupOwners -and $groupOwners.Length -gt 0)
{
    Write-Host "Setting group Owners " -ForegroundColor $CommandInfo
    $m365GroupId = $site.GroupId.Guid
    $grpOwners = Get-PnPMicrosoft365GroupOwners -Connection $adminCon -Identity $m365GroupId
    if ($grpMembers.Count -eq 0)
    {
        $grpOwnersNew = @()
    }
    else
    {
        $grpOwnersNew = @($grpOwners.UserPrincipalName)
    }
    foreach($own in $groupOwners)
    {
        if ([string]::IsNullOrWhiteSpace($own)) { continue }
        $fnd = $false
        foreach($gown in $grpOwners)
        {
            if ($gown.UserPrincipalName -eq $own -or $gown.Email -eq $own)
            {
                $fnd = $true
                break
            }
        }
        if (-Not $fnd)
        {
            $grpOwnersNew += $own
        }
    }
    if ($grpOwnersNew.Count -gt 0)
    {
        Set-PnPMicrosoft365Group -Connection $adminCon -Identity $m365GroupId -Owners $grpOwnersNew
    }
}

# Setting group Members
if ($null -ne $groupMembers -and $groupMembers.Length -gt 0)
{
    Write-Host "Setting group Members " -ForegroundColor $CommandInfo
    $m365GroupId = $site.GroupId.Guid
    $grpMembers = Get-PnPMicrosoft365GroupMembers -Connection $adminCon -Identity $m365GroupId
    if ($grpMembers.Count -eq 0)
    {
        $grpMembersNew = @()
    }
    else
    {
        $grpMembersNew = @($grpMembers.UserPrincipalName)
    }
    foreach($memb in $groupMembers)
    {
        if ([string]::IsNullOrWhiteSpace($memb)) { continue }
        $fnd = $false
        foreach($gmemb in $grpMembers)
        {
            if ($gmemb.UserPrincipalName -eq $memb -or $gmemb.Email -eq $memb)
            {
                $fnd = $true
                break
            }
        }
        if (-Not $fnd)
        {
            $grpMembersNew += $memb
        }
    }
    if ($grpMembersNew.Count -gt 0)
    {
        Set-PnPMicrosoft365Group -Connection $adminCon -Identity $m365GroupId -Members $grpMembersNew
    }
}

# M365 Group Sharing Capability
if ($siteTemplate -eq "TeamSite")
{
    Write-Host "Setting M365 Group sharing capability " -ForegroundColor $CommandInfo
    $m365GroupId = $site.GroupId.Guid
    if ($m365GroupId -eq [Guid]::Empty.Guid)
    {
        $m365GroupId = (Get-PnPMicrosoft365Group -Connection $adminCon -Identity $title).Id
    }
    $settingsValue = "true"
    if ($externalSharing -eq "None")
    {
        $settingsValue = "false"
    }
    $settings = Get-PnPMicrosoft365GroupSettings -Connection $adminCon -Identity $m365GroupId
    if (-Not $settings)
    {
        Write-Warning "Created new team guest settings"
        $settings = New-PnPMicrosoft365GroupSettings -Connection $adminCon -Identity $m365GroupId -DisplayName "Group.Unified.Guest" -TemplateId "08d542b9-071f-4e16-94b0-74abb372e3d9" -Values @{"AllowToAddGuests"=$settingsValue}
    }
    if (($settings.Values | Where-Object { $_.Name -eq "AllowToAddGuests"}).Value.ToString() -ne $settingsValue.ToString())
    {
        Write-Warning "Existing team guest settings changed"
        $settings = Set-PnPMicrosoft365GroupSettings -Connection $adminCon -Identity $settings.ID -Group $m365GroupId -Values @{"AllowToAddGuests"=$settingsValue}
    }
}

# Processing Home Page
Write-Host "Processing Home Page" -ForegroundColor $CommandInfo
if ($overwritePages -and $homePageTemplate)
{
    #To export it: Export-PnPPage -Connection $siteCon -Force -Identity Home.aspx -Out $tempFile
    $tempFile = [System.IO.Path]::GetTempFileName()
    $homePageTemplate | Set-Content -Path $tempFile -Encoding UTF8
    $tmp = Invoke-PnPSiteTemplate -Connection $siteCon -Path $tempFile
    Remove-Item -Path $tempFile

    # Setting home page
    Set-PnPHomePage -RootFolderRelativeUrl "SitePages/Home.aspx" -Connection $siteCon
}

# OneDrive Sync Url
Write-Host "OneDrive Sync Url" -ForegroundColor $CommandInfo
$site = Get-PnPSite -Connection $siteCon -Includes "ID"
$web = Get-PnPWeb -Connection $siteCon -Includes "ID","Title"
$list = Get-PnPList -Connection $siteCon | Where-Object { $_.Title -eq "Dokumente" -or $_.Title -eq "Freigegebene Dokumente" -or $_.Title -eq "Documents" -or $_.Title -eq "Shared Documents" }
$WebURL = [System.Web.HttpUtility]::UrlEncode("$($AlyaSharePointUrl)/sites/$title/")
$SiteID = [System.Web.HttpUtility]::UrlEncode("{$($site.Id.Guid)}")
$WebID = [System.Web.HttpUtility]::UrlEncode("{$($web.Id.Guid)}")
$ListID = [System.Web.HttpUtility]::UrlEncode("{$($list.Id.Guid)}")
$WebTitle = [System.Web.HttpUtility]::UrlEncode("$($web.Title)")
$ListTitle = [System.Web.HttpUtility]::UrlEncode("$($list.Title)")
$UserName = [System.Web.HttpUtility]::UrlEncode("xxxxxxxxxx@$AlyaDomainName")
Write-Host "odopen://sync?siteId=$SiteID&webId=$WebID&listId=$ListID&userEmail=$UserName&webUrl=$WebURL&webTitle=$WebTitle&listTitle=$ListTitle&scope=OPENLIST" -ForegroundColor DarkGreen

# Stopping Transcript
Stop-Transcript

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAwtIeffvMmEWZ+
# BZ7+4a/BomIUujgDK43eFE2j9N0i2qCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDWJ7M2R
# nQEAB8zHWNEW/+jmLinJY5IhTtRtGr23BUCUMA0GCSqGSIb3DQEBAQUABIICAHCm
# LB/vplKbEW4iqYq5cWi2z0Q08PLXSzf23kdcUfUroojL9idp2KD42moQie9I5J+H
# pA8Ed9u3NRkCsEW22WrNcSTvRKGnMV9TNWcZJRAl3Y6p/Ciahrnqmtrk+UmV/0Ad
# jRQwIAtQTdssdqOPnXPHuoj+q+pb2sDLU2jluBcEL0SIvxPt+HycoHQwpPuKtmIs
# bIHVlA+wrcwTHegEpHmxYgkI+4svvzs/jDFwaZZ53ckJVhzMcVoFo5rBU8WljVrN
# ZDfmJRKIHZBEEyhqJGjSQiNxya0Z+j5rwx2ypunWIXUnmkGTafWqfGfeIzpBXj+/
# HVTzZD9T69WV+6CtsV+sCnzrZlCSihLxMhWGCd61tBm52wHZig8OlaGEy08JZAse
# 0ALOaLBwe0TR4wF2Oxm/UUvTGAyzTyKpSHCnCa+bDB7UHx4kR08kOi6ZtCiagBDf
# deNxMsKg5gPNpjfGIVeLN5i91CiPnGaqXmkXQENet6d93a2AslMZPhgOP+CswnQi
# BpU0vi+6jaJ3RxgEn09mTmitq/HCZPvVCSO29Y93zwKbfoBcJwpeyZlVthx9Fpgz
# iaaKgBLUtkfDxuy5FprKEwtkDQJh9tldBXtxb8FZTqtWomCAGX4bhP7QlpparSgd
# CakxkOeOoEsKym74THMX/EjNe04f1XYEhmc1At+2oYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCBVOJi86XXxSX84iHwHq+mefLMaTJS2miDo8Sa7I97CFAIUDEDS
# e8tFBDo8tFxsI39i4ekiXTUYDzIwMjYwODI5MTUzMzMxWjADAgEBoF2kWzBZMQsw
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
# BDEyBDAZLav+MllRtdEgxobU/nxekIDX3WbVuv2GEyriS7QaX0rdtvwpabIndJ/0
# 8RQv6EcwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAR7fZoEm9kYmpx3nHxTJwto2CPFPBrYGrePUe3ErNYkH2
# iJamz58gxPf1jKWeOMT0g6xczdtbfQxtDPmmfHyyCX3f6srCnc4Ji5xp7Wav8HHO
# Feq9iYEVF6hNFUIf9xISu+CY0WuLWXsfjF03JuZaEpny+728xd0cP3X1sroCfYrK
# uy4dyO1cYZH/oKBB3qsGI2hpN7fIdxj5ZOzXXp0HD8504If5KBJdE8+yOGQ76Jv9
# Jtxlknuprw3/tlm0X3zFY4zUI6XTHnNhdAH7RdmqdIaLtu10cR3GpcCgeNpcxMkY
# u6W2La+ViTqgYJL/Hmx7jz2qtc3bV0pmw7mj1CVWUD9kwdt+ufVrsa0cD23U8vFT
# e5L5b5H2/UWnMC4Dcjni1HPoXTtbbjpm712Hre8X6C0SNkFKpU+rxkOg/VpLLRdi
# pBkjwt8q7sMGvd0umOnxSWSGEw+du/jMltKwCXtYtt87gOdf7p8ahbzsw56YJYId
# LRr7lQ0ivk6YKrVyEwzv
# SIG # End signature block
