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
    17.10.2022 Konrad Brunner       Initial Version
    25.03.2023 Konrad Brunner       Permissions added
    06.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules
    05.08.2023 Konrad Brunner       Added role admins

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
    [string[]]$siteReaders = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Create-Site-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell" # TODO Remove when null pointer bug is fixed

# Login
#Set-PnPTraceLog -On -WriteToConsole -Level Debug -AutoFlush $true
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

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
        $site = New-PnPSite -Connection $adminCon -Type "TeamSite" -Title $title -Alias "$($siteUrl)" -SiteAlias "$($siteUrl)" -Lcid $lcid -TimeZone $tmzId.Id -Description $description -Wait
        #$site = New-PnPSite -Connection $adminCon -Type "TeamSite" -Title $title -Alias "$($siteUrl)" -SiteAlias "$($siteUrl)" -Lcid $lcid -TimeZone $tmzId.Id -Description $description -Owners @($AlyaSharePointNewSiteOwner) -Wait -HubSiteId 
        #Set-PnPTraceLog -Off
    }
    else
    {
        $site = New-PnPSite -Connection $adminCon -Type $siteTemplate -Title $title -Url $absSiteUrl -Lcid $lcid -TimeZone $tmzId.Id -Description $description -Wait
    }
    do {
        Start-Sleep -Seconds 15
        $site = Get-PnPTenantSite -Connection $adminCon -Url $absSiteUrl -ErrorAction SilentlyContinue
    } while (-Not $site)
    Write-Host "Site created. Waiting one minute."
    Start-Sleep -Seconds 60
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
    Add-PnPGroupMember -Connection $siteCon -Group $mgroup -EmailAddress $usrEmail -SendEmail:$false
}

# Setting siteMembers access
Write-Host "Setting siteMembers access" -ForegroundColor $CommandInfo
$mgroup = Get-PnPGroup -Connection $siteCon -AssociatedMemberGroup
foreach ($usrEmail in $siteMembers)
{
    Add-PnPGroupMember -Connection $siteCon -Group $mgroup -EmailAddress $usrEmail -SendEmail:$false
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
    Add-PnPGroupMember -Connection $siteCon -Group $mgroup -EmailAddress $usrEmail -SendEmail:$false
}

<# TODO
    [string[]]$groupOwners = $null,
    [string[]]$groupMembers = $null,
#>

# M365 Group Sharing Capability
if ($siteTemplate -eq "TeamSite")
{
    Write-Host "Setting M365 Group sharing capability " -ForegroundColor $CommandInfo
    $m365GroupId = $site.GroupId.Guid
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

# Stopping Transscript
Stop-Transcript
