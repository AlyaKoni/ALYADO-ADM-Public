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
    [string[]]$siteReaders = $null,
    [string]$headerLayout = $null,
    [string]$headerEmphasis = $null,
    [bool]$quickLaunchEnabled = $null,
    [string[]]$localesToHandle = @("en-us","de-de")
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Create-Site-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell"

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
if (-Not $siteCon)
{
    $siteCon = LoginTo-PnP -Url $absSiteUrl
}
$web = Get-PnPWeb -Connection $siteCon -Includes TitleResource,DescriptionResource
foreach($locale in $localesToHandle)
{
    $web.TitleResource.SetValueForUICulture($locale,$title)
    $web.DescriptionResource.SetValueForUICulture($locale,$description)
}
$web.Update()
Invoke-PnPQuery -Connection $siteCon

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
        Add-PnPGroupMember -Connection $siteCon -Group $mgroup -LoginName $guserLoginName
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
    $agroup = $null
    try {
        $agroup = Get-PnPMicrosoft365Group -Connection $adminCon -Identity $usrEmail -ErrorAction SilentlyContinue
    }
    catch { }
    if ($agroup)
    {
        Add-PnPGroupMember -Connection $siteCon -Group $mgroup -LoginName "c:0o.c|federateddirectoryclaimprovider|$($agroup.Id)"-SendEmail:$false
    }
    else
    {
        Add-PnPGroupMember -Connection $siteCon -Group $mgroup -EmailAddress $usrEmail -SendEmail:$false
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
        $fnd = $false
        foreach($gown in $grpOwners)
        {
            if ($gown.UserPrincipalName -eq $own -or $gown.Email -eq $own)
            {
                $fnd = $true
                break
            }
            if (-Not $fnd)
            {
                $grpOwnersNew += $own
            }
        }
    }
    Set-PnPMicrosoft365Group -Connection $adminCon -Identity $m365GroupId -Owners $grpOwnersNew
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
        $fnd = $false
        foreach($gmemb in $grpMembers)
        {
            if ($gmemb.UserPrincipalName -eq $memb -or $gmemb.Email -eq $memb)
            {
                $fnd = $true
                break
            }
            if (-Not $fnd)
            {
                $grpMembersNew += $memb
            }
        }
    }
    Set-PnPMicrosoft365Group -Connection $adminCon -Identity $m365GroupId -Members $grpMembersNew
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

# Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIvCQYJKoZIhvcNAQcCoIIu+jCCLvYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC/+ztrzTuUlS3O
# GcMdOgUkTVbf2aZaskJRbvuILhvjh6CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPkzs8Iw
# eIrmcR13nDalbeKaIzMozF6CliTMPEHl0XPbMA0GCSqGSIb3DQEBAQUABIICAHJV
# WeFknAcjynSfZ750DWwu9vruI8pQ3e+qGE35/qc4NiJHUHTTdeY0+du9ykX1f8zA
# KCtZvEL14O7Z3RhZlS5eE3KGMXVyTPrpp0kk0TunsiGLbxS+k7iqHa3nevC1PlKw
# YTGqwCqgcpBSFCfsCItQIEjddW5rB3E6R5bKaUVsSGa8vmrcbKCsKsRN9aT91gy6
# +OwkD7UJINg7psuKLkIW9Gx4F1Jm3OcajFCP6AmTL4mZZDCPspseTsvR7Vz9jGAM
# WI+SQAFeizbRKaL6qsv+IOKqj0KJtDg+P/41jE9rkteYEzPEZz5NTmjJDBZuWpaA
# CRSwiFw2xLXuQl+hCFgfH4XPCUMrX615hgxBQseS5TTwYEgKrVyVWIO1h5+G+LW/
# 68xPu6Y7q594akqFnYL4EYRH7SQIS9TbpV4ZQifsCeZWfBR5xS90BBIW5L9V5iIJ
# QooBuFNnKsa9JCGIin7kZhQcmqB/OKYgtkJ1XhxHwVN+fDgiXxZ/sm/v0HK6MY34
# MYN4RtUm40mAK6x4Lwuuj5Ns6m+NE9cg6J5JoBl0cLSX/kKI9gpN9EiNuImigzeR
# bOvzRNChpAru4IcipmyxI+KCE9UdU3l5a2OZUHBOhMjxw0djLn6Aai2ijXQgaSyy
# O/toswS5JlFnPOqo2GzpvSKzj4ilc+0rYf8O7+uhoYIWuzCCFrcGCisGAQQBgjcD
# AwExghanMIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEw
# gd8GCyqGSIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCDD6YuBfZ3LAgA0zusM85GXsC8YVka2wKsBPLNbtamk3QIUeSsb
# HQ3EblyWibZy9mI4JkboKiEYDzIwMjUwNTE1MTQ0MjAwWjADAgEBoFikVjBUMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwh
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMC
# AQICEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNp
# Z24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5
# WhcNMzQxMjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFs
# U2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWdu
# MSAtIFI2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4
# PuCF6+aqCj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb
# 5gk0Xydy3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJSc
# RV1W6/6efi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy
# 5RJY+o1NWhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY
# 0Lie04DuKbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2Z
# wbI6yiFHaS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYh
# KUlrMH9+2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5s
# WtX1qvCzk6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGo
# MIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYD
# VR0OBBYEFIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQC
# MEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSB
# gzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2Ev
# Z3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2Jh
# bHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaA
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9j
# cmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG
# 9w0BAQwFAAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26
# IFq7fQMIrN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76Tkv
# L+v2f4mHolGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftP
# ttS+G/MhNUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIl
# S3Ki74CU15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt
# 8DT4RQj9LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5
# lgJkgXEc1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD
# 9hQchjiGkyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71
# yzGKWnbAWQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGL
# ZtJFJzGJD7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVA
# GXCqHsh62QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZ
# MIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAw
# MDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOv
# dYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt
# 0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHP
# vIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFU
# UweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16
# ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS
# 2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm1
# 9m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIG
# bxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMD
# Ad6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/Miy
# Tdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9
# GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGG
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDD
# vWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEB
# BDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jv
# b3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29t
# L3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0B
# AQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYW
# axlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCy
# z+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQ
# cXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0
# Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59e
# odaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8
# oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1
# If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbcl
# IA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2M
# tnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB
# +SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIID
# a6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQL
# ExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjET
# MBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAw
# MDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQK
# EwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4
# QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTe
# c5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWy
# ZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7tt
# U+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrK
# otudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKF
# t3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTfl
# puwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2Fm
# CWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5
# paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4O
# hxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwo
# TK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki
# 5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnm
# XNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJE
# lrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMp
# mY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6
# JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG
# 7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/
# gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324G
# abbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5
# MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO7
# 7oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4st
# Q1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjx
# guhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJ
# YIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZI
# hvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcN
# AQkEMSIEIGniRUnfdW/IXOMVGeFd2kvs/dHfe9xo/RG36qQ0dSVuMIGwBgsqhkiG
# 9w0BCRACLzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1or
# d69gXP0wczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hB
# Mzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAAImc
# 9HsP7+vtHzQYzmaD2IFdPXB7g3CQQr6PGCilwtJ7bprzLim6qFnvFS9ykMF/ZN2p
# NYuQf+HC1H9JZ2nnsBnLcuY0j35BWClVswZOoJjBk+7ehPwTHqXgWUrOh7hi6W8/
# P090SPz8bJVBQ8yW3eKTHk5svqHvthwnCFfcEaB+TY7toRG+B1I5Vi/kNKTtmev6
# VlVUWdrK/TEIdSAhsin+0FyJRcrwB2TOB0XWQaQoYrrF7ge9GYwPIZrR7lFMQGDV
# +vQsot4LvOnTom4am2RzY/VF8Ix/QnHdhffxA6Z8yMH21TpZCifrHUWMkFtvD/f8
# xnouOwdt/KcNHIE7OJvn8iNJe0Gg+H8mJV1MiKtL5bYNDvE5H+y1VqpASXeDo2kA
# rkiYXAAkYXN+ImhBREDVKkAokNEZl38+ybO8fFaYnsLJRtdB8K1ug2QoiO3kV+Wc
# e8s/2qzATQ+7dgB+5JBQ3hTQCG8QeC0lkFMVv3Gl+sMrR0LVbpxRm6P377zt
# SIG # End signature block
