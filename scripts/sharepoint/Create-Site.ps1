#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2022

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
    17.10.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$title,
    [string]$siteUrl = $null,
    [Parameter(Mandatory=$true)]
    [string]$hub,
    [Parameter(Mandatory=$false)]
    [string]$siteDesignName = $null,
    [Parameter(Mandatory=$true)]
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
    [string]$hubSitesConfigurationFile = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Create-Site-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Microsoft.Online.Sharepoint.PowerShell"
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Logging in
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-SPO

# Constants
if ($hubSitesConfigurationFile)
{
    if ((Test-Path $hubSitesConfigurationFile))
    {
        Write-Host "Using hub site configuration from: $($hubSitesConfigurationFile)"
        . $hubSitesConfigurationFile
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
        . $AlyaData\sharepoint\HubSitesConfiguration-$siteLocale.ps1
    }
    else
    {
        Write-Host "Using hub site configuration from: $($PSScriptRoot)\HubSitesConfigurationTemplate-$($siteLocale).ps1"
        Write-Warning "We suggest to copy the HubSitesConfigurationTemplate-$($siteLocale).ps1 to your data\sharepoint directory"
        pause
        . $AlyaScripts\sharepoint\HubSitesConfigurationTemplate-$siteLocale.ps1
    }
}

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

#Creating site
Write-Host "Creating site $($title)" -ForegroundColor $CommandInfo
if (-Not $siteUrl) { $siteUrl = BuildUrlFromTitle -title $title }
$site = $null
try { $site = Get-SPOSite -Identity "$($AlyaSharePointUrl)/sites/$($siteUrl)" -Detailed -ErrorAction SilentlyContinue } catch {}
if (-Not $site)
{
    Write-Warning "Site not found. Creating now site $($title)"
    $adminCon = LoginTo-PnP -Url "$AlyaSharePointAdminUrl"
    if ($siteTemplate -eq "TeamSite")
    {
        $site = New-PnPSite -Connection $adminCon -Type "TeamSite" -Title $title -Alias "$($siteUrl)" -Description $description -Wait
    }
    else
    {
        $site = New-PnPSite -Connection $adminCon -Type $siteTemplate -Title $title -Url "$($AlyaSharePointUrl)/sites/$($siteUrl)" -Description $description -Wait
    }
    do {
        Start-Sleep -Seconds 15
        try { $site = Get-SPOSite -Identity "$($AlyaSharePointUrl)/sites/$($siteUrl)" -Detailed -ErrorAction SilentlyContinue } catch {}
    } while (-Not $site)
    Start-Sleep -Seconds 60
}

#Assigning site to hub
if ($hub)
{
    Write-Host "Assigning site to hub $($hub)" -ForegroundColor $CommandInfo
    $hubSite = $hubSites | where { $_.short -eq $hub }
    if (-Not $hubSite)
    {
        throw "Hub site $($hub) not found"
    }
    $hubSiteObj = Get-PnPHubSite -Connection $adminCon -Identity "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
    if (-Not $hubSiteObj)
    {
        throw "Hub site $($hub) not found"
    }
    $hubCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
    $hubSite = Get-PnPSite -Connection $hubCon
    $siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$($siteUrl)"
    $siteSite = Get-PnPSite -Connection $siteCon
    Add-PnPHubSiteAssociation -Connection $adminCon -Site $siteSite -HubSite $hubSite
}

#Updating site logo
Write-Host "Updating site logo" -ForegroundColor $CommandInfo
$siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$($siteUrl)"
$web = Get-PnPWeb -Connection $siteCon -Includes HeaderEmphasis,HeaderLayout,SiteLogoUrl,QuickLaunchEnabled
if ([string]::IsNullOrEmpty($web.SiteLogoUrl) -and $siteLogoUrl)
{
    if ($siteTemplate -eq "TeamSite")
    {
        $fname = Split-Path -Path $siteLogoUrl -Leaf
        $tempFile = [System.IO.Path]::GetTempFileName()+$fname
        Invoke-RestMethod -Method GET -UseBasicParsing -Uri $siteLogoUrl -OutFile $tempFile
        Set-PnPSite -Connection $siteCon -LogoFilePath $tempFile
        Remove-Item -Path $tempFile
    }
    if ($siteTemplate -eq "CommunicationSite")
    {
        $web.SiteLogoUrl = $siteLogoUrl
        $web.Update()
        Invoke-PnPQuery -Connection $siteCon
    }
}

#Setting access
Write-Host "Setting access" -ForegroundColor $CommandInfo
$site = Get-SPOSite -Identity "$($AlyaSharePointUrl)/sites/$($siteUrl)" -Detailed
foreach ($usrEmail in $AlyaSharePointNewSiteCollectionAdmins)
{
    $tmp = Set-SPOUser -Site $Site -LoginName $usrEmail -IsSiteCollectionAdmin $True
}
$tmp = Set-SPOUser -Site $Site -LoginName $AlyaSharePointNewSiteOwner -IsSiteCollectionAdmin $True
$tmp = Set-SPOSite -Identity $Site -Owner $AlyaSharePointNewSiteOwner
    
#Processing site design
Write-Host "Processing site design" -ForegroundColor $CommandInfo
if (-Not $siteDesignName)
{
    $hubSiteDef = $hubSites | where { $_.short -eq $hub }
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
$siteDesign = Get-SPOSiteDesign | where { $_.Title -eq $siteDesignName }
Invoke-SPOSiteDesign -Identity $siteDesign.Id -WebUrl "$($AlyaSharePointUrl)/sites/$($siteUrl)"

#Processing external sharing
Write-Host "Processing external sharing" -ForegroundColor $CommandInfo
# None(Disabled), AdminOnly(ExistingExternalUserSharingOnly), KnownAccountsOnly(ExternalUserSharingOnly), ByLink(ExternalUserAndGuestSharing)
switch($externalSharing)
{
    "None" {
        Set-SPOSite -Identity $Site -SharingCapability Disabled
    }
    "AdminOnly" {
        Set-SPOSite -Identity $Site -SharingCapability ExistingExternalUserSharingOnly
    }
    "KnownAccountsOnly" {
        Set-SPOSite -Identity $Site -SharingCapability ExternalUserSharingOnly
    }
    "ByLink" {
        Set-SPOSite -Identity $Site -SharingCapability ExternalUserAndGuestSharing
    }
}

# M365 Group Sharing Capability
if ($siteTemplate -eq "TeamSite")
{
    Write-Host "Setting M365 Group sharing capability " -ForegroundColor $CommandInfo
    $m365GroupId = $site.GroupId.Guid
    if ($externalSharing -ne "None")
    {
        $settings = Get-AzureADObjectSetting -TargetType "Groups" -TargetObjectId $m365GroupId -All $true | where { $_.DisplayName -eq "Group.Unified.Guest" }
        if ($settings)
        {
            if ($settings["AllowToAddGuests"] -eq $false)
            {
                Write-Warning "Existing team guest settings changed to allow Guests"
                $settings["AllowToAddGuests"] = $true
                $settings = Set-AzureADObjectSetting -TargetType "Groups" -TargetObjectId $m365GroupId -Id $settings.Id -DirectorySetting $settings
            }
        }
    }
    else
    {
        $settings = Get-AzureADObjectSetting -TargetType "Groups" -TargetObjectId $m365GroupId -All $true | where { $_.DisplayName -eq "Group.Unified.Guest" }
        if (-Not $settings)
        {
            Write-Warning "Created new team guest settings to disable Guests"
            $template = Get-AzureADDirectorySettingTemplate | ? {$_.displayname -eq "Group.Unified.Guest"}
            $settingsCopy = $template.CreateDirectorySetting()
            $settingsCopy["AllowToAddGuests"] = $false
            $settings = New-AzureADObjectSetting -TargetType "Groups" -TargetObjectId $m365GroupId -DirectorySetting $settingsCopy
        }
        if ($settings["AllowToAddGuests"] -eq $true)
        {
            Write-Warning "Existing team guest settings changed to disable Guests"
            $settings["AllowToAddGuests"] = $false
            $settings = Set-AzureADObjectSetting -TargetType "Groups" -TargetObjectId $m365GroupId -Id $settings.Id -DirectorySetting $settings
        }
    }
}

#Processing Home Page
Write-Host "Processing Home Page" -ForegroundColor $CommandInfo
if ($overwritePages -and $homePageTemplate)
{
    #To export it: Export-PnPPage -Connection $siteCon -Force -Identity Home.aspx -Out $tempFile
    $tempFile = [System.IO.Path]::GetTempFileName()
    $homePageTemplate | Set-Content -Path $tempFile -Encoding UTF8
    $tmp = Invoke-PnPSiteTemplate -Connection $siteCon -Path $tempFile
    Remove-Item -Path $tempFile
}

# OneDrive Sync Url
Write-Host "OneDrive Sync Url" -ForegroundColor $CommandInfo
$site = Get-PnPSite -Connection $siteCon -Includes "ID"
$web = Get-PnPWeb -Connection $siteCon -Includes "ID","Title"
$list = Get-PnPList -Connection $siteCon | where { $_.Title -eq "Dokumente" -or $_.Title -eq "Freigegebene Dokumente" -or $_.Title -eq "Documents" -or $_.Title -eq "Shared Documents" }
$WebURL = [System.Web.HttpUtility]::UrlEncode("$($AlyaSharePointUrl)/sites/$title/")
$SiteID = [System.Web.HttpUtility]::UrlEncode("{$($site.Id.Guid)}")
$WebID = [System.Web.HttpUtility]::UrlEncode("{$($web.Id.Guid)}")
$ListID = [System.Web.HttpUtility]::UrlEncode("{$($list.Id.Guid)}")
$WebTitle = [System.Web.HttpUtility]::UrlEncode($web.Title)
$ListTitle = [System.Web.HttpUtility]::UrlEncode($list.Title)
$UserName = [System.Web.HttpUtility]::UrlEncode("xxxxxxxxxx@$AlyaDomainName")
Write-Host "odopen://sync?siteId=$SiteID&webId=$WebID&listId=$ListID&userEmail=$UserName&webUrl=$WebURL&webTitle=$WebTitle&listTitle=$ListTitle&scope=OPENLIST" -ForegroundColor DarkGreen

LogoutAllFrom-PnP

#Stopping Transscript
Stop-Transcript
