﻿#Requires -Version 7.0

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
    15.09.2020 Konrad Brunner       Initial Version
    15.02.2021 Konrad Brunner       Added locale selection and pages option
    10.08.2021 Konrad Brunner       Hub connection
    26.08.2021 Konrad Brunner       Support for Communication Sites
    07.07.2022 Konrad Brunner       New PnP Login and some fixes
    20.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules
    05.08.2023 Konrad Brunner       Added role admins
    04.09.2024 Konrad Brunner       Added overwritePagesOnlyOnHubs param

#>

[CmdletBinding()]
Param(
    [string]$siteLocale = "de-CH",
    [bool]$overwritePages = $false,
    [string[]]$overwritePagesOnlyOnHubs = @(),
    [string]$hubSitesConfigurationFile = $null,
    [bool]$createHubSitesOnly = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Configure-HubSites-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Logging in
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

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
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Configure-HubSites | O365" -ForegroundColor $CommandInfo
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

# Configuring hubs
foreach($hubSite in $hubSites)
{
    ###Processing site
    Write-Host "Processing site for Hub Site $($hubSite.title)" -ForegroundColor $TitleColor

    $site = $null
    $site = Get-PnPTenantSite -Connection $adminCon -Url "$($AlyaSharePointUrl)/sites/$($hubSite.url)" -Detailed -ErrorAction SilentlyContinue
    if (-Not $site)
    {
        Write-Warning "Hub site not found. Creating now hub site $($hubSite.title)"
        if ($hubSite.template -eq "TeamSite")
        {
            $site = New-PnPSite -Connection $adminCon -Type "TeamSite" -Title $hubSite.title -Alias "$($hubSite.url)" -Description $hubSite.description -Wait
        }
        else
        {
            $site = New-PnPSite -Connection $adminCon -Type $hubSite.template -Title $hubSite.title -Url "$($AlyaSharePointUrl)/sites/$($hubSite.url)" -Description $hubSite.description -Wait
        }
        do {
            Start-Sleep -Seconds 15
            $site = Get-PnPTenantSite -Connection $adminCon -Url "$($AlyaSharePointUrl)/sites/$($hubSite.url)" -Detailed -ErrorAction SilentlyContinue
        } while (-Not $site)
        Start-Sleep -Seconds 60
    }

    # Setting admin access
    Write-Host "Setting admin access" -ForegroundColor $TitleColor
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

    # Registering as hub
    if (-Not $site.IsHubSite)
    {
        Write-Host "Registering site as hub site"
        $siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
        $pSite = Get-PnPSite -Connection $siteCon
        Register-PnPHubSite -Connection $adminCon -Site $pSite
        $site = Get-PnPTenantSite -Connection $adminCon -Url "$($AlyaSharePointUrl)/sites/$($hubSite.url)" -Detailed -ErrorAction SilentlyContinue
    }
    
    # Registering to parent hub
    if ($hubSite.parent)
    {
        Write-Host "Registering to parent hub $($hubSite.parent)" -ForegroundColor $TitleColor
        Start-Sleep -Seconds 60
        $parHubSite = $hubSites | Where-Object { $_.short -eq $hubSite.parent }
        if (-Not $parHubSite)
        {
            throw "Hub site $($hubSite.parent) not found"
        }
        $hubSiteObj = Get-PnPHubSite -Connection $adminCon -Identity "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
        if (-Not $hubSiteObj)
        {
            throw "Hub site $($hubSite.short) not found"
        }
        $parSiteObj = Get-PnPHubSite -Connection $adminCon -Identity "$($AlyaSharePointUrl)/sites/$($parHubSite.url)"
        if (-Not $parSiteObj)
        {
            throw "Hub site $($hub) not found"
        }
        Add-PnPHubToHubAssociation -Connection $adminCon -Source $hubSiteObj.ID -Target $parSiteObj.ID
    }

    ###Processing designs
    Write-Host "Processing designs for Hub Site $($hubSite.title)" -ForegroundColor $TitleColor
    $SiteScriptName = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) HubSite SiteScript "+$siteLocale
    $SiteDesignNameTeam = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) HubSite Team Site "+$siteLocale
    $SiteDesignNameComm = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) HubSite Communication Site "+$siteLocale

    # Getting theme
    Write-Host "Getting theme" -ForegroundColor $CommandInfo
    $Theme = Get-PnPTenantTheme -Connection $adminCon -Name $themeName -ErrorAction SilentlyContinue
    if (-Not $Theme)
    {
        throw "Theme does not exist. Please create it first"
    }

    # Checking site script
    Write-Host "Checking site script" -ForegroundColor $CommandInfo
    $hubSite.siteScript = $hubSite.siteScript.Replace("##HUBSITEID##", $site.HubSiteId).Replace("##HUBSITENAME##", $hubSite.title)
    $SiteScript = Get-PnPSiteScript -Connection $adminCon | Where-Object { $_.Title -eq "$SiteScriptName"}
    if (-Not $SiteScript)
    {
        Write-Warning "Site script not found. Creating now site script $SiteScriptName"
        $SiteScript = Add-PnPSiteScript -Connection $adminCon -Title $SiteScriptName -Content $hubSite.siteScript -Description $hubSite.siteScriptDescription
    }
    else
    {
        Write-Host "Updating site script $SiteScriptName"
        $SiteScript = Set-PnPSiteScript -Connection $adminCon -Identity $SiteScript -Title $SiteScriptName -Content $hubSite.siteScript -Description $hubSite.siteScriptDescription
    }
    $SiteScript = Get-PnPSiteScript -Connection $adminCon | Where-Object { $_.Title -eq "$SiteScriptName"}

    # Checking site design
    Write-Host "Checking team site design" -ForegroundColor $CommandInfo
    $SiteDesignTeam = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SiteDesignNameTeam"}
    if (-Not $SiteDesignTeam)
    {
        Write-Warning "Team site design not found. Creating now team site design $SiteDesignNameTeam"
        $SiteDesignTeam = Add-PnPSiteDesign -Connection $adminCon -Title $SiteDesignNameTeam -WebTemplate "64" -SiteScript $SiteScript -Description $hubSite.siteScriptDescription
    }
    else
    {
        Write-Host "Updating Team site design $SiteDesignNameTeam"
        $SiteDesignTeam = Set-PnPSiteDesign -Connection $adminCon -Identity $SiteDesignTeam.Id -Title $SiteDesignNameTeam -WebTemplate "64" -SiteScriptIds $SiteScript.Id -Description $hubSite.siteScriptDescription
    }
    $SiteDesignTeam = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SiteDesignNameTeam"}

    # Checking site design
    Write-Host "Checking communication site design" -ForegroundColor $CommandInfo
    $SiteDesignComm = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SiteDesignNameComm"}
    if (-Not $SiteDesignComm)
    {
        Write-Warning "Communication site design not found. Creating now Communication site design $SiteDesignNameComm"
        $SiteDesignComm = Add-PnPSiteDesign -Connection $adminCon -Title $SiteDesignNameComm -WebTemplate "68" -SiteScript $SiteScript -Description $hubSite.siteScriptDescription
    }
    else
    {
        Write-Host "Updating Communication site design $SiteDesignNameComm"
        $SiteDesignComm = Set-PnPSiteDesign -Connection $adminCon -Identity $SiteDesignComm.Id -Title $SiteDesignNameComm -WebTemplate "68" -SiteScriptIds $SiteScript.Id -Description $hubSite.siteScriptDescription
    }
    $SiteDesignComm = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SiteDesignNameComm"}

    # Checking site script for sub sites
    if ($hubSite.subSiteScript)
    {
        $SubSiteScriptName = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) SubSite SiteScript "+$siteLocale
        $SubSiteDesignNameTeam = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) SubSite Team Site "+$siteLocale
        $SubSiteDesignNameComm = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) SubSite Communication Site "+$siteLocale

        # Checking site script for sub sites
        Write-Host "Checking site script for sub sites" -ForegroundColor $CommandInfo
        $hubSite.subSiteScript = $hubSite.subSiteScript.Replace("##HUBSITEID##", $site.HubSiteId).Replace("##HUBSITENAME##", $hubSite.title)
        $SubSiteScript = Get-PnPSiteScript -Connection $adminCon | Where-Object { $_.Title -eq "$SubSiteScriptName"}
        if (-Not $SubSiteScript)
        {
            Write-Warning "Site script not found. Creating now site script $SubSiteScriptName"
            $SubSiteScript = Add-PnPSiteScript -Connection $adminCon -Title $SubSiteScriptName -Content $hubSite.subSiteScript -Description $hubSite.siteScriptDescription
        }
        else
        {
            Write-Host "Updating site script $SubSiteScriptName"
            $null = Set-PnPSiteScript -Connection $adminCon -Identity $SubSiteScript -Title $SubSiteScriptName -Content $hubSite.subSiteScript -Description $hubSite.siteScriptDescription
            $SubSiteScript = Get-PnPSiteScript -Connection $adminCon | Where-Object { $_.Title -eq "$SubSiteScriptName"}
        }

        # Checking site design
        Write-Host "Checking team site design" -ForegroundColor $CommandInfo
        $SubSiteDesignTeam = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SubSiteDesignNameTeam"}
        if (-Not $SubSiteDesignTeam)
        {
            Write-Warning "Team site design not found. Creating now team site design $SubSiteDesignNameTeam"
            $SubSiteDesignTeam = Add-PnPSiteDesign -Connection $adminCon -Title $SubSiteDesignNameTeam -WebTemplate "64" -SiteScript $SubSiteScript -Description $hubSite.siteScriptDescription
        }
        else
        {
            Write-Host "Updating Team site design $SubSiteDesignNameTeam"
            $SubSiteDesignTeam = Set-PnPSiteDesign -Connection $adminCon -Identity $SubSiteDesignTeam.Id -Title $SubSiteDesignNameTeam -WebTemplate "64" -SiteScriptIds $SubSiteScript.Id -Description $hubSite.siteScriptDescription
        }
        $SubSiteDesignTeam = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SubSiteDesignNameTeam"}

        # Checking site design
        Write-Host "Checking communication site design" -ForegroundColor $CommandInfo
        $SubSiteDesignComm = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SubSiteDesignNameComm"}
        if (-Not $SubSiteDesignComm)
        {
            Write-Warning "Communication site design not found. Creating now Communication site design $SubSiteDesignNameComm"
            $SubSiteDesignComm = Add-PnPSiteDesign -Connection $adminCon -Title $SubSiteDesignNameComm -WebTemplate "68" -SiteScript $SubSiteScript -Description $hubSite.siteScriptDescription
        }
        else
        {
            Write-Host "Updating Communication site design $SubSiteDesignNameComm"
            $SubSiteDesignComm = Set-PnPSiteDesign -Connection $adminCon -Identity $SubSiteDesignComm.Id -Title $SubSiteDesignNameComm -WebTemplate "68" -SiteScriptIds $SubSiteScript.Id -Description $hubSite.siteScriptDescription
        }
        $SubSiteDesignComm = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SubSiteDesignNameComm"}
    }

    # Processing site design
    Write-Host "Processing site design for Hub Site $($hubSite.title)" -ForegroundColor $TitleColor
    if ($hubSite.template -eq "TeamSite")
    {
        Invoke-PnPSiteDesign -Connection $adminCon -Identity $SiteDesignTeam.Id -WebUrl "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
    }
    if ($hubSite.template -eq "CommunicationSite")
    {
        Invoke-PnPSiteDesign -Connection $adminCon -Identity $SiteDesignComm.Id -WebUrl "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
    }

    # Updating logo
	$siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
    $web = Get-PnPWeb -Connection $siteCon -Includes HeaderEmphasis,HeaderLayout,SiteLogoUrl,QuickLaunchEnabled
    $web.HeaderLayout = $hubSite.headerLayout
    $web.HeaderEmphasis = $hubSite.headerEmphasis
    $web.QuickLaunchEnabled = $false
    $web.Update()
    Invoke-PnPQuery -Connection $siteCon
    if ([string]::IsNullOrEmpty($web.SiteLogoUrl))
    {
        if ($hubSite.template -eq "TeamSite")
        {
            $fname = Split-Path -Path $hubSite.siteLogoUrl -Leaf
            $tempFile = [System.IO.Path]::GetTempFileName()+$fname
            Invoke-RestMethod -Method GET -UseBasicParsing -Uri $hubSite.siteLogoUrl -OutFile $tempFile
            Set-PnPSite -Connection $siteCon -LogoFilePath $tempFile
            Remove-Item -Path $tempFile
        }
        if ($hubSite.template -eq "CommunicationSite")
        {
            $web.SiteLogoUrl = $hubSite.siteLogoUrl
            $web.Update()
            Invoke-PnPQuery -Connection $siteCon
        }
    }

    # Processing external sharing
    Write-Host "Processing external sharing" -ForegroundColor $CommandInfo
    # None(Disabled), AdminOnly(ExistingExternalUserSharingOnly), KnownAccountsOnly(ExternalUserSharingOnly), ByLink(ExternalUserAndGuestSharing)
    $externalSharing = $AlyaSharingPolicy
    if ($hubSite.externalSharing -eq $false) { $externalSharing = "None" }
    switch($externalSharing)
    {
        "None" {
            Set-PnPTenantSite -Connection $adminCon -Identity "$($AlyaSharePointUrl)/sites/$($hubSite.url)" -SharingCapability Disabled
        }
        "AdminOnly" {
            Set-PnPTenantSite -Connection $adminCon -Identity "$($AlyaSharePointUrl)/sites/$($hubSite.url)" -SharingCapability  ExistingExternalUserSharingOnly
        }
        "KnownAccountsOnly" {
            Set-PnPTenantSite -Connection $adminCon -Identity "$($AlyaSharePointUrl)/sites/$($hubSite.url)" -SharingCapability  ExternalUserSharingOnly
        }
        "ByLink" {
            Set-PnPTenantSite -Connection $adminCon -Identity "$($AlyaSharePointUrl)/sites/$($hubSite.url)" -SharingCapability  ExternalUserAndGuestSharing
        }
    }
}

# Processing navigation
if (-Not $createHubSitesOnly)
{

    Write-Host "Processing navigation" -ForegroundColor $TitleColor
    foreach($hubSite in $hubSites)
    {
        if ($hubSite.short -ne "COL")
        {
            Write-Host "Hub Site $($hubSite.title)"
		    $siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
            $site = Get-PnPSite -Connection $siteCon
            $topNavs = Get-PnPNavigationNode -Connection $siteCon -Location TopNavigationBar
            foreach($hubSiteI in $hubSites)
            {
                if ($hubSiteI.url -ne $hubSite.url)
                {
                    $nav = $topNavs | Where-Object {$_.Title -eq $hubSiteI.title}
                    if (-Not $nav)
                    {
                        Write-Host ("Adding nav node title={0} url={1}" -f $hubSiteI.title, $hubSiteI.url)
                        $null = Add-PnPNavigationNode -Connection $siteCon -Location TopNavigationBar -Title $hubSiteI.title -Url "$($AlyaSharePointUrl)/sites/$($hubSiteI.url)"
                    }
                }
            }
        }
    }

}

# Processing designs for connected sites
if (-Not $createHubSitesOnly)
{

    Write-Host "Processing site designs for connected sites" -ForegroundColor $TitleColor
    foreach($hubSite in $hubSites)
    {
        if ($hubSite.subSiteScript)
        {
            Write-Host "Hub Site $($hubSite.title)"
            $SubSiteDesignNameTeam = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) SubSite Team Site "+$siteLocale
            $SubSiteDesignNameComm = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) SubSite Communication Site "+$siteLocale
            $SubSiteDesignTeam = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SubSiteDesignNameTeam"}
            $SubSiteDesignComm = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SubSiteDesignNameComm"}

            $adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl
            $hubSiteObj = Get-PnPHubSite -Connection $adminCon -Identity "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
            $childs = Get-PnPHubSiteChild -Connection $adminCon -Identity $hubSiteObj
            foreach($child in $childs)
            {
                try
                {
				    $siteCon = LoginTo-PnP -Url $child
                    $site = Get-PnPWeb -Connection $siteCon -Includes WebTemplate, Configuration
                    $template = $site.WebTemplate + "#" + $site.Configuration
                    if ($template -eq "GROUP#0")
                    {
                        Invoke-PnPSiteDesign -Connection $adminCon -Identity $SubSiteDesignTeam.Id -WebUrl $child
                    }
                    if ($template -eq "SITEPAGEPUBLISHING#0")
                    {
                        Invoke-PnPSiteDesign -Connection $adminCon -Identity $SubSiteDesignComm.Id -WebUrl $child
                    }
                    if ($template -ne "GROUP#0" -and $template -ne "SITEPAGEPUBLISHING#0")
                    {
                        Write-Warning "Dont know how to handle site template $template"
                    }
                } catch
                {
                    Write-Error $_
                }
            }
        }
    }

}

# SharePoint Home Featured Links
if (-Not $createHubSitesOnly)
{

    Write-Host "Processing SharePoint Home Featured Links" -ForegroundColor $TitleColor
    $siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)"
    $list = Get-PnPList -Connection $siteCon -Identity "SharePointHomeOrgLinks"
    if (-Not $list)
    {
        Write-Warning "Looks like noone has started once the SharePoint start page."
        Write-Warning "The links list will only be created after first access."
        Write-Warning "Please access once the start page: $($AlyaSharePointUrl)/_layouts/15/sharepoint.aspx"
        Start-Process "$($AlyaSharePointUrl)"
        pause
        $list = Get-PnPList -Connection $siteCon -Identity "SharePointHomeOrgLinks"
    }
    $items = Get-PnPListItem -Connection $siteCon -List $list -Fields "Title","Url","Priority","GUID"
    foreach($hubSite in $hubSites)
    {
        $fnd = $false
        foreach($item in $items)
        {
            if ($item["Title"] -eq $hubSite.title)
            {
                $fnd = $true
                break
            }
        }
        if (-Not $fnd)
        {
            Write-Host "Adding $($hubSite.title)"
            Add-PnPListItem -Connection $siteCon -List $list -Values @{"Title"=$hubSite.title; "Url"="$($AlyaSharePointUrl)/sites/$($hubSite.url)"; "MobileAppVisible"=$true; "Priority"=1000 }
        }
        else
        {
            Write-Host "Already there $($hubSite.title)"
        }
    }

}

# Configuring root site design
if (-Not $createHubSitesOnly)
{

    Write-Host "Configuring root site title" -ForegroundColor $TitleColor
    $adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl
    Set-PnpTenantSite -Connection $adminCon -Identity "$($AlyaSharePointUrl)" -Title "$($AlyaCompanyNameShortM365.ToUpper())SP"
    $siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)"
    $web = Get-PnPWeb -Connection $siteCon -Includes HeaderEmphasis,HeaderLayout,SiteLogoUrl,QuickLaunchEnabled
    $web.HeaderLayout = $rootSiteHeaderLayout
    $web.HeaderEmphasis = $rootSiteHeaderEmphasis
    $web.QuickLaunchEnabled = $rootSiteQuickLaunchEnabled
    $web.Update()
    Invoke-PnPQuery -Connection $siteCon
    if ([string]::IsNullOrEmpty($web.SiteLogoUrl))
    {
        if ($web.WebTemplate -eq "SITEPAGEPUBLISHING")
        {
            $web.SiteLogoUrl = $rootSiteSiteLogoUrl
            $web.Update()
            Invoke-PnPQuery -Connection $siteCon
        }
        else
        {
            $fname = Split-Path -Path $rootSiteSiteLogoUrl -Leaf
            $tempFile = [System.IO.Path]::GetTempFileName()+$fname
            Invoke-RestMethod -Method GET -UseBasicParsing -Uri $rootSiteSiteLogoUrl -OutFile $tempFile
            Set-PnPSite -Connection $siteCon -LogoFilePath $tempFile
            Remove-Item -Path $tempFile
        }
    }
    $SiteDesignNameTeam = "$($AlyaCompanyNameShortM365.ToUpper())SP Default Team Site"
    $SiteDesignNameComm = "$($AlyaCompanyNameShortM365.ToUpper())SP Default Communication Site"
    $SiteDesignTeam = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SiteDesignNameTeam"}
    $SiteDesignComm = Get-PnPSiteDesign -Connection $adminCon | Where-Object { $_.Title -eq "$SiteDesignNameComm"}
    if ($web.WebTemplate -eq "SITEPAGEPUBLISHING")
    {
        Invoke-PnPSiteDesign -Connection $adminCon -Identity $SiteDesignComm.Id -WebUrl "$($AlyaSharePointUrl)"
    }
    else
    {
        Invoke-PnPSiteDesign -Connection $adminCon -Identity $SiteDesignTeam.Id -WebUrl "$($AlyaSharePointUrl)"
    }

}

# Configuring access to hub and root sites
Write-Host "Configuring access to hub and root sites" -ForegroundColor $TitleColor
foreach($hubSite in $hubSites)
{
    #$hubSite = $hubSites[0]
	$siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
    $group = Get-PnPGroup -Connection $siteCon -AssociatedVisitorGroup
    $agroup = Get-PnPMicrosoft365Group -Connection $adminCon -Identity $AlyaAllInternals
    Add-PnPGroupMember -Connection $siteCon -Group $group -LoginName "c:0o.c|federateddirectoryclaimprovider|$($agroup.Id)"
    if ($hubSite.short -eq "COL")
    {
        $agroup = Get-PnPMicrosoft365Group -Connection $adminCon -Identity $AlyaAllExternals
        Add-PnPGroupMember -Connection $siteCon -Group $group -LoginName "c:0o.c|federateddirectoryclaimprovider|$($agroup.Id)"
    }
}
if (-Not $createHubSitesOnly)
{
    $siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)"
    $vgroup = Get-PnPGroup -Connection $siteCon -AssociatedVisitorGroup
    $agroup = Get-PnPMicrosoft365Group -Connection $adminCon -Identity $AlyaAllInternals
    Add-PnPGroupMember -Connection $siteCon -Group $vgroup -LoginName "c:0o.c|federateddirectoryclaimprovider|$($agroup.Id)"
    $agroup = Get-PnPMicrosoft365Group -Connection $adminCon -Identity $AlyaAllExternals
    Add-PnPGroupMember -Connection $siteCon -Group $vgroup -LoginName "c:0o.c|federateddirectoryclaimprovider|$($agroup.Id)"
    $mgroup = Get-PnPGroup -Connection $siteCon -AssociatedMemberGroup
    $members = Get-PnPGroupMember -Connection $siteCon -Group $mgroup
    foreach($member in $members)
    {
        if ($member.LoginName.Contains("spo-grid-all-users"))
        {
            Remove-PnPGroupMember -Connection $siteCon -Group $mgroup -LoginName $member.LoginName
        }
    }
}

# Processing Hub Site Start Pages
if (-Not $createHubSitesOnly)
{

    Write-Host "Processing Hub Site Start Pages" -ForegroundColor $TitleColor
    if ($overwritePages -or ($null -ne $overwritePagesOnlyOnHubs -and $overwritePagesOnlyOnHubs.Count -gt 0))
    {

        #Set-PnPTraceLog -On -WriteToConsole -Level Debug
        #To export it: Export-PnPClientSidePage -Force -Identity Home.aspx -Out $tempFile
        foreach($hubSite in $hubSites)
        {
            #$hubSite = $hubSites[0]
            if ($null -ne $overwritePagesOnlyOnHubs -and $overwritePagesOnlyOnHubs.Count -gt 0 -and `
                $hubSite.short -notin $overwritePagesOnlyOnHubs)
            {
                continue
            }
		    $siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
            $tempFile = [System.IO.Path]::GetTempFileName()
            $hubSite.homePageTemplate | Set-Content -Path $tempFile -Encoding UTF8
            $null = Invoke-PnPSiteTemplate -Connection $siteCon -Path $tempFile
            Remove-Item -Path $tempFile
        }
        #Set-PnPTraceLog -Off

        if ($overwritePages)
        {
            ###Processing Root Site Start Page
            $siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)"
            if ($homePageTemplateRootTeamSite) # defined in hub def script
            {
                Write-Host "Processing Root Site Start Page" -ForegroundColor $TitleColor
                $tempFile = [System.IO.Path]::GetTempFileName()
                $homePageTemplateRootTeamSite | Set-Content -Path $tempFile -Encoding UTF8
                $null = Invoke-PnPSiteTemplate -Connection $siteCon -Path $tempFile
                Remove-Item -Path $tempFile
            }
        }
    }

}

# Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCnxKJ7rWwXUMyK
# KXs7hJlZ57dOGhTBvBMi3jMKhlG7MqCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINPUkBWZ9OO/PyMy
# 32i41rkyKh97SeV+8TltU31ly711MA0GCSqGSIb3DQEBAQUABIICAFTF1bvz6Wop
# kpx1X9II6Fc9BNCgJouIxJ1ysMYhMHW2F5qk7klBZwPSwCEbxL67dTkNcuJkHtqW
# btnHQIm37LE1UsqfN+gGIZZ7gcS/h3wCRtfkdELj9S6LLD7Rimpp7HGf8K4iYyEw
# 25lNth56S+V1AVhzTNdLotPYsE5ZBi2wuB5v9uaDqjDwdxHcF4viLxcEDDJGZPEZ
# /vqcUUca0i8mLV+unYe42ATJZmoJGR41zrO1KXWZU4qvm7g980EqXo7v4ZJpv3st
# azm5aKzOJcLTmCVljHRYvVLI0TUhcp/TpIoQWpPdRkS5q3RVcY3XgnLCuv0225A8
# J7xl83nhUd+oafy3RHwROuXKhJdjhZ11fCpsk5fzQmToJe7wJE7o3MAABtk1lmHj
# G/7lwa81KQvXk42vhrQhfeK3ttDBCsQxamTZ/4QRuEGwszcp8Dy/U9/mHXbjykWs
# MUCBbQ48faZ040sYCPWDATon0sSb/kv8txFLotOOvrhpHpg7KwLTIqVD8MmjJ77q
# vbP/rSlBP9NPbhzuumd6v6gvI/qGG02tsdTZj5jj0USTBT6LbE26ULNhEJWYyvFJ
# KAYILeGUnG8OqeUQuzfnSY2AYlsyaptpkzd39jHQ/rWXZWV2MqOACCM7owi0cGY/
# k7/f7u6+7g3Dq8VLhJL9ew5eRPEjDpYYoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCBiqR9Oy5SfkFE8B4wEkvbI91rjO4fsQyH2Fv6+NbA9eQIUP9vku8PTg0YT
# LxPyftSoojh/dAUYDzIwMjUwNTI2MTkyNDA0WjADAgEBoFikVjBUMQswCQYDVQQG
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
# IHTNi4YdsSaboAqzRCiAl4AlZqCJTmv+0xkG58pgOFZIMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAJ0Yc+tg5sRn3
# /35x8wDIqMfb0JoTkQwKa8ay7EeWUjlo+4vlNadHALxreYm/98+S+psQ9A/fwe9M
# O84GM/sT/vLMxuLCRT24qNVPxqSVgVbj4SVcTdBrw9Epivfjcj3ZO3pXDAFwkKpB
# gmO8lASCFQvFKD6gvYFR5fVygoAYE18DWQEFXRSd7FAOwgdK9i8XGZ4kgQY4N+fl
# oKgX89hHY9EDTmwy4oZ+7s8FQyxvOmiL2KOv+OFgYYkMXPu1u8gQgVLu3tPDPpu/
# swqfksnyVmNXKSvqoI7EY1PE8q2L2JMz3qsFG7zmJiZk0Fzqw/jMRyNr45rRYr4u
# TVc7uq0wCC9NCLmVf6kUHJU/9RW/yjZjbUCjflosTcPhjSN5fB8BTk7fqOD0Kwve
# RFckeM/l1YIbp8iZdw56ejXNjYmtJK4deeouwfO4lepFlK+Az+tKBDEl0QoGXcY4
# b6kY7qbBoCzwCsg/33Kr6dlu+GoiFUkIx2ec5Rh2i9WaNOlgukfR
# SIG # End signature block
