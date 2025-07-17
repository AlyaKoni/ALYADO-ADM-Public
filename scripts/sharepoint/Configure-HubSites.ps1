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
    15.09.2020 Konrad Brunner       Initial Version
    15.02.2021 Konrad Brunner       Added locale selection and pages option
    10.08.2021 Konrad Brunner       Hub connection
    26.08.2021 Konrad Brunner       Support for Communication Sites
    07.07.2022 Konrad Brunner       New PnP Login and some fixes
    20.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules
    05.08.2023 Konrad Brunner       Added role admins
    04.09.2024 Konrad Brunner       Added overwritePagesOnlyOnHubs param
    08.07.2025 Konrad Brunner       Added CompanyName param

#>

[CmdletBinding()]
Param(
    [string]$siteLocale = "de-CH",
    [bool]$overwritePages = $false,
    [string[]]$overwritePagesOnlyOnHubs = @(),
    [string]$hubSitesConfigurationFile = $null,
    [bool]$createHubSitesOnly = $false,
    [bool]$doNotProcessRootSite = $false,
    [string]$CompanyName = $null
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
if ([string]::IsNullOrEmpty($CompanyName))
{
    $CompanyName = $AlyaCompanyNameShortM365
}

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
    $SiteScriptName = "$($CompanyName.ToUpper())SP $($hubSite.short) HubSite SiteScript "+$siteLocale
    $SiteDesignNameTeam = "$($CompanyName.ToUpper())SP $($hubSite.short) HubSite Team Site "+$siteLocale
    $SiteDesignNameComm = "$($CompanyName.ToUpper())SP $($hubSite.short) HubSite Communication Site "+$siteLocale

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
        $SubSiteScriptName = "$($CompanyName.ToUpper())SP $($hubSite.short) SubSite SiteScript "+$siteLocale
        $SubSiteDesignNameTeam = "$($CompanyName.ToUpper())SP $($hubSite.short) SubSite Team Site "+$siteLocale
        $SubSiteDesignNameComm = "$($CompanyName.ToUpper())SP $($hubSite.short) SubSite Communication Site "+$siteLocale

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
            $SubSiteDesignNameTeam = "$($CompanyName.ToUpper())SP $($hubSite.short) SubSite Team Site "+$siteLocale
            $SubSiteDesignNameComm = "$($CompanyName.ToUpper())SP $($hubSite.short) SubSite Communication Site "+$siteLocale
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
if (-Not $createHubSitesOnly -and -not $doNotProcessRootSite)
{

    Write-Host "Configuring root site title" -ForegroundColor $TitleColor
    $adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl
    Set-PnpTenantSite -Connection $adminCon -Identity "$($AlyaSharePointUrl)" -Title "$($CompanyName.ToUpper())SP"
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
    $SiteDesignNameTeam = "$($CompanyName.ToUpper())SP Default Team Site"
    $SiteDesignNameComm = "$($CompanyName.ToUpper())SP Default Communication Site"
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
Write-Host "Configuring access to hub sites" -ForegroundColor $TitleColor
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
if (-Not $createHubSitesOnly -and -not $doNotProcessRootSite)
{
    Write-Host "Configuring access to root site" -ForegroundColor $TitleColor
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

        if ($overwritePages -and -not $doNotProcessRootSite)
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
# MIIvCQYJKoZIhvcNAQcCoIIu+jCCLvYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCbvR3oeOLSBZc2
# U+l4nl80wJVn4Iomco/C/QPFrjoCP6CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFiJKXvH
# bttpfG/BnlO+F8Y2LP6E+6tG5hp5601xFW7eMA0GCSqGSIb3DQEBAQUABIICAIVL
# hNKh0Q0hLzTK07L/LYWTiqo/p9Zaje/IcaHoSKcelt4b1kudQS3OUe1dUonwdrPK
# swKgxQO/dVKo0g/s1I0qhUWh4AQJI9uY3do+0U9fNa4frwRJWwaHKT4+vYT+mkQG
# r0k4FPYM1CEPVZXPtDaIpPqqXCXqfy6frPsG1M9r2XT1BeT67Orr5EeBfJcwMnOC
# 9HUrsF1h8gg0/5KIr/qLVzxEoqWgT7PxUnFqPYrm6FQlAJgKNGnur3jvA/GTSxoB
# TTxOgl21MP2gRrGjY+SdPGoP8F5bX80uchDi6Nj0p/1bLVVjBjffwg395f8ap8Hl
# EeUsSv168SLnXkdDjBDF4NazddUQVjzgv4Js2S3+gW0wkh1lJ4f32UHYOmiYUh02
# C2ayX7scC1bpUVZyoByQrep4p0HVG/kXSxV14HbInX8RPkXhiW7dYDnKPsig1bk/
# uzipa5TQ2YE6tW1Zt1FxBIp/yMaxvN4bny1SPHrjN9zqFqQFSVYUFpf/9yr98ONn
# 0E7UfwQ5gGNk2lWe1LL3/bm2/Fet+wvx3KXt0Gj5h5lGEthsBWFWi5DXD7RhlDVw
# yDNysx1Ld/K2GSqzLP/d3O07I6+rvDRsGuVSm0/kQF4D0rWqLSrL8mcIXlAUhz/j
# LvU7FLNYu/EgvaW0wTh9ebpcqJYvTAQtrq/dLfCloYIWuzCCFrcGCisGAQQBgjcD
# AwExghanMIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEw
# gd8GCyqGSIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCAwsqJH/vcDawHYFilQdHawWsdQS0qJDI6vdhvBziTFUwIUD/Fh
# PCTh90Y9FUiiMCLmp+LunxUYDzIwMjUwNzExMjAzNTQ4WjADAgEBoFikVjBUMQsw
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
# AQkEMSIEIAUtRcpELBGZl+hlxmSPwpXRRiXOKUbYeQPHOzmbupb3MIGwBgsqhkiG
# 9w0BCRACLzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1or
# d69gXP0wczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hB
# Mzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGABl21
# 6VXHStmGPDK3UwUH34GKV5I31TVyOAiDCajCJ4FEdBQaKa/9Pwnxcj3eJu/38ii9
# Cbw6Afy83lqMT5yVPYYglRA7pbVmlSkIoBmYrs4w6h7x0vf2Lyj3OVyaWo35KkvH
# IpgODony8NoIT3hK62m6f4icCdxxMleRjPt9a3LxHK2Wfre84H5fvXZGijv9sGBv
# ciLwkPDAvzlnOS9+vr9agNCUvdStjt+XLwnYUBKSsIA7NyrGs2uS76vixYB8DIAY
# IFUadMpwjZlFNSzcgX/rfR92AEXCly2zRv0x1yN4gzwGIcbuc9+bbpaD0WkGpyaA
# fHMfnJjrOWDfZMsW3bva+JDV0MA4+n63GM5poJ7Satqozp3O0OwmnSVW6vbm8j/z
# pwKJoRaFPciUlBPUS89ECXSzXss35xdNVJPH8SpfFjJ3Le5i/ZxrWqJtzaAY8Aqm
# uRXT1QfECm/7LxOaWFHAEdRWfQ+Tq03UPecPES/N9OwF12YjLolwMdePeHhl
# SIG # End signature block
