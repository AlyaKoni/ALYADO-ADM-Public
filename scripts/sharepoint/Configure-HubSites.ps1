#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2021

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
    15.09.2020 Konrad Brunner       Initial Version
    15.02.2021 Konrad Brunner       Added locale selection and pages option
    10.08.2021 Konrad Brunner       Hub connection
    26.08.2021 Konrad Brunner       Support for Communication Sites
    07.07.2022 Konrad Brunner       New PnP Login and some fixes

#>

[CmdletBinding()]
Param(
    $siteLocale = "de-CH",
    $overwritePages = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Configure-HubSites-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "AzureAdPreview"
Install-ModuleIfNotInstalled "Microsoft.Online.Sharepoint.PowerShell"
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Logging in
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad
LoginTo-SPO

# Constants
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

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Configure-HubSites | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

foreach($hubSite in $hubSites)
{
    ###Processing site
    Write-Host "Processing site for Hub Site $($hubSite.title)" -ForegroundColor $TitleColor

    $site = $null
    try { $site = Get-SPOSite -Identity "$($AlyaSharePointUrl)/sites/$($hubSite.url)" -Detailed -ErrorAction SilentlyContinue } catch {}
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
            try { $site = Get-SPOSite -Identity "$($AlyaSharePointUrl)/sites/$($hubSite.url)" -Detailed -ErrorAction SilentlyContinue } catch {}
        } while (-Not $site)
        Start-Sleep -Seconds 60
    }
    $site = Get-SPOSite -Identity "$($AlyaSharePointUrl)/sites/$($hubSite.url)" -Detailed
    foreach ($usrEmail in $AlyaSharePointNewSiteCollectionAdmins)
    {
        $tmp = Set-SPOUser -Site $Site -LoginName $usrEmail -IsSiteCollectionAdmin $True
    }
    $tmp = Set-SPOUser -Site $Site -LoginName $AlyaSharePointNewSiteOwner -IsSiteCollectionAdmin $True
    $tmp = Set-SPOSite -Identity $Site -Owner $AlyaSharePointNewSiteOwner
    if (-Not $site.IsHubSite)
    {
        Write-Host "Registering site as hub site"
        $siteReg = Register-SPOHubSite -Site "$($AlyaSharePointUrl)/sites/$($hubSite.url)" -Principals $null
        #TODO Principals
        Start-Sleep -Seconds 60
        $site = Get-SPOSite -Identity "$($AlyaSharePointUrl)/sites/$($hubSite.url)" -Detailed
    }
    
    ###Processing designs
    Write-Host "Processing designs for Hub Site $($hubSite.title)" -ForegroundColor $TitleColor

    $SiteScriptName = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) HubSite SiteScript "+$siteLocale
    $SiteDesignNameTeam = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) HubSite Team Site "+$siteLocale
    $SiteDesignNameComm = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) HubSite Communication Site "+$siteLocale

    # Getting theme
    Write-Host "Getting theme" -ForegroundColor $CommandInfo
    try { $Theme = Get-SPOTheme -Name $themeName -ErrorAction SilentlyContinue } catch {}
    if (-Not $Theme)
    {
        throw "Theme does not exist. Please create it first"
    }

    # Checking site script
    Write-Host "Checking site script" -ForegroundColor $CommandInfo
    $hubSite.siteScript = $hubSite.siteScript.Replace("##HUBSITEID##", $site.HubSiteId).Replace("##HUBSITENAME##", $hubSite.title)
    $SiteScript = Get-SPOSiteScript | where { $_.Title -eq "$SiteScriptName"}
    if (-Not $SiteScript)
    {
        Write-Warning "Site script not found. Creating now site script $SiteScriptName"
        $SiteScript = Add-SPOSiteScript -Title $SiteScriptName -Content $hubSite.siteScript -Description $hubSite.siteScriptDescription
    }
    else
    {
        Write-Host "Updating site script $SiteScriptName"
        $tmp = Set-SPOSiteScript -Identity $SiteScript -Title $SiteScriptName -Content $hubSite.siteScript -Description $hubSite.siteScriptDescription
        $SiteScript = Get-SPOSiteScript | where { $_.Title -eq "$SiteScriptName"}
    }

    # Checking site design
    Write-Host "Checking team site design" -ForegroundColor $CommandInfo
    $SiteDesignTeam = Get-SPOSiteDesign | where { $_.Title -eq "$SiteDesignNameTeam"}
    if (-Not $SiteDesignTeam)
    {
        Write-Warning "Team site design not found. Creating now team site design $SiteDesignNameTeam"
        $SiteDesignTeam = Add-SPOSiteDesign -Title $SiteDesignNameTeam -WebTemplate "64" -SiteScripts $SiteScript.Id -Description $hubSite.siteScriptDescription
    }
    else
    {
        Write-Host "Updating Team site design $SiteDesignNameTeam"
        $tmp = Set-SPOSiteDesign -Identity $SiteDesignTeam -Title $SiteDesignNameTeam -WebTemplate "64" -SiteScripts $SiteScript.Id -Description $hubSite.siteScriptDescription
        $SiteDesignTeam = Get-SPOSiteDesign | where { $_.Title -eq "$SiteDesignNameTeam"}
    }

    # Checking site design
    Write-Host "Checking communication site design" -ForegroundColor $CommandInfo
    $SiteDesignComm = Get-SPOSiteDesign | where { $_.Title -eq "$SiteDesignNameComm"}
    if (-Not $SiteDesignComm)
    {
        Write-Warning "Communication site design not found. Creating now Communication site design $SiteDesignNameComm"
        $SiteDesignComm = Add-SPOSiteDesign -Title $SiteDesignNameComm -WebTemplate "68" -SiteScripts $SiteScript.Id -Description $hubSite.siteScriptDescription
    }
    else
    {
        Write-Host "Updating Communication site design $SiteDesignNameComm"
        $tmp = Set-SPOSiteDesign -Identity $SiteDesignComm -Title $SiteDesignNameComm -WebTemplate "68" -SiteScripts $SiteScript.Id -Description $hubSite.siteScriptDescription
        $SiteDesignComm = Get-SPOSiteDesign | where { $_.Title -eq "$SiteDesignNameComm"}
    }

    # Checking site script for sub sites
    if ($hubSite.subSiteScript)
    {
        $SubSiteScriptName = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) SubSite SiteScript "+$siteLocale
        $SubSiteDesignNameTeam = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) SubSite Team Site "+$siteLocale
        $SubSiteDesignNameComm = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) SubSite Communication Site "+$siteLocale

        # Checking site script
        Write-Host "Checking site script" -ForegroundColor $CommandInfo
        $hubSite.subSiteScript = $hubSite.subSiteScript.Replace("##HUBSITEID##", $site.HubSiteId).Replace("##HUBSITENAME##", $hubSite.title)
        $SubSiteScript = Get-SPOSiteScript | where { $_.Title -eq "$SubSiteScriptName"}
        if (-Not $SubSiteScript)
        {
            Write-Warning "Site script not found. Creating now site script $SubSiteScriptName"
            $SubSiteScript = Add-SPOSiteScript -Title $SubSiteScriptName -Content $hubSite.subSiteScript -Description $hubSite.siteScriptDescription
        }
        else
        {
            Write-Host "Updating site script $SubSiteScriptName"
            $tmp = Set-SPOSiteScript -Identity $SubSiteScript -Title $SubSiteScriptName -Content $hubSite.subSiteScript -Description $hubSite.siteScriptDescription
            $SubSiteScript = Get-SPOSiteScript | where { $_.Title -eq "$SubSiteScriptName"}
        }

        # Checking site design
        Write-Host "Checking team site design" -ForegroundColor $CommandInfo
        $SubSiteDesignTeam = Get-SPOSiteDesign | where { $_.Title -eq "$SubSiteDesignNameTeam"}
        if (-Not $SubSiteDesignTeam)
        {
            Write-Warning "Team site design not found. Creating now team site design $SubSiteDesignNameTeam"
            $SubSiteDesignTeam = Add-SPOSiteDesign -Title $SubSiteDesignNameTeam -WebTemplate "64" -SiteScripts $SubSiteScript.Id -Description $hubSite.siteScriptDescription
        }
        else
        {
            Write-Host "Updating Team site design $SubSiteDesignNameTeam"
            $tmp = Set-SPOSiteDesign -Identity $SubSiteDesignTeam -Title $SubSiteDesignNameTeam -WebTemplate "64" -SiteScripts $SubSiteScript.Id -Description $hubSite.siteScriptDescription
            $SubSiteDesignTeam = Get-SPOSiteDesign | where { $_.Title -eq "$SubSiteDesignNameTeam"}
        }

        # Checking site design
        Write-Host "Checking communication site design" -ForegroundColor $CommandInfo
        $SubSiteDesignComm = Get-SPOSiteDesign | where { $_.Title -eq "$SubSiteDesignNameComm"}
        if (-Not $SubSiteDesignComm)
        {
            Write-Warning "Communication site design not found. Creating now Communication site design $SubSiteDesignNameComm"
            $SubSiteDesignComm = Add-SPOSiteDesign -Title $SubSiteDesignNameComm -WebTemplate "68" -SiteScripts $SubSiteScript.Id -Description $hubSite.siteScriptDescription
        }
        else
        {
            Write-Host "Updating Communication site design $SubSiteDesignNameComm"
            $tmp = Set-SPOSiteDesign -Identity $SubSiteDesignComm -Title $SubSiteDesignNameComm -WebTemplate "68" -SiteScripts $SubSiteScript.Id -Description $hubSite.siteScriptDescription
            $SubSiteDesignComm = Get-SPOSiteDesign | where { $_.Title -eq "$SubSiteDesignNameComm"}
        }
    }

    ###Processing site design
    Write-Host "Processing site design for Hub Site $($hubSite.title)" -ForegroundColor $TitleColor

    if ($hubSite.template -eq "TeamSite")
    {
        Invoke-SPOSiteDesign -Identity $SiteDesignTeam.Id -WebUrl "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
    }
    if ($hubSite.template -eq "CommunicationSite")
    {
        Invoke-SPOSiteDesign -Identity $SiteDesignComm.Id -WebUrl "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
    }

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
}

###Processing navigation
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
                $nav = $topNavs | where {$_.Title -eq $hubSiteI.title}
                if (-Not $nav)
                {
                    Write-Host ("Adding nav node title={0} url={1}" -f $hubSiteI.title, $hubSiteI.url)
                    $tmp = Add-PnPNavigationNode -Connection $siteCon -Location TopNavigationBar -Title $hubSiteI.title -Url "$($AlyaSharePointUrl)/sites/$($hubSiteI.url)"
                }
            }
        }
    }
}

###Processing designs for connected sites
Write-Host "Processing site designs for connected sites" -ForegroundColor $TitleColor
foreach($hubSite in $hubSites)
{
    if ($hubSite.subSiteScript)
    {
        Write-Host "Hub Site $($hubSite.title)"
        $SubSiteDesignNameTeam = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) SubSite Team Site "+$siteLocale
        $SubSiteDesignNameComm = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSite.short) SubSite Communication Site "+$siteLocale
        $SubSiteDesignTeam = Get-SPOSiteDesign | where { $_.Title -eq "$SubSiteDesignNameTeam"}
        $SubSiteDesignComm = Get-SPOSiteDesign | where { $_.Title -eq "$SubSiteDesignNameComm"}

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
                    Invoke-SPOSiteDesign -Identity $SubSiteDesignTeam.Id -WebUrl $child
                }
                if ($template -eq "SITEPAGEPUBLISHING#0")
                {
                    Invoke-SPOSiteDesign -Identity $SubSiteDesignComm.Id -WebUrl $child
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

###SharePoint Home Featured Links
Write-Host "Processing SharePoint Home Featured Links" -ForegroundColor $TitleColor
$siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)"
$list = Get-PnPList -Connection $siteCon -Identity "SharePointHomeOrgLinks"
$items = Get-PnPListItem -Connection $siteCon -List $list -Fields "Title","Url"
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

###Configuring root site design
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
$SiteDesignTeam = Get-SPOSiteDesign | where { $_.Title -eq "$SiteDesignNameTeam"}
$SiteDesignComm = Get-SPOSiteDesign | where { $_.Title -eq "$SiteDesignNameComm"}
if ($web.WebTemplate -eq "SITEPAGEPUBLISHING")
{
    Invoke-SPOSiteDesign -Identity $SiteDesignComm.Id -WebUrl "$($AlyaSharePointUrl)"
}
else
{
    Invoke-SPOSiteDesign -Identity $SiteDesignTeam.Id -WebUrl "$($AlyaSharePointUrl)"
}

###Configuring access to hub and root sites
Write-Host "Configuring access to hub and root sites" -ForegroundColor $TitleColor
foreach($hubSite in $hubSites)
{
    #$hubSite = $hubSites[0]
	$siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
    $group = Get-PnPGroup -Connection $siteCon -AssociatedVisitorGroup
    $site = Get-SPOSite -Identity "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
    Add-SPOUser -Site $site -Group $group.Title -LoginName "$AlyaAllInternals@$AlyaDomainName"
    if ($hubSite.short -eq "COL")
    {
        Add-SPOUser -Site $site -Group $group.Title -LoginName "$AlyaAllExternals@$AlyaDomainName"
    }
}
$siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)"
$group = Get-PnPGroup -Connection $siteCon -AssociatedVisitorGroup
$site = Get-SPOSite -Identity "$($AlyaSharePointUrl)"
Add-SPOUser -Site $site -Group $group.Title -LoginName "$AlyaAllInternals@$AlyaDomainName"
Add-SPOUser -Site $site -Group $group.Title -LoginName "$AlyaAllExternals@$AlyaDomainName"

###Processing Hub Site Start Pages

#ATTENTION: Invoke-PnPSiteTemplate runs into an error if this code runs from start
#           Looks like dll hell. Some dll is loaded which has a missing function
#           Still trying to unload that dll
try { $null = Disconnect-SPOService -ErrorAction SilentlyContinue } catch{}
try { $null = Disconnect-AzureAD } catch{}
LogoutFrom-Az
Remove-Module Microsoft.Online.SharePoint.PowerShell -Force -ErrorAction SilentlyContinue
Remove-Module AzureADPreview -Force -ErrorAction SilentlyContinue
Remove-Module Az.Resources -Force -ErrorAction SilentlyContinue
Remove-Module Az.Accounts -Force -ErrorAction SilentlyContinue

if ($overwritePages)
{

    #Set-PnPTraceLog -On -WriteToConsole -Level Debug
    #To export it: Export-PnPClientSidePage -Force -Identity Home.aspx -Out $tempFile
    Write-Host "Processing Hub Site Start Pages" -ForegroundColor $TitleColor
    foreach($hubSite in $hubSites)
    {
        #$hubSite = $hubSites[0]
		$siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)/sites/$($hubSite.url)"
        $tempFile = [System.IO.Path]::GetTempFileName()
        $hubSite.homePageTemplate | Set-Content -Path $tempFile -Encoding UTF8
        $tmp = Invoke-PnPSiteTemplate -Connection $siteCon -Path $tempFile
        Remove-Item -Path $tempFile
    }
    #Set-PnPTraceLog -Off

    ###Processing Root Site Start Page
	$siteCon = LoginTo-PnP -Url "$($AlyaSharePointUrl)"
    if ($homePageTemplateRootTeamSite) # defined in hub def script
    {
        Write-Host "Processing Root Site Start Page" -ForegroundColor $TitleColor
        $tempFile = [System.IO.Path]::GetTempFileName()
        $homePageTemplateRootTeamSite | Set-Content -Path $tempFile -Encoding UTF8
        $tmp = Invoke-PnPSiteTemplate -Connection $siteCon -Path $tempFile
        Remove-Item -Path $tempFile
    }
}

LogoutAllFrom-PnP

#Stopping Transscript
Stop-Transcript