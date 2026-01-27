#Requires -Version 7.0

<#
    Copyright (c) Alya Consulting, 2019-2026

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
    26.01.2026 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$siteLocale = "de-CH",
    [string]$hubSitesConfigurationFile = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Configure-AssetLibrarySite-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Members
if ([string]::IsNullOrEmpty($multiGeoAdminUrl))
{
    $multiGeoAdminUrl = $AlyaSharePointAdminUrl
}

# Logging in
$adminCon = LoginTo-PnP -Url $multiGeoAdminUrl

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
Write-Host "SharePoint | Configure-AssetLibrarySite | O365" -ForegroundColor $CommandInfo
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

Write-Host "Getting current user" -ForegroundColor $CommandInfo
$ctx = Get-PnPContext -Connection $adminCon
$ctx.Load($ctx.Web.CurrentUser)
$ctx.ExecuteQuery()
$actUser = $ctx.Web.CurrentUser.LoginName

# Checking assets site collection
Write-Host "Checking assets site collection" -ForegroundColor $CommandInfo
$assetsSiteName = "$prefix-ADM-Assets"
$site = $null
$site = Get-PnPTenantSite -Connection $adminCon -Url "$($AlyaSharePointUrl)/sites/$assetsSiteName" -Detailed -ErrorAction SilentlyContinue
if (-Not $site)
{
    Write-Warning "Assets site not found. Creating now assets site $assetsSiteName"
    $site = New-PnPSite -Connection $adminCon -Type "CommunicationSite" -Title $assetsSiteName -Url "$($AlyaSharePointUrl)/sites/$assetsSiteName" -Description "Microsoft 365 assets library" -Wait
    do {
        Start-Sleep -Seconds 15
        $site = Get-PnPTenantSite -Connection $adminCon -Url "$($AlyaSharePointUrl)/sites/$assetsSiteName" -Detailed -ErrorAction SilentlyContinue
    } while (-Not $site)
    Start-Sleep -Seconds 60

    # Setting site design
    Write-Host "Setting site design" -ForegroundColor $CommandInfo
    if ($hubSiteDef.subSiteScript)
    {
        $SubSiteDesignNameComm = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSiteDef.short) SubSite Communication Site "+$siteLocale
        $siteDesign = Get-PnPSiteDesign -Connection $adminCon -Identity $SubSiteDesignNameComm
        Invoke-PnPSiteDesign -Connection $adminCon -Identity $siteDesign -WebUrl "$($AlyaSharePointUrl)/sites/$assetsSiteName"
    }
    else
    {
		$SiteDesignNameComm = "$($AlyaCompanyNameShortM365.ToUpper())SP $($hubSiteDef.short) HubSite Communication Site "+$siteLocale
        $siteDesign = Get-PnPSiteDesign -Connection $adminCon -Identity $SiteDesignNameComm
        Invoke-PnPSiteDesign -Connection $adminCon -Identity $siteDesign -WebUrl "$($AlyaSharePointUrl)/sites/$assetsSiteName"
    }

}

# Setting admin access
Write-Host "Setting admin access" -ForegroundColor $TitleColor
$owners = @($actUser)
if ($null -ne $sauserLoginName) { $owners += $sauserLoginName }
foreach ($owner in $AlyaSharePointNewSiteCollectionAdmins)
{
    if (-Not [string]::IsNullOrEmpty($owner) -and $owner -ne "PleaseSpecify")
    {
        $owners += $owner
    }
}
Set-PnPTenantSite -Connection $adminCon -Identity "$($AlyaSharePointUrl)/sites/$assetsSiteName" -PrimarySiteCollectionAdmin $gauserLoginName -Owners $owners

# Login to assets
Write-Host "Login to assets" -ForegroundColor $CommandInfo
$siteCon = LoginTo-PnP "$($AlyaSharePointUrl)/sites/$assetsSiteName"

# Adding site to hub
Write-Host "Adding site to hub" -ForegroundColor $CommandInfo
$hubSite = Get-PnPSite -Connection $hubCon
$siteSite = Get-PnPSite -Connection $siteCon
Add-PnPHubSiteAssociation -Connection $adminCon -Site $siteSite -HubSite $hubSite

# Configuring access to assets site for internals
Write-Host "Configuring access to assets site" -ForegroundColor $CommandInfo
$vgroup = Get-PnPGroup -Connection $siteCon -AssociatedVisitorGroup
$agroup = Get-PnPMicrosoft365Group -Connection $adminCon -Identity $AlyaAllInternals
Add-PnPGroupMember -Connection $siteCon -Group $vgroup -LoginName "c:0o.c|federateddirectoryclaimprovider|$($agroup.Id)"
try {
    Add-PnPGroupMember -Connection $siteCon -Group $vgroup -LoginName "Jeder, außer externen Benutzern"
}
catch {
    try {
        Add-PnPGroupMember -Connection $siteCon -Group $vgroup -LoginName "Everyone except external users"
    }
    catch {
        Write-Warning "Could not add 'Everyone except external users' to visitors group. Please do it by hand."
    }
}

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
Set-PnPWeb -Connection $siteCon -Title "$assetsSiteName"
Set-PnPTenantSite -Connection $adminCon -Identity $site.Url -Title "$assetsSiteName"

Write-Host "Checking public cdn" -ForegroundColor $CommandInfo
$cdnEnabled = (Get-PnPTenantCdnEnabled -Connection $adminCon -CdnType "Public").Value
if (-Not $cdnEnabled)
{
    throw "Please enable the public CDN before configuring the asset library site. Use following script: Enable-PublicCdn.ps1"
}

Write-Host "Configuring assets library ImageAssets" -ForegroundColor $CommandInfo
$libName = "ImageAssets"
$docLib = Get-PnPList -Connection $siteCon -Identity $libName -ErrorAction SilentlyContinue
if (-Not $docLib)
{
    Write-Host "Creating document library $libName" -ForegroundColor $CommandInfo
    $docLib = New-PnPList -Connection $siteCon -Title $libName -Template "DocumentLibrary" -OnQuickLaunch
    $docLib = Get-PnPList -Connection $siteCon -Identity $libName
}
$assLib = Get-PnPOrgAssetsLibrary -Connection $siteCon | Where-Object { $_.LibraryUrl.DecodedUrl -eq "sites/$assetsSiteName/$libName" -and $_.OrgAssetType -eq "ImageDocumentLibrary" }
if (-Not $assLib)
{
    Write-Host "Registering document library $libName" -ForegroundColor $CommandInfo
    $assLib = Add-PnPOrgAssetsLibrary -Connection $siteCon -LibraryUrl "$($AlyaSharePointUrl)/sites/$assetsSiteName/$libName" -CdnType "Public" -OrgAssetType "ImageDocumentLibrary" -DefaultOriginAdded $true -IsCopilotSearchable $true
}
#Remove-PnPOrgAssetsLibrary -Connection $siteCon -LibraryUrl "$($AlyaSharePointUrl)/sites/$assetsSiteName/$libName" -CdnType "Public" -ShouldRemoveFromCdn $true

Write-Host "Configuring assets library TemplateAssets" -ForegroundColor $CommandInfo
$libName = "TemplateAssets"
$docLib = Get-PnPList -Connection $siteCon -Identity $libName -ErrorAction SilentlyContinue
if (-Not $docLib)
{
    Write-Host "Creating document library $libName" -ForegroundColor $CommandInfo
    $docLib = New-PnPList -Connection $siteCon -Title $libName -Template "DocumentLibrary" -OnQuickLaunch
    $docLib = Get-PnPList -Connection $siteCon -Identity $libName
}
$assLib = Get-PnPOrgAssetsLibrary -Connection $siteCon | Where-Object { $_.LibraryUrl.DecodedUrl -eq "sites/$assetsSiteName/$libName" -and $_.OrgAssetType -eq "OfficeTemplateLibrary" }
if (-Not $assLib)
{
    Write-Host "Registering document library $libName" -ForegroundColor $CommandInfo
    $assLib = Add-PnPOrgAssetsLibrary -Connection $siteCon -LibraryUrl "$($AlyaSharePointUrl)/sites/$assetsSiteName/$libName" -CdnType "Public" -OrgAssetType "OfficeTemplateLibrary" -DefaultOriginAdded $true -IsCopilotSearchable $false
}
#Remove-PnPOrgAssetsLibrary -Connection $siteCon -LibraryUrl "$($AlyaSharePointUrl)/sites/$assetsSiteName/$libName" -CdnType "Public" -ShouldRemoveFromCdn $true

Write-Host "Uploading ImageAssets" -ForegroundColor $CommandInfo
$libName = "ImageAssets"
$assetsRoot = "$AlyaData\azure\publicStorage"
$images = Get-ChildItem -Path $assetsRoot -Recurse -Include "*.png","*.jpg","*.jpeg","*.gif","*.svg"
foreach($image in $images)
{
    #$image = $images[0]
    $relativePath = $image.FullName.Substring($assetsRoot.Length).TrimStart("\")
    $relativeParentPath = [System.IO.Path]::GetDirectoryName($relativePath)
    $targetPath = [System.IO.Path]::Combine($libName, $relativeParentPath)
    Write-Host "  Uploading $($image.FullName)"
    $null = Add-PnPFile -Connection $siteCon -Path $image.FullName -Folder $targetPath
}

Write-Host "Applying home page template" -ForegroundColor $CommandInfo
$homePageTemplate = @"
<pnp:Provisioning xmlns:pnp="http://schemas.dev.office.com/PnP/2022/09/ProvisioningSchema">
  <pnp:Preferences Generator="PnP.Framework, Version=1.18.0.0, Culture=neutral, PublicKeyToken=0d501f89f11b748c" />
  <pnp:Templates ID="CONTAINER-TEMPLATE-3041EB5FE7A848E682E1B5C54C8CDBE9">
    <pnp:ProvisioningTemplate ID="TEMPLATE-3041EB5FE7A848E682E1B5C54C8CDBE9" Version="1" BaseSiteTemplate="SITEPAGEPUBLISHING#0" Scope="RootSite">
      <pnp:ClientSidePages>
        <pnp:ClientSidePage PromoteAsNewsArticle="false" PromoteAsTemplate="false" Overwrite="true" Layout="Home" EnableComments="false" Title="Home" ThumbnailUrl="" PageName="Home.aspx">
          <pnp:Header Type="None" LayoutType="FullWidthImage" ShowTopicHeader="false" ShowPublishDate="false" ShowBackgroundGradient="false" TopicHeader="" AlternativeText="" Authors="" AuthorByLineId="-1" />
          <pnp:Sections>
            <pnp:Section Order="1" Type="OneColumn">
              <pnp:Controls>
                <pnp:CanvasControl WebPartType="List" JsonControlData="{&quot;id&quot;: &quot;f92bf067-bc19-489e-a556-7fe95f508720&quot;, &quot;instanceId&quot;: &quot;1a440d40-dedc-4fe2-8c4e-ecd4b8f19927&quot;, &quot;title&quot;: &quot;Dokumentbibliothek&quot;, &quot;description&quot;: &quot;Eine Dokumentbibliothek von dieser Website anzeigen.&quot;, &quot;dataVersion&quot;: &quot;1.0&quot;, &quot;properties&quot;: {&quot;isDocumentLibrary&quot;:true,&quot;selectedListId&quot;:&quot;{listid:ImageAssets}&quot;,&quot;selectedListUrl&quot;:&quot;{site}/ImageAssets&quot;,&quot;webRelativeListUrl&quot;:&quot;/ImageAssets&quot;,&quot;selectedViewId&quot;:&quot;{viewid:ImageAssets,Alle Dokumente}&quot;,&quot;webpartHeightKey&quot;:4}, &quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},&quot;searchablePlainTexts&quot;:{&quot;listTitle&quot;:&quot;ImageAssets&quot;},&quot;imageSources&quot;:{},&quot;links&quot;:{}}, &quot;dynamicDataPaths&quot;: {}, &quot;dynamicDataValues&quot;: {&quot;filterBy&quot;:{}}}" ControlId="f92bf067-bc19-489e-a556-7fe95f508720" Order="1" Column="1" />
                <pnp:CanvasControl WebPartType="List" JsonControlData="{&quot;id&quot;: &quot;f92bf067-bc19-489e-a556-7fe95f508720&quot;, &quot;instanceId&quot;: &quot;edcd4345-c84c-4548-a797-5e2e7af84fe0&quot;, &quot;title&quot;: &quot;Dokumentbibliothek&quot;, &quot;description&quot;: &quot;Eine Dokumentbibliothek von dieser Website anzeigen.&quot;, &quot;dataVersion&quot;: &quot;1.0&quot;, &quot;properties&quot;: {&quot;isDocumentLibrary&quot;:true,&quot;selectedListId&quot;:&quot;{listid:TemplateAssets}&quot;,&quot;selectedListUrl&quot;:&quot;{site}/TemplateAssets&quot;,&quot;webRelativeListUrl&quot;:&quot;/TemplateAssets&quot;,&quot;webpartHeightKey&quot;:4,&quot;selectedViewId&quot;:&quot;{viewid:TemplateAssets,Alle Dokumente}&quot;}, &quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},&quot;searchablePlainTexts&quot;:{&quot;listTitle&quot;:&quot;TemplateAssets&quot;},&quot;imageSources&quot;:{},&quot;links&quot;:{}}, &quot;dynamicDataPaths&quot;: {}, &quot;dynamicDataValues&quot;: {&quot;filterBy&quot;:{}}}" ControlId="f92bf067-bc19-489e-a556-7fe95f508720" Order="2" Column="1" />
                <pnp:CanvasControl WebPartType="News" JsonControlData="{&quot;id&quot;: &quot;8c88f208-6c77-4bdb-86a0-0c47b4316588&quot;, &quot;instanceId&quot;: &quot;3c3acc5f-432c-4b7b-a6b3-0426a6dad5cf&quot;, &quot;title&quot;: &quot;Neuigkeiten&quot;, &quot;description&quot;: &quot;Show recent news for the current site.&quot;, &quot;dataVersion&quot;: &quot;1.18&quot;, &quot;properties&quot;: {&quot;showChrome&quot;:true,&quot;carouselSettings&quot;:{&quot;autoplay&quot;:false,&quot;autoplaySpeed&quot;:5,&quot;dots&quot;:true,&quot;lazyLoad&quot;:true},&quot;showNewsMetadata&quot;:{&quot;showSocialActions&quot;:false,&quot;showAuthor&quot;:true,&quot;showDate&quot;:true,&quot;showSiteTitle&quot;:true},&quot;isTitleEnabled&quot;:true,&quot;isChromeModified&quot;:true,&quot;minimumLayoutWidth&quot;:22,&quot;layoutId&quot;:&quot;GridNews&quot;,&quot;newsDataSourceProp&quot;:1,&quot;carouselHeroWrapperComponentId&quot;:&quot;&quot;,&quot;prefetchCount&quot;:4,&quot;filters&quot;:[{&quot;filterType&quot;:1,&quot;value&quot;:&quot;&quot;,&quot;values&quot;:[]}],&quot;dataProviderId&quot;:&quot;news&quot;,&quot;newsSiteList&quot;:[],&quot;renderItemsSliderValue&quot;:4,&quot;layoutComponentId&quot;:&quot;&quot;,&quot;webId&quot;:&quot;{siteid}&quot;,&quot;siteId&quot;:&quot;{sitecollectionid}&quot;,&quot;filterKQLQuery&quot;:&quot;&quot;}, &quot;serverProcessedContent&quot;: {&quot;htmlStrings&quot;:{},&quot;searchablePlainTexts&quot;:{},&quot;imageSources&quot;:{},&quot;links&quot;:{&quot;baseUrl&quot;:&quot;https://{fqdn}{site}&quot;}}, &quot;dynamicDataPaths&quot;: {}, &quot;dynamicDataValues&quot;: {}}" ControlId="8c88f208-6c77-4bdb-86a0-0c47b4316588" Order="3" Column="1" />
              </pnp:Controls>
            </pnp:Section>
          </pnp:Sections>
        </pnp:ClientSidePage>
      </pnp:ClientSidePages>
    </pnp:ProvisioningTemplate>
  </pnp:Templates>
</pnp:Provisioning>
"@
$tempFile = [System.IO.Path]::GetTempFileName()
$homePageTemplate | Set-Content -Path $tempFile -Encoding $AlyaUtf8Encoding
$null = Invoke-PnPSiteTemplate -Connection $siteCon -Path $tempFile
Remove-Item -Path $tempFile

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBk2AttWI02lzzV
# Zd8RCmfelb0OYy6nCPxuNupPPM85oKCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJJaE77Ob1u1OyGy
# piWhavRB2g84fFIfoShiLJjFD+10MA0GCSqGSIb3DQEBAQUABIICAFryl8tWrViO
# ll2hrnt9NwLy6PYAKNr/nl6G/eqv6kkY5RKsWJUoMiv2AY+xuKi3DrzspdCORtk9
# eVuZChre1SagUQoO0lZb8L9HQkvUgCr2ItljJCfmNKM3+AMuSljRatflnNRIbTL8
# YZNDq1JA9Tq1o9dhhw6UMO/bYc9t7Fl56hpcoaZm51cxloi/W2o5GVIW9xd1yElN
# WDw8ClPMfRCFZtC2/M4rC67rK/uMuFSOqE1Xngwc0xvT33BSK/Xk2kPJmqNnZwxr
# M5sukkE/W5uk9lkl2hnWbZc+nLMVnDANjahV2PfG2ePcpKUXEjhkH8iO3MlQ+LUD
# GYn4v0XVRw6gjtPm3j/U0m9NpPKzYFqb9ESJI9u3b7ejmxSuG0H1I5iqqbvl8pGJ
# /eXpjywpbfj9UPI9X1flCgqu3nwTCubvfecRaYaENJl57tlwfydKRBdSt828JPzk
# V8H9Xj/Y2AhM4+HmjaRwNaVQx2/YJVGmqsLuhWNXMVC7GKiAb4E2RpQ92CcJWHvt
# +e1qw+5ax41Fic7ric6ORV2fgnWEiWR76oDAnchwjsy3qIhkuq/yTe4SwT1R7MuL
# 0wspWYXsXkX73toA66U4KiDw9g5a8pvAA8OAZswyUZUP6WHguB5eDGtuxqPlC4qX
# Y/nPW+92IFjaRsCAfIB4hUezWjMkyhr/oYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCCxz8y6ubwcjUtQADrzAu6PYKF9QJrPJ7wjIMfMYRgvQgIUJKvpDt6qtXfJ
# 3ln8A43XpHmaO0AYDzIwMjYwMTI2MjIzODU1WjADAgEBoFikVjBUMQswCQYDVQQG
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
# ICHkS82tc00izdEPR7sZAIIk4OnpIaIEaiTG1Q15KNeUMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAMYeHLFmw7/hw
# bRJiQjadlXQ+OPVFKMjQK9Kd+AowOA87BuQ6pioVeP1toHWCUrsLsIec7XPVAcq7
# KcLLLs96TZg94I7ALx/WqHG2NeCBGt92yC7Fy2ge9zUVYqgWiaFAHD9uWt0JoMDB
# N2fNG5R8c7mmbTcwnC38O9je6ZJfXcD66rwcdd/8vhsgFQyxmdchTjr81IUFin82
# 5plkGLsd6MTiw8qYZxXTVB6N7UHRpK43mCEyC6RzhSR8ky6N5IxZLQCU/FU/4i+s
# L624nbl1fxcbAPP1L8Nfew1xcADdBmwwhiea8pAfYeNciaMnK73TG7Zje4j6TyvH
# vqukHMM2VvQS+qUXM8KEjpxhKumxzk3Nb20I3j8VXpJ87/OWngdJ3kX3HMttsj5x
# iYqPjlYDFSrZoLwm94vsoTrwLxjOukwF4AvKy0IDLkhMGIGbCZDeT7UY9cW9dpf2
# JYI8UYwW/541+BOMdRq+ZmpZ5pL2E27eyWaPeoErTZWuJMJEdKW5
# SIG # End signature block
