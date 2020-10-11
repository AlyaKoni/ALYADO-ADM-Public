#Requires -Version 2.0
#Requires -Modules Microsoft.Online.Sharepoint.PowerShell, SharePointPnPPowerShellOnline

Start-Transcript -Path "$PSScriptRoot\..\logs\Fix-Migration-$(get-date -Format 'yyyyMMddhhmmss').txt"

Write-Output "Enviroment setup"
$webApplication = "webAppName1"
$migrateAll = $false
$sharepointUrl = "https://alyaconsulting.sharepoint.com"
$sharepointAdminUrl = "https://alyaconsulting-admin.sharepoint.com"
$sharepointSitesUrl = "$($sharepointUrl)/sites"
$sharePointEnvSuffix = ""
$sharepointAdmins = ("konrad.brunner@alyaconsulting.ch", "admin@alyaconsulting.onmicrosoft.com", "AlyaSpAdmin@alyaconsulting.ch")
$corpCssUrl = "https://alyapinfstrg001.blob.core.windows.net/styles/"

if (-Not $global:ocred)
{
    Write-Output "Getting credentials"
    $global:ocred = Get-Credential
}

Write-Output "Connecting to SPOService"
$tmp = Connect-SPOService -Url $sharepointAdminUrl -Credential $global:ocred

Write-Output "Connecting to PnP"
$tmp = Connect-PnPOnline -Url $sharepointUrl -Credential $global:ocred

$migSites = Import-Csv -Delimiter "," -encoding UTF8 $PSScriptRoot\..\setupSites.csv
if ([string]::IsNullOrEmpty($migSites[0].DstCol))
{
	$migSites = Import-Csv -Delimiter ";" -encoding UTF8 $PSScriptRoot\..\setupSites.csv
}
if ([string]::IsNullOrEmpty($migSites[0].DstCol))
{
	Write-Error "Wrong delimiter found."
	exit
}

$migSites | where { ( $migrateAll -or $_.Command.ToLower() -eq "copy" ) -and $_.WebApplication -eq $webApplication } | foreach {

    if ([string]::IsNullOrEmpty($_.DstUrl))
    {
	    $fullUrl = "$($sharepointSitesUrl)/$($_.DstCol)$($sharePointEnvSuffix)"
    	$alias = "$($_.DstCol)$($sharePointEnvSuffix)"
    }
    else
    {
	    $fullUrl = "$($sharepointSitesUrl)/$($_.DstCol)$($sharePointEnvSuffix)-$($_.DstUrl)"
    	$alias = "$($_.DstCol)$($sharePointEnvSuffix)-$($_.DstUrl)"
    }
	Write-Output "Site $($fullUrl)"
    $siteTheme = $_.Theme

    $site = $null
    try { $site = Get-SPOSite -Identity $fullUrl -ErrorAction SilentlyContinue } catch {}
    
    if ($site)
    {
	    Write-Output "  - Fixing css"
		Connect-PnPOnline -Url $fullUrl -Credential $global:ocred
        $rootWeb = (Get-PnPSite -Includes RootWeb).RootWeb
        $subwebs = Get-PnPSubWebs -Recurse -Includes SiteLogoUrl
        $subwebs += $rootWeb
        $fullCssUrl = $corpCssUrl + $_.StyleSheet
        foreach ($web in $subwebs)
        {
		    Connect-PnPOnline -Url "$($sharepointUrl)$($web.ServerRelativeUrl)" -Credential $global:ocred
    		Write-Output "      Web $($web.ServerRelativeUrl)"
            $web = Get-PnPWeb
            if ($web.AlternateCssUrl -ne $fullCssUrl)
            {
                Set-PnpWeb -AlternateCssUrl $fullCssUrl
            }
        }
		 
	    Write-Output "  - Fixing theme"
        foreach ($web in $subwebs)
        {
		    Connect-PnPOnline -Url "$($sharepointUrl)$($web.ServerRelativeUrl)" -Credential $global:ocred
    		Write-Output "      Web $($web.ServerRelativeUrl)"
            #TODO $actTheme = Get-PnPTheme # looks actually like a bug. Returns nothing
            #if ($actTheme.Theme -ne $siteTheme)
            #{
                Set-PnPWebTheme -Theme $siteTheme
            #}
        }

	    Write-Output "  - Fixing logo"
        foreach ($web in $subwebs)
        {
		    Connect-PnPOnline -Url "$($sharepointUrl)$($web.ServerRelativeUrl)" -Credential $global:ocred
    		Write-Output "      Web $($web.ServerRelativeUrl)"
            $web = Get-PnPWeb
            if ($web.SiteLogoUrl -ne $_.Logo)
            {
                Set-PnpWeb -SiteLogoUrl $_.Logo
            }
        }

        if ($alias -eq "intranet-fms" -OR $alias -eq "site1internal-ex2")
        {
		    Write-Output "  - Disabling modern design"
            foreach ($web in $subwebs)
            {
		        Connect-PnPOnline -Url "$($sharepointUrl)$($web.ServerRelativeUrl)" -Credential $global:ocred
    		    Write-Output "      Web $($web.ServerRelativeUrl)"
                $web = Get-PnPWeb
                $lists = Get-PnPList -Web $web
                foreach ($list in $lists)
                {
                    Set-PnPList -Identity $list -ListExperience Auto
                }
            }
            $featureguid = new-object System.Guid "E3540C7D-6BEA-403C-A224-1A12EAFEE4C4"
		    Connect-PnPOnline -Url $fullUrl -Credential $global:ocred
            $site = Get-PnPSite
            $tmp = $site.Features.Add($featureguid, $true, [Microsoft.SharePoint.Client.FeatureDefinitionScope]::None)
            Execute-PnPQuery
        }

    }
    else
    {
	    Write-Output "  - Does not exists"
    }
}


Write-Output "Fixing it"
$tmp = $null
$tmp = Connect-PnPOnline -Url "$($sharepointUrl)/sites/$($webApplication)$($sharePointEnvSuffix)-it" -ReturnConnection -Credential $global:ocred -ErrorAction SilentlyContinue
if ($tmp)
{
    $file = Add-PnPFile -Path $PSScriptRoot\ALG-CHProjectDashboard.js -Folder "_catalogs/masterpage"
}

Write-Output "Fixing someExample"
$tmp = $null
$tmp = Connect-PnPOnline -Url "$($sharepointUrl)/sites/$($webApplication)$($sharePointEnvSuffix)-someExample" -ReturnConnection -Credential $global:ocred -ErrorAction SilentlyContinue
if ($tmp)
{
    $fieldJson = Get-Content -Encoding UTF8 -Raw $PSScriptRoot\statusField.json
    Set-PnPField -List StatusReporting -Identity Health -Values @{ CustomFormatter = $fieldJson.ToString()}
    Set-PnPField -List StatusReporting -Identity Time -Values @{ CustomFormatter = $fieldJson.ToString()}
    Set-PnPField -List StatusReporting -Identity Cost -Values @{ CustomFormatter = $fieldJson.ToString()}
    Set-PnPField -List StatusReporting -Identity Scope -Values @{ CustomFormatter = $fieldJson.ToString()}
    Set-PnPField -List StatusReporting -Identity Quality -Values @{ CustomFormatter = $fieldJson.ToString()}
    Set-PnPField -List StatusReporting -Identity Staffing -Values @{ CustomFormatter = $fieldJson.ToString()}
    Set-PnPField -List StatusReporting -Identity Trend -Values @{ CustomFormatter = $fieldJson.ToString()}
}

Disconnect-PnPOnline
Disconnect-SPOService

Stop-Transcript
