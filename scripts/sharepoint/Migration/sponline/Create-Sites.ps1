#Requires -Version 2.0
#Requires -Modules Microsoft.Online.Sharepoint.PowerShell, SharePointPnPPowerShellOnline

Start-Transcript -Path "$PSScriptRoot\..\logs\Create-Sites-$(get-date -Format 'yyyyMMddhhmmss').txt"

Write-Output "Enviroment setup"
$webApplication = "webAppName1"
$migrateAll = $false
$sharepointUrl = "https://alyaconsulting.sharepoint.com"
$sharepointAdminUrl = "https://alyaconsulting-admin.sharepoint.com"
$sharepointSitesUrl = "$($sharepointUrl)/sites"
$sharePointEnvSuffix = ""
$sharepointAdmins = ("konrad.brunner@alyaconsulting.ch", "admin@alyaconsulting.onmicrosoft.com", "AlyaSpAdmin@alyaconsulting.ch")

if (-Not $global:ocred)
{
    Write-Output "Getting credentials"
    $global:ocred = Get-Credential
}

Write-Output "Connecting to SPOService"
$tmp = Connect-SPOService -Url $sharepointAdminUrl -Credential $global:ocred
Set-SPOTenant -SpecialCharactersStateInFileFolderNames Allowed

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

$migSites | Where-Object { ( $migrateAll -or $_.Command.ToLower() -eq "copy" ) -and $_.WebApplication -eq $webApplication } | Foreach-Object {

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
	Write-Output "Checking site $($fullUrl)"

    $site = $null
    try { $site = Get-SPOSite -Identity $fullUrl -ErrorAction SilentlyContinue } catch {}
    
    if (-Not $site)
    {
	    Write-Output "  - Creating"

        New-PnPTenantSite `
          -Title $_.Title `
          -Url $fullUrl `
          -Description $_.Description `
          -Owner $sharepointAdmins[0] `
          -Lcid $_.Lcid `
          -Template $_.Template `
          -TimeZone 4 `
          -Wait `
          -ErrorAction Stop

	    Write-Output ""
    }
    else
    {
	    Write-Output "  - Exists"
    }
}

Write-Host "Waiting for 5 minutes to let backgound jobs doing their work"
Start-Sleep -Seconds 300

$migSites | Where-Object { ( $migrateAll -or $_.Command.ToLower() -eq "copy" ) -and $_.WebApplication -eq $webApplication } | Foreach-Object {

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
	Write-Output "Checking site $($fullUrl)"

    $site = $null
    try { $site = Get-SPOSite -Identity $fullUrl -ErrorAction SilentlyContinue } catch {}
    
    if ($site)
    {
	    Write-Output "  - Updating"

        $tmp = Connect-PnPOnline -Url $fullUrl -Credential $global:ocred
        Add-PnPSiteCollectionAdmin -Owners $sharepointAdmins
        $tmp = Connect-SPOService -Url $sharepointAdminUrl -Credential $global:ocred
        Set-SPOSite -Identity $fullUrl -DenyAddAndCustomizePages $false
        if ($_.AllowFileSharingForGuestUsers)
        {
            Set-SPOSite -Identity $fullUrl -SharingCapability ExternalUserSharingOnly
        }
        else
        {
            Set-SPOSite -Identity $fullUrl -SharingCapability ExistingExternalUserSharingOnly
        }

	    Write-Output ""
    }
    else
    {
	    Write-Output "  - Site does not exist"
    }
}

Disconnect-PnPOnline
Disconnect-SPOService

Stop-Transcript

<#

$fullUrl = "https://alyaconsulting.sharepoint.com/sites/site1internal-ex1"
$tmp = Connect-SPOService -Url $sharepointAdminUrl -Credential $global:ocred
Set-SPOSite -Identity $fullUrl -DenyAddAndCustomizePages $false
Set-SPOSite -Identity $fullUrl -SharingCapability ExistingExternalUserSharingOnly

$fullUrl = "https://alyaconsulting.sharepoint.com/sites/site1internal-ex2"
$tmp = Connect-SPOService -Url $sharepointAdminUrl -Credential $global:ocred
Set-SPOSite -Identity $fullUrl -DenyAddAndCustomizePages $false
Set-SPOSite -Identity $fullUrl -SharingCapability ExternalUserSharingOnly

#>
