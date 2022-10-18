#Requires -Version 2.0
#Requires -Modules Microsoft.Online.Sharepoint.PowerShell, SharePointPnPPowerShellOnline

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

Write-Output "Connecting to PnP"
$tmp = Connect-PnPOnline -Url $sharepointUrl -Credential $global:ocred -ReturnConnection

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
    }
    else
    {
	    $fullUrl = "$($sharepointSitesUrl)/$($_.DstCol)$($sharePointEnvSuffix)-$($_.DstUrl)"
    }

	Write-Output "Checking site $($fullUrl)"

    $site = $null
    try { $site = Get-SPOSite -Identity $fullUrl -ErrorAction SilentlyContinue } catch {}
    
    if ($site)
    {
	    Write-Output "  - Deleting"
        Remove-PnPTenantSite -Url $fullUrl -SkipRecycleBin -Force
    }
    else
    {
	    Write-Output "  - Does not exist"
    }
}

Start-Sleep -Seconds 20

$migSites | where WebApplication -eq $webApplication | foreach {

    if ([string]::IsNullOrEmpty($_.DstUrl))
    {
	    $fullUrl = "$($sharepointSitesUrl)/$($_.DstCol)$($sharePointEnvSuffix)"
    }
    else
    {
	    $fullUrl = "$($sharepointSitesUrl)/$($_.DstCol)$($sharePointEnvSuffix)-$($_.DstUrl)"
    }

	Write-Output "Checking recycle bin $($fullUrl)"
    Clear-PnPTenantRecycleBinItem  -Url $fullUrl -Force -ErrorAction SilentlyContinue | Out-Null
}

Disconnect-PnPOnline
Disconnect-SPOService
