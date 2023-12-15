#Requires -Version 3.0

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


#>

Start-Transcript -Path "$PSScriptRoot\..\logs\Fix-WebParts-$(get-date -Format 'yyyyMMddhhmmss').txt"

Write-Output "Enviroment setup"
$webApplication = "webAppName1"
$migrateAll = $false
$sharepointUrl = "https://alyaconsulting.sharepoint.com"
$sharepointAdminUrl = "https://alyaconsulting-admin.sharepoint.com"
$sharepointSitesUrl = "$($sharepointUrl)/sites"
$sharePointEnvSuffix = ""
$sharepointAdmins = ("konrad.brunner@alyaconsulting.ch", "admin@alyaconsulting.onmicrosoft.com", "AlyaSpAdmin@alyaconsulting.ch")

# Getting csom if not already present
function DownloadAndInstallCSOM($dir, $nuget, $nuvrs)
{
	$fileName = "$PSScriptRoot\$nuget_" + $nuvrs + ".nupkg"
	Invoke-WebRequest -Uri $nusrc.href -OutFile $fileName
	if (-not (Test-Path $fileName))
	{
		Write-Error "Was not able to download $nuget which is a prerequisite for this script"
		break
	}
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($fileName, "$PSScriptRoot\$dir")
    Remove-Item $fileName
}

function PrepareCSOM($dir, $nuget)
{
    $resp = Invoke-WebRequest –Uri "https://www.nuget.org/packages/$nuget"
    $nusrc = ($resp).Links | Where-Object { $_.outerText -eq "Manual download" -or $_."data-track" -eq "outbound-manual-download"}
    $nuvrs = $nusrc.href.Substring($nusrc.href.LastIndexOf("/") + 1, $nusrc.href.Length - $nusrc.href.LastIndexOf("/") - 1)
    if (-not (Test-Path "$PSScriptRoot\$dir\lib\net45"))
    {
        DownloadAndInstallCSOM -dir $dir -nuget $nuget -nuvrs $nuvrs
    }
    else
    {
        # Checking CSOM version, updating if required
        $nuspec = [xml](Get-Content "$PSScriptRoot\$dir\$nuget.nuspec")
        if ($nuspec.package.metadata.version -ne $nuvrs)
        {
            Write-Host "There is a newer CSOM package available. Downloading and installing it."
            Remove-Item -Recurse -Force "$PSScriptRoot\$dir"
            DownloadAndInstallCSOM -dir $dir -nuget $nuget -nuvrs $nuvrs
        }
    }
}

if (-not $global:credLS4D) { $global:credLS4D = Get-Credential -Message "Enter Sharepoint password:" }
PrepareCSOM -dir "_csomOnline" -nuget "Microsoft.SharePointOnline.CSOM"
Add-Type -Path "$PSScriptRoot\_csomOnline\lib\net45\Microsoft.SharePoint.Client.dll"
Add-Type -Path "$PSScriptRoot\_csomOnline\lib\net45\Microsoft.SharePoint.Client.Runtime.dll"
$creds = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($global:credLS4D.UserName, $global:credLS4D.Password)

#Reading input data
if (-Not (Test-Path "$PSScriptRoot\OnPremWebParts$($webApplication)$($webEnv).csv"))
{
    Write-Host "Reading onprem WebParts"
    & "$PSScriptRoot\Get-WebParts.ps1" -onprem $true
}
if (-Not (Test-Path "$PSScriptRoot\OnlineWebParts$($webApplication)$($webEnv).csv"))
{
    Write-Host "Reading online WebParts"
    & "$PSScriptRoot\getWebParts$($webApplication)$($webEnv).ps1" -onprem $false
}

Write-Host "Reading csv files"
$onpremWPs = Import-Csv -Path "$PSScriptRoot\OnPremWebParts$($webApplication)$($webEnv).csv" -Encoding UTF8
$onlineWPs = Import-Csv -Path "$PSScriptRoot\OnlineWebParts$($webApplication)$($webEnv).csv" -Encoding UTF8

#Calcluating changes
Write-Host "Compairing"
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
	$fullSrcUrl = "https://$($webApplication).alyaconsulting.ch$($_.SrcUrl)"
	Write-Host "  Site $($fullUrl)"
	Write-Host "   with data from $($fullSrcUrl)"

    $onpremWebs = $onpremWPs | Where-Object { $_.Site -eq $fullSrcUrl } | Select-Object -ExpandProperty Web -Unique
    foreach ($onpremWeb in $onpremWebs)
    {
        $onpremPages = $onpremWPs | Where-Object { $_.Site -eq $fullSrcUrl -and $_.Web -eq $onpremWeb } | Select-Object -ExpandProperty Page -Unique
        foreach ($onpremPage in $onpremPages)
        {
            $onlineWeb = $onpremWeb
            if ($_.SrcUrl.length -gt 0) {
                $onlineWeb = $onlineWeb.Replace($_.SrcUrl,"")
            }
            if ($onlineWeb -eq "/") {
                $onlineWeb = ""
            }
            $onlineWeb = "/sites/" + $alias + $onlineWeb
	        Write-Host "   Web $($onlineWeb)"
            $onlinePage = $onpremPage.Replace($onpremWeb,$onlineWeb)
	        Write-Host "     Page $($onlinePage)"

            $onpremPageWPs = $onpremWPs | Where-Object { $_.Site -eq $fullSrcUrl -and $_.Page -eq $onpremPage }
            foreach ($onpremPageWP in $onpremPageWPs)
            {
	            Write-Host "       WP $($onpremPageWP.WPTitle)"
                $onlinePageWPFnd = $onlineWPs | Where-Object { $_.Site -eq $fullUrl -and $_.Page -eq $onlinePage -and $_.WPTitle -eq $onpremPageWP.WPTitle -and $_.WPHidden -eq $onpremPageWP.WPHidden -and $_.WPDisplayName -eq $onpremPageWP.WPDisplayName }
                if ($onlinePageWPFnd.Count -gt 1)
                {
                    Write-Host "         *** $($onlinePageWPFnd.Count) duplicates found" -ForegroundColor Red
                    Write-Host "         *** Onprem: $($onpremPage)"
                    Write-Host "         *** Online $($onlinePage)"
                }
                if ($onlinePageWPFnd.Count -eq 0)
                {
                    Write-Host "         *** not found in export!" -ForegroundColor Red
                    Write-Host "         *** Onprem: $($onpremPage)"
                    Write-Host "         *** Online $($onlinePage)"
                }
                foreach ($onlinePageWP in $onlinePageWPFnd)
                {
                    $toChange = $false
                    if ($onlinePageWP.WPChromeState -ne $onpremPageWP.WPChromeState) { $toChange = $true }
                    if ($onlinePageWP.WPChromeType -ne $onpremPageWP.WPChromeType) { $toChange = $true }
                    if ($toChange)
                    {
	                    Write-Host "         *** Changing"
	                    
                        $ctx = New-Object Microsoft.SharePoint.Client.ClientContext($sharepointUrl+$onlineWeb)
                        $ctx.credentials = $creds
                        $ctx.load($ctx.Web)
                        $ctx.executeQuery()
	                    
	                    $page = $ctx.Web.GetFileByServerRelativeUrl($onlinePage)
                        $ctx.load($page)
                        $ctx.executeQuery()

                        $webPartManager = $page.GetLimitedWebPartManager([System.Web.UI.WebControls.WebParts.PersonalizationScope]::Shared)
                        $ctx.Load($webPartManager)
                        $ctx.Load($webPartManager.WebParts)
                        $ctx.ExecuteQuery()
                        $fnd = $false
                        foreach($webPart in $webPartManager.WebParts)
                        {
                            $ctx.Load($webPart.WebPart.Properties)
                            $ctx.ExecuteQuery()
                            if ($webPart.WebPart.Properties["Title"] -eq $onpremPageWP.WPTitle)
                            {
                                $webPart.WebPart.Properties["ChromeState"] = [int]$onpremPageWP.WPChromeState
                                $webPart.WebPart.Properties["ChromeType"] = [int]$onpremPageWP.WPChromeType
                                $webPart.SaveWebPartChanges()
                                $ctx.ExecuteQuery()
                                $fnd = $true
                                break
                            }
                        }
                        if (-Not $fnd)
                        {
                            Write-Host "         *** webpart not found on page!" -ForegroundColor Red
                        }
                    }
                }
            }
        }
    }
}

Stop-Transcript
