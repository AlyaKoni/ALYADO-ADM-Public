﻿#Requires -Version 3.0

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

param(
   [bool]$onprem
)

Write-Output "Enviroment setup"
$webApplication = "webAppName1"
$migrateAll = $false
$sharepointUrl = "https://alyaconsulting.sharepoint.com"
$sharepointAdminUrl = "https://alyaconsulting-admin.sharepoint.com"
$sharepointSitesUrl = "$($sharepointUrl)/sites"
$sharePointEnvSuffix = ""
$sharepointAdmins = ("konrad.brunner@alyaconsulting.ch", "admin@alyaconsulting.onmicrosoft.com", "AlyaSpAdmin@alyaconsulting.ch")

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

$sourceUrls = @()
$destUrls = @()

$migSites | Where-Object { ($_.Command.ToLower() -eq "copy" ) -and $_.WebApplication -eq $webApplication } | Foreach-Object {
    if ([string]::IsNullOrEmpty($_.DstUrl))
    {
	    $fullDstUrl = "$($sharepointSitesUrl)/$($_.DstCol)$($sharePointEnvSuffix)"
    	$alias = "$($_.DstCol)$($sharePointEnvSuffix)"
    }
    else
    {
	    $fullDstUrl = "$($sharepointSitesUrl)/$($_.DstCol)$($sharePointEnvSuffix)-$($_.DstUrl)"
    	$alias = "$($_.DstCol)$($sharePointEnvSuffix)-$($_.DstUrl)"
    }
	$fullSrcUrl = "https://$($webApplication).alyaconsulting.ch$($_.SrcUrl)"
    $sourceUrls += $fullSrcUrl
    $destUrls += $fullDstUrl
}

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
if ($onprem)
{
    PrepareCSOM -dir "_csomOnPrem" -nuget "Microsoft.SharePoint2016.CSOM"
    Add-Type -Path "$PSScriptRoot\_csomOnPrem\lib\net45\Microsoft.SharePoint.Client.dll"
    Add-Type -Path "$PSScriptRoot\_csomOnPrem\lib\net45\Microsoft.SharePoint.Client.Runtime.dll"
    $creds = New-Object System.Net.NetworkCredential($global:credLS4D.UserName, $global:credLS4D.Password)
    $serverUrls = $sourceUrls
    $outfile = "OnPremNavigation$($webApplication)$($webEnv).csv"
}
else
{
    PrepareCSOM -dir "_csomOnline" -nuget "Microsoft.SharePointOnline.CSOM"
    Add-Type -Path "$PSScriptRoot\_csomOnline\lib\net45\Microsoft.SharePoint.Client.dll"
    Add-Type -Path "$PSScriptRoot\_csomOnline\lib\net45\Microsoft.SharePoint.Client.Runtime.dll"
    $creds = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($global:credLS4D.UserName, $global:credLS4D.Password)
    $serverUrls = $destUrls
    $outfile = "OnlineNavigation$($webApplication)$($webEnv).csv"
}

function ProcessNavNode($navNode, $parentNode)
{
    if ($parentNode){$parentID=$parentNode.Id}else{$parentID=""}
    $fnd = New-Object System.Object
    $fnd | Add-Member -MemberType NoteProperty -Name "Site" -Value $serverUrl
    $fnd | Add-Member -MemberType NoteProperty -Name "Web" -Value $web.ServerRelativeUrl
    $fnd | Add-Member -MemberType NoteProperty -Name "Location" -Value $location
    $fnd | Add-Member -MemberType NoteProperty -Name "Id" -Value $navNode.Id
    $fnd | Add-Member -MemberType NoteProperty -Name "ParentId" -Value $parentID
    $fnd | Add-Member -MemberType NoteProperty -Name "Title" -Value $navNode.Title
    $fnd | Add-Member -MemberType NoteProperty -Name "Url" -Value $navNode.Url
    $fnd | Add-Member -MemberType NoteProperty -Name "Visible" -Value $navNode.IsVisible
    $global:foundItems += $fnd
    $ctx.load($navNode.Children)
    $ctx.executeQuery()
    foreach ($subNode in $navNode.Children)
    {
        ProcessNavNode -navNode $subNode -parentNode $navNode
    }
}

function RunWeb($web)
{
    Write-Host " Web: $($web.ServerRelativeUrl)"
    foreach($location in ("QuickLaunch","TopNavigationBar"))
    {
        $ctx.load($web.Navigation.$location)
        $ctx.executeQuery()
        foreach($navNode in $web.Navigation.$location)
        {
            ProcessNavNode -navNode $navNode -parentNode $null
        }
    }
    $ctx.load($web.Webs)
    $ctx.executeQuery()
    foreach($sweb in $web.Webs)
    {
        RunWeb -web $sweb
    }
}

$global:foundItems = @()
foreach($serverUrl in $serverUrls)
{
    Write-Host "Site: $($serverUrl)"
    $ctx = New-Object Microsoft.SharePoint.Client.ClientContext($serverUrl)
    $ctx.credentials = $creds
    $ctx.load($ctx.Web)
    $ctx.executeQuery()
    RunWeb -web $ctx.Web
}
$global:foundItems | Export-Csv -NoTypeInformation -Path $outfile -Encoding UTF8 -Force -Confirm:$false
