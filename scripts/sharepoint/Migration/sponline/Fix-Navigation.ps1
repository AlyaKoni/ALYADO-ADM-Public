#Requires -Version 3.0

<#
    Copyright (c) Alya Consulting, 2019-2023

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

Start-Transcript -Path "$PSScriptRoot\..\logs\Fix-Navigation-$(get-date -Format 'yyyyMMddhhmmss').txt"

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
if (-Not (Test-Path "$PSScriptRoot\OnPremNavigation$($webApplication)$($webEnv).csv"))
{
    Write-Output "Reading onprem nodes"
    & "$PSScriptRoot\getNavigation$($webApplication)$($webEnv).ps1" -onprem $true
}
if (-Not (Test-Path "$PSScriptRoot\OnlineNavigation$($webApplication)$($webEnv).csv"))
{
    Write-Output "Reading online nodes"
    & "$PSScriptRoot\getNavigation$($webApplication)$($webEnv).ps1" -onprem $false
}

Write-Output "Reading csv files"
$onpremNavsCsv = Import-Csv -Path "$PSScriptRoot\OnPremNavigation$($webApplication)$($webEnv).csv" -Encoding UTF8
$onlineNavsCsv = Import-Csv -Path "$PSScriptRoot\OnlineNavigation$($webApplication)$($webEnv).csv" -Encoding UTF8

$onpremNavs = @()
$onlineNavs = @()

foreach ($onpremNavCsv in $onpremNavsCsv)
{
    $fnd = New-Object System.Object
    $fnd | Add-Member -MemberType NoteProperty -Name "Site" -Value $onpremNavCsv.Site
    $fnd | Add-Member -MemberType NoteProperty -Name "Web" -Value $onpremNavCsv.Web
    $fnd | Add-Member -MemberType NoteProperty -Name "Location" -Value $onpremNavCsv.Location
    $fnd | Add-Member -MemberType NoteProperty -Name "Id" -Value $onpremNavCsv.Id
    $fnd | Add-Member -MemberType NoteProperty -Name "ParentId" -Value $onpremNavCsv.ParentId
    $fnd | Add-Member -MemberType NoteProperty -Name "Title" -Value $onpremNavCsv.Title
    $fnd | Add-Member -MemberType NoteProperty -Name "Url" -Value $onpremNavCsv.Url
    $fnd | Add-Member -MemberType NoteProperty -Name "IsVisible" -Value $onlineNavCsv.Visible
    $fnd | Add-Member -MemberType NoteProperty -Name "Delete" -Value $false
    $fnd | Add-Member -MemberType NoteProperty -Name "Add" -Value $false
    $fnd | Add-Member -MemberType NoteProperty -Name "RenameTo" -Value $null
    $fnd | Add-Member -MemberType NoteProperty -Name "MakeVisible" -Value $null
    $onpremNavs += $fnd
}

foreach ($onlineNavCsv in $onlineNavsCsv)
{
    $fnd = New-Object System.Object
    $fnd | Add-Member -MemberType NoteProperty -Name "Site" -Value $onlineNavCsv.Site
    $fnd | Add-Member -MemberType NoteProperty -Name "Web" -Value $onlineNavCsv.Web
    $fnd | Add-Member -MemberType NoteProperty -Name "Location" -Value $onlineNavCsv.Location
    $fnd | Add-Member -MemberType NoteProperty -Name "Id" -Value $onlineNavCsv.Id
    $fnd | Add-Member -MemberType NoteProperty -Name "ParentId" -Value $onlineNavCsv.ParentId
    $fnd | Add-Member -MemberType NoteProperty -Name "Title" -Value $onlineNavCsv.Title
    $fnd | Add-Member -MemberType NoteProperty -Name "Url" -Value $onlineNavCsv.Url
    $fnd | Add-Member -MemberType NoteProperty -Name "IsVisible" -Value $onlineNavCsv.Visible
    $fnd | Add-Member -MemberType NoteProperty -Name "Delete" -Value $false
    $fnd | Add-Member -MemberType NoteProperty -Name "Add" -Value $false
    $fnd | Add-Member -MemberType NoteProperty -Name "RenameTo" -Value $null
    $fnd | Add-Member -MemberType NoteProperty -Name "MakeVisible" -Value $null
    $onlineNavs += $fnd
}

#Calcluating changes
Write-Output "Compairing"
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
	Write-Output "  Site $($fullUrl)"
	Write-Output "   with data from $($fullSrcUrl)"

    $onpremWebs = $onpremNavs | Where-Object { $_.Site -eq $fullSrcUrl } | Select-Object -ExpandProperty Web -Unique
    foreach ($onpremWeb in $onpremWebs)
    {
        $onlineWeb = $onpremWeb
        if ($_.SrcUrl.length -gt 0) {
            $onlineWeb = $onlineWeb.Replace($_.SrcUrl,"")
        }
        if ($onlineWeb -eq "/") {
            $onlineWeb = ""
        }
        $onlineWeb = "/sites/" + $alias + $onlineWeb
	    Write-Output "   Web $($onlineWeb)"

        foreach($navType in ("QuickLaunch", "TopNavigationBar"))
        {
	        Write-Output "      NavType $($navType)"

            $onpremWebNodes = $onpremNavs | Where-Object { $_.Site -eq $fullSrcUrl -and $_.Web -eq $onpremWeb -and $_.Location -eq $navType -and $_.ParentId -eq "" }

            <#$onlineWebNodes = $onlineNavs | Where-Object { $_.Site -eq $fullUrl -and $_.Web -eq $onlineWeb -and $_.Location -eq $navType -and $_.ParentId -eq "" -and $_.Url -eq "" }
            foreach ($onlineWebNode in $onlineWebNodes)
            {
                $onlineWebNode.Delete = $true
            }#>
            $onlineWebNodes = $onlineNavs | Where-Object { $_.Site -eq $fullUrl -and $_.Web -eq $onlineWeb -and $_.Location -eq $navType -and $_.ParentId -eq "" -and $_.Delete -eq $false }

            $titles = $onlineWebNodes | Select-Object -ExpandProperty Title -Unique
            foreach ($title in $titles)
            {
                $checkNodes = $onlineWebNodes | Where-Object { $_.Title -eq $title -and $_.Delete -eq $false }
                for ($i=0; $i -lt $checkNodes.Length; $i++)
                {
                    if ($i -gt 0)
                    { 
                        $checkNodes[$i].Delete = $true
                    }
                    else
                    {
                        $onpremNode = $onpremWebNodes | Where-Object { $_.Title -eq $title }
                        if ($checkNodes[$i].IsVisible -ne $onpremNode.IsVisible)
                        {
                            $checkNodes[$i].MakeVisible = $onpremNode.IsVisible
                        }
                    }
                }
                $checkNodes = $onpremWebNodes | Where-Object { $_.Title -eq $title }
                if (-Not $checkNodes -Or $checkNodes.Length -eq 0)
                {
                    $renamed = $false
                    foreach ($onpremWebNode in $onpremWebNodes)
                    {
                        if ($onpremWebNode.Title -like $title+"*")
                        {
                            $renamed = $true
                            ($onlineWebNodes | Where-Object { $_.Title -eq $title }).RenameTo = $onpremWebNode.Title
                            break
                        }
                    }
                    if (-Not $renamed)
                    {
                        ($onlineWebNodes | Where-Object { $_.Title -eq $title }).Delete = $true
                    }
                }
            }

            foreach ($onpremWebNode in $onpremWebNodes)
            {
                $checkNodes = $onlineWebNodes | Where-Object { $_.Title -eq $onpremWebNode.Title -and $_.Delete -eq $false }
                if (-Not $checkNodes -Or $checkNodes.Length -Eq 0)
                {
                    $renamedOne = $onlineWebNodes | Where-Object { $_.RenameTo -eq $onpremWebNode.Title }
                    if (-Not $renamedOne -Or $renamedOne.Length -Eq 0)
                    {
                        $fnd = New-Object System.Object
                        $onpremWebNode.psobject.properties | % {
                            $fnd | Add-Member -MemberType $_.MemberType -Name $_.Name -Value $_.Value
                        }
                        $fnd.Site = $fullUrl
                        $fnd.Web = $onlineWeb
                        $fnd.Location = $navType
                        $fnd.Add = $true
                        $fnd.Url = $fnd.Url.Replace($onpremWeb, $onlineWeb)
                        $onlineNavs += $fnd
                    }
                }
            }

        }
    }
}

#Fixing navigation nodes
Write-Output "Fixing"
$totAdd = 0
$totDel = 0
$totRen = 0
$onlineSites = $onlineNavs | Select-Object -ExpandProperty Site -Unique
foreach ($onlineSite in $onlineSites)
{
    Write-Host "  $($onlineSite)"
    $onlineWebs = $onlineNavs | Where-Object { $_.Site -eq $onlineSite } | Select-Object -ExpandProperty Web -Unique
    foreach ($onlineWeb in $onlineWebs)
    {
        Write-Host "    $($onlineWeb)"
        $ctx = New-Object Microsoft.SharePoint.Client.ClientContext($sharepointUrl+$onlineWeb)
        $ctx.credentials = $creds
        $ctx.load($ctx.Web)
        $ctx.executeQuery()
        foreach($navType in ("QuickLaunch", "TopNavigationBar"))
        {
	        Write-Output "      $($navType)"
            $ctx.load($ctx.Web.Navigation.$navType)
            $ctx.executeQuery()

            Write-Host "        Adds:"
            $onlineNodes = $onlineNavs | Where-Object { $_.Site -eq $onlineSite -And $_.Web -eq $onlineWeb -and $_.Location -eq $navType -And $_.Add -eq $true }
            foreach ($onlineNode in $onlineNodes)
            {
                Write-Host "          $($onlineNode.Title)"        
                $totAdd = $totAdd + 1
                $navNode = New-Object Microsoft.SharePoint.Client.NavigationNodeCreationInformation
                $navNode.Title = $onlineNode.Title
                $navNode.Url = $onlineNode.Url
                $navNode.AsLastNode = $true    
                $ctx.Load($ctx.Web.Navigation.$navType.Add($navNode)) 
                $ctx.ExecuteQuery()
            }

            Write-Host "        Deletes:"
            $onlineNodes = $onlineNavs | Where-Object { $_.Site -eq $onlineSite -And $_.Web -eq $onlineWeb -and $_.Location -eq $navType -And $_.Delete -eq $true }
            foreach ($onlineNode in $onlineNodes)
            {
                Write-Host "          $($onlineNode.Title)" 
                $totDel = $totDel + 1   
                $fnd = $null
                foreach($navNode in $ctx.Web.Navigation.$navType)
                {
                    if ($navNode.Id -eq $onlineNode.Id -and $navNode.Title -eq $onlineNode.Title -and $navNode.Url -eq $onlineNode.Url)
                    {
                        $fnd = $navNode
                        break
                    }
                }
                if (-Not $fnd)
                {
                    Write-Host "            NOT FOUND!" -ForegroundColor Red
                }
                else
                {
                    $fnd.DeleteObject()
                    $ctx.ExecuteQuery()
                }
            }

            Write-Host "        Renames:"
            $onlineNodes = $onlineNavs | Where-Object { $_.Site -eq $onlineSite -And $_.Web -eq $onlineWeb -and $_.Location -eq $navType -And $_.RenameTo -ne $null }
            foreach ($onlineNode in $onlineNodes)
            {
                Write-Host "          '$($onlineNode.Title)' to '$($onlineNode.RenameTo)'" 
                $totRen = $totRen + 1       
                $fnd = $null
                foreach($navNode in $ctx.Web.Navigation.$navType)
                {
                    if ($navNode.Id -eq $onlineNode.Id -and $navNode.Title -eq $onlineNode.Title -and $navNode.Url -eq $onlineNode.Url)
                    {
                        $fnd = $navNode
                        break
                    }
                }
                if (-Not $fnd)
                {
                    Write-Host "            NOT FOUND!" -ForegroundColor Red
                }
                else
                {
                    $navNode.Title = $onlineNode.RenameTo
                    $navNode.Update()
                    $ctx.ExecuteQuery()
                }
            }
        }
    }
}

Write-Output "Total Adds $($totAdd)"
Write-Output "Total Deletes $($totDel)"
Write-Output "Total Renames $($totRen)"

Stop-Transcript
