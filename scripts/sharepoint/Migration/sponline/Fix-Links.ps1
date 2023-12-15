#Requires -Version 2.0
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

#Requires -Modules Microsoft.Online.Sharepoint.PowerShell, SharePointPnPPowerShellOnline

Start-Transcript -Path "$PSScriptRoot\..\logs\Fix-Links-$(get-date -Format 'yyyyMMddhhmmss').txt"

Write-Output "Enviroment setup"
$webApplication = "webAppName1"
$migrateAll = $false
$sharepointUrl = "https://alyaconsulting.sharepoint.com"
$sharepointAdminUrl = "https://alyaconsulting-admin.sharepoint.com"
$sharepointSitesUrl = "$($sharepointUrl)/sites"
$sharePointEnvSuffix = ""
$sharepointAdmins = ("konrad.brunner@alyaconsulting.ch", "admin@alyaconsulting.onmicrosoft.com", "AlyaSpAdmin@alyaconsulting.ch")

$regxHref = "href\s*=\s*(?:[`"'](?<1>[^`"']*)[`"']|(?<1>\\S+))"
$regxSrc = "src\s*=\s*(?:[`"'](?<1>[^`"']*)[`"']|(?<1>\\S+))"

function Init-Replacers ()
{
	$global:replacers = ( `
		("/sites/site1internal/sites/ex1","/sites/site1internal-ex1",$false), `
		("https://alyaconsulting.sharepoint.com/sites/ex1","https://alyaconsulting.sharepoint.com/sites/site1internal-ex1",$false), `
		("https://site1internal.alyaconsulting.ch/sites","https://alyaconsulting.sharepoint.com/sites",$false) `
	)
}

function Process-Value ($value)
{
    foreach($replacer in $global:replacers)
    {
        if ($value -like "*$($replacer[0])*")
        {
            $value = $value.Replace($replacer[0], $replacer[1])
        }
    }
    return $value
}

function Process-Regex ($value, $regxStr)
{
    if ($value -match $regxStr)
    {
        $regx = [Regex]::new($regxStr)
        $matches = $regx.Matches($wikiField)
        foreach($match in $matches)
        {
            foreach($replacer in $global:replacers)
            {
                if ($replacer[2]) { continue }
                $srcStr = $match.Groups[1].Value
                if ($srcStr -like "*$($replacer[0])*")
                {
                    $value = $value.Replace($replacer[0], $replacer[1])
                    $replacer[2] = $true
                    #TODO break check if break required
                }
            }
        }
    }
    return $value
}

function Process-Lib ($libName)
{
    $fldr = $ctx.Web.GetFolderByServerRelativeUrl("$($web.ServerRelativeUrl)/$($libName)")
    try {
        $ctx.Load($fldr)
        $ctx.Load($fldr.Files)
        $ctx.ExecuteQuery()
    } catch {}
    if ($fldr.Exists)
    {
	    Write-Output "    - Fixing $($fldr.Files.Count) pages in $($fldr.ServerRelativeUrl)"
        foreach ($file in $fldr.Files)
        {
            $ctx.Load($file)
            $ctx.Load($file.ListItemAllFields)
            $ctx.ExecuteQuery()
            Write-Output "      - Page $($file.ServerRelativeUrl)"
            $wikiField = $file.ListItemAllFields["WikiField"]
            if ($wikiField)
            {
                Write-Output "        - Processing wiki field"
                Init-Replacers
                $wikiFieldNew = Process-Regex -value $wikiField -regxStr $regxHref
                $wikiFieldNew = Process-Regex -value $wikiFieldNew -regxStr $regxSrc
                if ($wikiFieldNew -ne $wikiField)
                {
                    Write-Output "        - *** Updating"
                    $file.ListItemAllFields["WikiField"] = $wikiFieldNew
                    $file.ListItemAllFields.SystemUpdate()
                    $ctx.ExecuteQuery()
                }
            }
            else
            {
                Write-Output "        - No wiki field found"
            }

            Write-Output "        - Processing WebParts"
            $webPartManager = $file.GetLimitedWebPartManager([System.Web.UI.WebControls.WebParts.PersonalizationScope]::Shared)
            $ctx.Load($webPartManager)
            $ctx.Load($webPartManager.WebParts)
            $ctx.ExecuteQuery()
            foreach($webPart in $webPartManager.WebParts)
            {
                $ctx.Load($webPart.WebPart.Properties)
                $ctx.ExecuteQuery()
                Write-Output "            $($webPart.WebPart.Properties["Title"])"
                $changed = $false
                $fieldValueKeys = @()
                foreach($fieldValueKey in $webPart.WebPart.Properties.FieldValues.Keys)
                {
                    $fieldValueKeys += $fieldValueKey
                }
                foreach($fieldValueKey in $fieldValueKeys)
                {
                    $value = $webPart.WebPart.Properties[$fieldValueKey]
                    $value = Process-Value -value $value
                    if ($value -ne $webPart.WebPart.Properties[$fieldValueKey])
                    {
                        Write-Output "            *** Updating $($fieldValueKey)"
                        $webPart.WebPart.Properties[$fieldValueKey] = $value
                        $changed = $true
                    }
                }
                if ($changed)
                {
                    $webPart.SaveWebPartChanges()
                    $ctx.ExecuteQuery()
                }
            }
        }
    }
}

if (-Not $global:ocred)
{
    Write-Output "Getting credentials"
    $global:ocred = Get-Credential
}

Write-Output "Connecting to SPOService"
$null = Connect-SPOService -Url $sharepointAdminUrl -Credential $global:ocred

Write-Output "Connecting to PnP"
$null = Connect-PnPOnline -Url $sharepointUrl -Credential $global:ocred

function ProcessNavNode($navNode)
{
    $value = $navNode.Url
    foreach($replacer in $global:replacers)
    {
        if ($value -like "*$($replacer[0])*")
        {
            $value = $value.Replace($replacer[0], $replacer[1])
            #break
        }
    }
    if ($navNode.Url -ne $value)
    {
        Write-Output "        - *** Updating $($navNode.Url) to $($value)"
        $navNode.Url = $value
        $navNode.Update()
        $ctx.ExecuteQuery()
    }
    $ctx.load($navNode.Children)
    $ctx.executeQuery()
    foreach ($subNode in $navNode.Children)
    {
        ProcessNavNode -navNode $subNode
    }
}

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
	Write-Output "Site $($fullUrl)"

    $site = $null
    try { $site = Get-SPOSite -Identity $fullUrl -ErrorAction SilentlyContinue } catch {}
    
    if ($site)
    {
	    Write-Output "  - Fixing urls in wiki pages"
		Connect-PnPOnline -Url $fullUrl -Credential $global:ocred
        $rootWeb = (Get-PnPSite -Includes RootWeb).RootWeb
        $subwebs = Get-PnPSubWebs -Recurse -Includes SiteLogoUrl
        $subwebs += $rootWeb
        foreach ($web in $subwebs)
        {
		    Connect-PnPOnline -Url "$($sharepointUrl)$($web.ServerRelativeUrl)" -Credential $global:ocred
            $ctx = Get-PnPContext
            Process-Lib "Pages"
            Process-Lib "SitePages"
        }
	    Write-Output "  - Fixing urls in navigation"
        Init-Replacers
        foreach ($web in $subwebs)
        {
	        Write-Output "    - Fixing navigation on web $($web.ServerRelativeUrl)"
		    Connect-PnPOnline -Url "$($sharepointUrl)$($web.ServerRelativeUrl)" -Credential $global:ocred
            $ctx = Get-PnPContext
            foreach($location in ("QuickLaunch","SearchNav","TopNavigationBar"))
            {
                $navNodes = Get-PnPNavigationNode -Location $location
	            Write-Output "      - Fixing $($navNodes.Count) $($location) navigation nodes"
            
                if ($navNodes.Count -gt 0)
                {
                    foreach($navNode in $navNodes)
                    {
                        ProcessNavNode -navNode $navNode
                    }
                }
            }
        }
    }
    else
    {
	    Write-Output "  - Does not exists"
    }
}

Disconnect-PnPOnline
Disconnect-SPOService

Stop-Transcript
