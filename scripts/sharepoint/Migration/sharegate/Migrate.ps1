#Requires -Version 2.0
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

#Requires -Modules Sharegate

Start-Transcript -Path "$PSScriptRoot\..\logs\Migrate-$(get-date -Format 'yyyyMMddhhmmss').txt"

Write-Output "Enviroment setup"
$webApplication = "webAppName1"
$migrateAll = $false
$sharepointUrl = "https://alyaconsulting.sharepoint.com"
$sharepointAdminUrl = "https://alyaconsulting-admin.sharepoint.com"
$sharepointSitesUrl = "$($sharepointUrl)/sites"
$sharePointEnvSuffix = ""
$sharepointAdmins = ("konrad.brunner@alyaconsulting.ch", "admin@alyaconsulting.onmicrosoft.com", "AlyaSpAdmin@alyaconsulting.ch")

Write-Output "ATTENTION!"
Write-Output "Please configure following settings in Sharegate first:"
Write-Output " - Performance: normal"
Write-Output " - Auto-assign Site Collection Administrator: true"
Write-Output " - Allow Office 365 special characters: true`n`n"
pause

if (-Not $global:ocred)
{
    Write-Output "Getting online credentials"
    $global:ocred = Get-Credential
}

#Copy settings
$copySettings = New-CopySettings -OnWarning Continue -OnError Skip -OnSiteObjectExists Merge -OnContentItemExists Overwrite -VersionOrModerationComment "Moderated by migration"

#Mapping settings
$mappingSettings = New-MappingSettings
$mappings = Import-Csv -Delimiter "," -encoding UTF8 $PSScriptRoot\..\setupMapping.csv
if ([string]::IsNullOrEmpty($migSites[0].DstCol))
{
	$migSites = Import-Csv -Delimiter ";" -encoding UTF8 $PSScriptRoot\..\setupMapping.csv
}
if ([string]::IsNullOrEmpty($migSites[0].DstCol))
{
	Write-Error "Wrong delimiter found."
	exit
}
foreach($mapping in $mappings)
{
    Set-UserAndGroupMapping -MappingSettings $mappingSettings -Source $mapping.From -Destination $mapping.To | Out-Null
}

#Site mappings
Set-SiteTemplateMapping -MappingSettings $mappingSettings  -DefaultTemplate -Destination "STS#3" -AllLanguages | Out-Null
Set-SiteTemplateMapping -MappingSettings $mappingSettings  -Source "STS#0" -Destination "STS#3" -AllLanguages | Out-Null

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
	    $fullDstUrl = "$($sharepointSitesUrl)/$($_.DstCol)$($sharePointEnvSuffix)"
    	$alias = "$($_.DstCol)$($sharePointEnvSuffix)"
    }
    else
    {
	    $fullDstUrl = "$($sharepointSitesUrl)/$($_.DstCol)$($sharePointEnvSuffix)-$($_.DstUrl)"
    	$alias = "$($_.DstCol)$($sharePointEnvSuffix)-$($_.DstUrl)"
    }
	$fullSrcUrl = "https://$($webApplication)-search.alyaconsulting.ch$($_.SrcUrl)"
	Write-Output "Migrating site"
    Write-Output "  from $($fullSrcUrl)"
    Write-Output "  to   $($fullDstUrl)"

	Write-Output "  Connecting Source site"
    $srcSite = Connect-Site -Url $fullSrcUrl -Credential $global:ocred -ErrorAction Stop
    if (-Not $srcSite)
    {
        throw "Can't connect Source site"
    }
    if ($srcSite.Address.AbsoluteUri -notmatch $fullSrcUrl)
    {
        throw "Connected to wrong Source site"
    }

	Write-Output "  Connecting Destination site"
    $dstSite = Connect-Site -Url $fullDstUrl -Credential $global:ocred -ErrorAction Stop
    if (-Not $dstSite)
    {
        throw "Can't connect Destination site"
    }
    if ($dstSite.Address.AbsoluteUri -notmatch $fullDstUrl)
    {
        throw "Connected to wrong Destination site"
    }

	Write-Output "  Migrating"
    $result = Copy-Site -Site $srcSite -DestinationSite $dstSite -Merge -Subsites -InsaneMode -MappingSettings $mappingSettings -CopySettings $copySettings -ForceNewListExperience -Verbose #-WaitForImportCompletion 

	Write-Output "  Reporting"
    $result
    Export-Report $result -Path "$PSScriptRoot\..\logs\$($alias)-$(get-date -Format 'yyyyMMddhhmmss').xlsx" -Overwrite

}

Stop-Transcript
