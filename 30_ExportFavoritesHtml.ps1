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


    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    11.05.2021 Konrad Brunner       Initial version
#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\30_ExportFavoritesHtml-$($AlyaTimeString).log" | Out-Null

#Main
function ExportUrls($baseDir, $actDir, $lastNode)
{
    $actNode = $lastNode
    $dirName = Make-PascalCase -string $actDir.BaseName
    if ($dirName -ne "Scripts")
    {
        if ($dirName -ne "Links")
        {
            $lastNode["Subs"][$dirName] = @{}
            $lastNode["Subs"][$dirName]["Subs"] = @{}
            $actNode = $lastNode["Subs"][$dirName]
            $actNode["Parent"] = $lastNode
            $actNode["HasUrl"] = $false
            $actNode["Dir"] = $actDir.FullName
            $actNode["Name"] = $dirName
        }
        else
        {
            $actNode = $lastNode
        }
    }
    else
    {
        $actNode["Dir"] = $actDir.FullName
    }

    $urls = Get-ChildItem -Path $actDir.FullName -Filter "*.url"
    if ($urls -and $urls.Count -gt 0)
    {
        $urlNode = $null
        foreach($url in $urls)
        {
            if (-Not $urlNode) {
                $actNode["Urls"] = @{}
                $urlNode =  $actNode["Urls"]
            }
            $cnt = Get-Content -Path $url.FullName -Force
            $cntReg = [RegEx]"URL=(\S*)"
            $http = $cntReg.Match($cnt).Groups[1].Value
            $urlNode[$url.BaseName] = $http
        }
        $actNode["HasUrl"] = $true
        $parentNode = $actNode["Parent"]
        while ($parentNode)
        {
            $parentNode["HasUrl"] = $true
            $parentNode = $parentNode["Parent"]
        }
    }

    $dirs = Get-ChildItem -Path $actDir.FullName -Directory
    foreach($dir in $dirs)
    {
        ExportUrls -baseDir $baseDir -actDir $dir -lastNode $actNode
    }
}

$base = Get-Item -Path "$PSScriptRoot\scripts"
$nodes = @{}
$nodes["Subs"] = @{}
ExportUrls -baseDir $base -actDir $base -lastNode $nodes
$ED = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime() -uformat "%s"))
$Global:fileContent = ""
$Global:fileContent += "<!DOCTYPE NETSCAPE-Bookmark-file-1>`n"
$Global:fileContent += "<META HTTP-EQUIV=`"Content-Type`" CONTENT=`"text/html; charset=UTF-8`">`n"
$Global:fileContent += "<TITLE>Bookmarks</TITLE>`n"
$Global:fileContent += "<H1>Bookmarks</H1>`n"
$Global:fileContent += "<DL><p>`n"
$Global:fileContent += "  <DT><H3 ADD_DATE=`"$ED`" LAST_MODIFIED=`"$ED`" PERSONAL_TOOLBAR_FOLDER=`"true`">Favoritenleiste</H3>`n"
$Global:fileContent += "  <DL><p>`n"
function ProcessNode($node, $parent, $level)
{
    $parentDir = $parent.Dir
    $nodeDir = $node.Dir
    if ($parentDir -eq $nodeDir)
    {
        $nodeDir = "Alya Links"
    }
    else
    {
        $nodeDir = $node["Name"]
    }
    if ($node.HasUrl)
    {
        $space = "".PadLeft($level*2)
        $Global:fileContent += "$($space)<DT><H3 ADD_DATE=`"$ED`" LAST_MODIFIED=`"$ED`">$nodeDir</H3>`n"
        $Global:fileContent += "$($space)<DL><p>`n"
        $keys = $node.Subs.Keys | Sort-Object
        foreach($key in $keys)
        {
            ProcessNode -node $node.Subs[$key] -parent $node -level ($level+1)
        }
        if ($node.Urls -and $node.Urls.Count -gt 0)
        {
            $keys = $node.Urls.Keys | Sort-Object
            foreach($key in $keys)
            {
                $Global:fileContent += "$($space)  <DT><A ADD_DATE=`"$ED`" HREF=`"$($node.Urls[$key])`">$($key)</A>`n"
            }
        }
        $Global:fileContent += "$($space)</DL><p>`n"
    }
}
ProcessNode -node $nodes -parent $nodes -level 2
$Global:fileContent += "  </DL><p>`n"
$Global:fileContent += "</DL><p>`n"
$Global:fileContent | Set-Content -Path "$AlyaData\Favorites.html"
Write-Host "Favorites exported to $AlyaData\Favorites.html"
notepad "$AlyaData\Favorites.html"

#Stopping Transscript
Stop-Transcript
