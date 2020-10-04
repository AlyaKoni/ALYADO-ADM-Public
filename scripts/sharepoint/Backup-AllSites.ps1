#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting: 2020

    This file is part of the Alya Base Configuration.
    The Alya Base Configuration is free software: you can redistribute it
	and/or modify it under the terms of the GNU General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
	Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    Alya Basis Konfiguration ist Freie Software: Sie koennen es unter den
	Bedingungen der GNU General Public License, wie von der Free Software
	Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veroeffentlichten Version, weiter verteilen und/oder modifizieren.
    Alya Basis Konfiguration wird in der Hoffnung, dass es nuetzlich sein wird,
	aber OHNE JEDE GEWAEHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewaehrleistung der MARKTFAEHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
	https://www.gnu.org/licenses/gpl-3.0.txt

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    22.09.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$backupLocation = $null, #Defaults to "$($AlyaData)\sharepoint\Backup"
    [ValidateSet("Fast","Detailed")]
    [string]$exportMode = "Fast" #Fast, Detailed
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Backup-AllSites-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "SharePointPnPPowerShellOnline" -exactVersion "3.23.2007.1" #TODO Upgrade after bug is fixed https://github.com/pnp/PnP-PowerShell/issues/2849

# Constants
if (-Not $backupLocation)
{
    $backupLocation = "$($AlyaData)\sharepoint\Backup"
}
if (-Not (Test-Path $backupLocation))
{
    $tmp = New-Item -Path $backupLocation -ItemType Directory -Force
}

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Backup-AllSites | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Backup all SharePoint sites to $($backupLocation)" -ForegroundColor Cyan

function Get-ExportObject(
    $obj,
    $level=0,
    $maxlevel=2,
    [bool]$exportContentTypes = $false,
    [bool]$exportFields = $false,
    [bool]$exportLists = $false,
    [bool]$exportNavigation = $false,
    [bool]$exportFolders = $false
)
{
    $expObj = New-Object PSObject
    if ($level -eq 0)
    {
        $global:allExported = @()
    }
    if ($level -le $maxlevel)
    {
        Write-Host ("".PadLeft($level*2, " ") + "obj $($obj.GetType().Name)")
        if ($obj.GetType().ToString() -like "*SharePoint.Client*")
        {
            if ($obj.Path)
            {
                if (-Not $global:allExported.Contains($obj.Path))
                {
                    $global:allExported += $obj.Path
                }
                else
                {
                    return $obj.Path
                }
            }
            foreach($prop in $obj.PSObject.Properties)
            {
                try
                {
                    $tmp = Get-PnPProperty -ClientObject $obj -Property $prop.Name
                } catch {}
            }
        }
        foreach($prop in $obj.PSObject.Properties)
        {
            if (-Not [string]::IsNullOrEmpty($prop.Name))
            {
                Write-Host ("".PadLeft($level*2, " ") + "  prp " + $prop.Name + " level " + $level)
                if ($prop.Name -eq "TypedObject" -or $prop.Name -like "*Parent*" -or $prop.Name -like "*SecurableObject*" -or `
                    $prop.Name -like "*PushNotification*" -or $prop.Name -eq "Forms"-or $prop.Name -eq "TimeZones"-or $prop.Name -eq "RootWeb"-or `
                    ($prop.Name -eq "Context" -and $level -gt 0) -or `
                    (-Not $exportContentTypes -and $prop.Name -like "*ContentTypes") -or `
                    (-Not $exportFields -and $prop.Name -like "*Fields") -or `
                    (-Not $exportLists -and $prop.Name -like "*Lists*") -or `
                    (-Not $exportNavigation -and $prop.Name -like "*Navigation*") -or `
                    (-Not $exportFolders -and $prop.Name -like "*Folder*")
                )
                { continue }
                $value = $null
                if ((-Not $prop.Value) -or ($prop.Value.GetType().IsValueType) -or ($prop.Value.GetType().ToString() -notlike "*SharePoint.Client*"))
                {
                    <#
                    if (-Not $prop.Value)
                    {
                        Write-Host ("".PadLeft($level*2, " ") + "  val direct null")
                    }
                    else
                    {
                        Write-Host ("".PadLeft($level*2, " ") + "  val direct $($prop.Value.GetType().ToString())")
                    }
                    #>
                    $value = ""+$prop.Value
                }
                else
                {
                    $cnt = 0
                    $cntMem = Get-Member -InputObject $prop.Value -Name Count
                    if ($cntMem)
                    {
                        $cnt = $prop.Value.Count
                    }
                    else
                    {
                        $cntMem = Get-Member -InputObject $prop.Value -Name Length
                        if ($cntMem)
                        {
                            $cnt = $prop.Value.Length
                        }
                        else
                        {
                            $cnt = ($prop.Value | Measure-Object | Select-Object Count).Count
                        }
                    }
                    if ($cnt -gt 1)
                    {
                        #Write-Host ("".PadLeft($level*2, " ") + "  val object list $($prop.Value.GetType().ToString())")
                        $value = @()
                        try {
                        foreach($ob in $prop.Value)
                        {
                            $value += Get-ExportObject -obj $ob -level ($level+1) -maxlevel $maxlevel
                        }
                        } catch {}
                    }
                    else
                    {
                        #Write-Host ("".PadLeft($level*2, " ") + "  val object $($prop.Value.GetType().ToString())")
                        $value = Get-ExportObject -obj $prop.Value -level ($level+1) -maxlevel $maxlevel
                    }
                }
                $expObj | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $value -Force
            }
        }
    }
    return $expObj
}

function Download-FolderRecursive($folderObj, $parentDir)
{
    $items = @(Get-PnPFolderItem -FolderSiteRelativeUrl $folderObj.ServerRelativeUrl)
    foreach($item in $items)
    {
        $itemPath = $item.ServerRelativeUrl -replace "^$(([Uri]$item.Context.Url).AbsolutePath)/",""
        $folderPath = Join-Path $parentDir $item.ServerRelativeUrl.Replace("/","\")
        Write-Host $folderPath
        if ($item.GetType().Name -eq "Folder")
        {
            if(-Not (Test-Path $folderPath))
            {
                $tmp = New-Item -Path $folderPath -ItemType Directory -Force
            }
            Download-FolderRecursive -folderObj $item -parentDir $parentDir
        }
        else 
        {
            $destinationFolderPath = Join-Path $parentDir ((Split-Path $itemPath).Replace("/","\"))
            if(-Not (Test-Path $destinationFolderPath))
            {
                $tmp = New-Item -Path $destinationFolderPath -ItemType Directory -Force
                if(-Not (Test-Path $destinationFolderPath))
                {
                    Start-Sleep -Seconds 1
                }
            }
            try
            {
                Get-PnPFile -Url $item.ServerRelativeUrl -Path $destinationFolderPath -AsFile -Force # Latest version
                $ctx= Get-PnPContext
                $ctx.Load($item.Versions)
                $ctx.ExecuteQuery()
                foreach ($version in $item.Versions)
                {
                    $versionValue = $version.VersionLabel
                    $str = $version.OpenBinaryStream()
                    $ctx.ExecuteQuery()
                    $filename =  (Split-Path $item.ServerRelativeUrl -Leaf) + "." + $versionValue
                    $filepath = Join-Path $destinationFolderPath $filename
                    $fs = New-Object IO.FileStream $filepath ,'Append','Write','Read'
                    $str.Value.CopyTo($fs) # Older version
                    $fs.Close()
                }
            } catch
            { 
                Write-Error "Download failed: $($_.Exception)" -ErrorAction Continue
            }
        }
    }
}

Write-Host "Connecting to SharePoint Online administration" -ForegroundColor Cyan
LoginTo-PnP -Url $AlyaSharePointAdminUrl

#Traverse site collections
Write-Host "Getting all site collections" -ForegroundColor Cyan
$sites = Get-PnPTenantSite -Detailed
foreach($site in $sites)
{
    $expSiteCol = $site
    $siteUrl = $site.Url
    if (-Not $siteUrl.Contains("-my") -and -Not $siteUrl.Contains("/portals") -and -Not $siteUrl.Contains("/search"))
    {
        Write-Host "Working on site collection $($siteUrl)" -ForegroundColor Cyan

        ReloginTo-PnP -Url $siteUrl
        if ($exportMode -eq "Detailed")
        {
            $site = Get-PnPSite
            $expSite = Get-ExportObject -obj $site -level 0 -maxlevel 2
        }
        else
        {
            $expSite = Invoke-PnPSPRestMethod -Url "/_api/site"
        }

        ReloginTo-PnP -Url $siteUrl
        $web = Get-PnPWeb
        if ($exportMode -eq "Detailed")
        {
            $expWeb = Get-ExportObject -obj $web -level 0 -maxlevel 2
        }
        else
        {
            $expWeb = Invoke-PnPSPRestMethod -Url "/_api/web"
        }

        $dirName = $siteUrl.Replace("://","_").Replace("/","_").TrimEnd("_")
        $expDir = Join-Path $backupLocation $dirName
        Write-Host "Exporting to $($expDir)"
        if ((Test-Path $expDir -PathType Container))
        {
            Write-Host "Cleaning last export"
            Remove-Item -Path $expDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        $tmp = New-Item -Path $expDir -ItemType Directory -Force -ErrorAction SilentlyContinue

        if ($expSiteCol.Template -ne "RedirectSite#0")
        {
            Write-Host "Exporting lists"
            ReloginTo-PnP -Url $siteUrl
            $lists = Get-PnpList -Includes @("ID", "Fields", "RootFolder")
            foreach($list in $lists)
            {
                try
                {
                    $relUrl = $list.RootFolder.ServerRelativeUrl.Replace($web.ServerRelativeUrl, "")
                    if ($web.ServerRelativeUrl -eq "/")
                    {
                        $relUrl = $list.RootFolder.ServerRelativeUrl.TrimStart("/")
                    }
                    Write-Host "Exporting $($relUrl)"
                    $listDir = Join-Path $expDir $relUrl.Replace("/","\")
                    if (-Not (Test-Path $listDir -PathType Container))
                    {
                        $tmp = New-Item -Path $listDir -ItemType Directory -Force
                    }

                    ReloginTo-PnP -Url $siteUrl
                    if ($exportMode -eq "Detailed")
                    {$resp
                        $expList = Get-ExportObject -obj $list -level 0 -maxlevel 2 -exportFields $true -exportLists $true -exportContentTypes $true -exportFolders $true
                    }
                    else
                    {
                        $expList = Invoke-PnPSPRestMethod -Url ("/_api/web/lists(guid'$($list.Id.Guid)')")
                    }

                    $allItems = @()
                    if ($exportMode -eq "Detailed")
                    {
                        $items = Get-PnPListItem -List $list -PageSize 500
                        foreach($item in $items)
                        {
                            $allItems += Get-ExportObject -obj $item -level 0 -maxlevel 2
                        }
                    }
                    else
                    {
                        $allItems = Invoke-PnPSPRestMethod -Url ("/_api/web/lists(guid'$($list.Id.Guid)')/items")
                    }

                    $allItems | ConvertTo-JSON -Depth 3 | Set-Content -Path (Join-Path $listDir "listItems.metadata") -Force
                    $expList | ConvertTo-JSON -Depth 3 | Set-Content -Path (Join-Path $listDir "listDefinition.metadata") -Force
                } catch
                {
                    Write-Error "Error exporting list: $($_.Exception)" -ErrorAction Continue
                }
            }

            Write-Host "Exporting files"
            $web = Get-PnPWeb -Includes "RootFolder"

            if ((Test-Path "C:\AlyaExport"))
            {
                cmd /c rmdir "C:\AlyaExport"
            }
            cmd /c mklink /d "C:\AlyaExport" "$expDir"
            if (-Not (Test-Path "C:\AlyaExport"))
            {
                throw "Not able to create symbolic link"
            }
            Download-FolderRecursive -folderObj $web.RootFolder -parentDir "C:\AlyaExport"
            if ((Test-Path "C:\AlyaExport"))
            {
                cmd /c rmdir "C:\AlyaExport"
            }
        }

        $expSiteCol | ConvertTo-JSON | Set-Content -Path (Join-Path $expDir "siteCollectionDefinition.metadata") -Force
        $expSite | ConvertTo-JSON | Set-Content -Path (Join-Path $expDir "siteDefinition.metadata") -Force
        $expWeb | ConvertTo-JSON | Set-Content -Path (Join-Path $expDir "webDefinition.metadata") -Force
    }
}

#Stopping Transscript
Stop-Transcript