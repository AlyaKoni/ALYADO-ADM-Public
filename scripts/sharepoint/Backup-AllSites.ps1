#Requires -Version 7.0
#Requires -RunAsAdministrator

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
    22.09.2020 Konrad Brunner       Initial Version
    20.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules

#>

[CmdletBinding()]
Param(
    [string]$backupLocation = "C:\Temp\Backup", #$null, #Defaults to "$($AlyaData)\sharepoint\Backup"
    [ValidateSet("Fast","Detailed")]
    [string]$exportMode = "Fast" #Fast, Detailed
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Backup-AllSites-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Logins
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

# Constants
if (-Not $backupLocation)
{
    $backupLocation = "$($AlyaData)\sharepoint\Backup"
}
if (-Not (Test-Path $backupLocation))
{
    $null = New-Item -Path $backupLocation -ItemType Directory -Force
}

# Getting app information
Write-Host "Getting app information" -ForegroundColor $CommandInfo
. $PSScriptRoot\Configure-ServiceApplication.ps1

# Checking app certificate
Write-Host "Checking app certificate" -ForegroundColor $CommandInfo
$cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq $AlyaSharePointAppCertificate }
if (-Not $cert)
{
    & "$PSScriptRoot\Install-ServiceApplicationCertificate.ps1"
}

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Backup-AllSites | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Backup all SharePoint sites to $($backupLocation)" -ForegroundColor $CommandInfo

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
                    $null = Get-PnPProperty -Connection $siteCon -ClientObject $obj -Property $prop.Name
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

function Download-FolderRecursive($folderObj, $webUrl, $parentDir)
{
    $url = $folderObj.ServerRelativeUrl
    if ($webUrl -ne "/") { $url = $url.Replace($webUrl, "") }
    $retries = 10
    do
    {
        try
        {
            $items = @(Get-PnPFolderItem -Connection $siteCon -FolderSiteRelativeUrl $url)
            break
        }
        catch
        {
            Write-Error $_.Exception -ErrorAction Continue
            Write-Warning "Retrying $retries times"
            Start-Sleep -Seconds 15
            $retries--
            if ($retries -lt 0) { throw }
        }
    } while ($true)
    foreach($item in $items)
    {
        $itemPath = Join-Path $parentDir $item.ServerRelativeUrl
        if ($webUrl -ne "/") { $itemPath = $itemPath.Replace($webUrl.Replace("/","\"), "") }
        Write-Host $itemPath
        if ($item.GetType().Name -eq "Folder")
        {
            Download-FolderRecursive -folderObj $item -webUrl $webUrl -parentDir $parentDir
        }
        else 
        {
            $folderPath = Split-Path -Path $itemPath
            if(-Not (Test-Path $folderPath))
            {
                $null = New-Item -Path $folderPath -ItemType Directory -Force
                if(-Not (Test-Path $folderPath))
                {
                    Start-Sleep -Seconds 1
                }
            }
            try
            {
                $retries = 10
                do
                {
                    try
                    {
                        Get-PnPFile -Connection $siteCon -Url $item.ServerRelativeUrl -Path $folderPath -AsFile -Force # Latest version
                        $ctx= Get-PnPContext -Connection $siteCon
                        $ctx.Load($item.Versions)
                        $ctx.ExecuteQuery()
                        foreach ($version in $item.Versions)
                        {
                            $versionValue = $version.VersionLabel
                            $str = $version.OpenBinaryStream()
                            $ctx.ExecuteQuery()
                            $filename =  (Split-Path $item.ServerRelativeUrl -Leaf) + "." + $versionValue
                            $filepath = Join-Path $folderPath $filename
                            $fs = New-Object IO.FileStream $filepath ,'Append','Write','Read'
                            $str.Value.CopyTo($fs) # Older version
                            $fs.Close()
                        }
                        break
                    }
                    catch
                    {
                        Write-Error $_.Exception -ErrorAction Continue
                        Write-Warning "Retrying $retries times"
                        Start-Sleep -Seconds 15
                        $retries--
                        if ($retries -lt 0) { throw }
                    }
                } while ($true)
            } catch
            { 
				try { Write-Error ($_.Exception | ConvertTo-Json -Depth 3) -ErrorAction Continue } catch {}
				Write-Error ($_.Exception) -ErrorAction Continue
                Write-Error "Download failed" -ErrorAction Continue
            }
        }
    }
}

Write-Host "Connecting to SharePoint Online administration" -ForegroundColor $CommandInfo
$retries = 10
do
{
    try
    {
        $adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl -ClientId $AlyaSharePointAppId -Thumbprint $AlyaSharePointAppCertificate
        break
    }
    catch
    {
        Write-Error $_.Exception -ErrorAction Continue
        Write-Warning "Retrying $retries times"
        Start-Sleep -Seconds 15
        $retries--
        if ($retries -lt 0) { throw }
    }
} while ($true)

#Traverse site collections
Write-Host "Getting all site collections" -ForegroundColor $CommandInfo
$retries = 10
do
{
    try
    {
        $sites = Get-PnPTenantSite -Connection $adminCon -Detailed
        break
    }
    catch
    {
        Write-Error $_.Exception -ErrorAction Continue
        Write-Warning "Retrying $retries times"
        Start-Sleep -Seconds 15
        $retries--
        if ($retries -lt 0) { throw }
    }
} while ($true)
foreach($site in $sites)
{
    $expSiteCol = $site
    $siteUrl = $site.Url
    if (-Not $siteUrl.Contains("-my") -and -Not $siteUrl.Contains("/portals") -and -Not $siteUrl.Contains("/search"))
    {
        Write-Host "Working on site collection $($siteUrl)" -ForegroundColor $CommandInfo

        $retries = 10
        do
        {
            try
            {
                $siteCon = LoginTo-PnP -Url $siteUrl -ClientId $AlyaSharePointAppId -Thumbprint $AlyaSharePointAppCertificate
                break
            }
            catch
            {
                Write-Error $_.Exception -ErrorAction Continue
                Write-Warning "Retrying $retries times"
                Start-Sleep -Seconds 15
                $retries--
                if ($retries -lt 0) { throw }
            }
        } while ($true)
        $retries = 10
        do
        {
            try
            {
                if ($exportMode -eq "Detailed")
                {
                    $site = Get-PnPSite -Connection $siteCon
                    $expSite = Get-ExportObject -obj $site -level 0 -maxlevel 2
                }
                else
                {
                    $expSite = Invoke-PnPSPRestMethod -Connection $siteCon -Url "/_api/site"
                }
                break
            }
            catch
            {
                Write-Error $_.Exception -ErrorAction Continue
                Write-Warning "Retrying $retries times"
                Start-Sleep -Seconds 15
                $retries--
                if ($retries -lt 0) { throw }
            }
        } while ($true)

        $retries = 10
        do
        {
            try
            {
                $web = Get-PnPWeb -Includes "ServerRelativeUrl", "RootFolder", "RootFolder.ServerRelativeUrl"
                if ($exportMode -eq "Detailed")
                {
                    $expWeb = Get-ExportObject -obj $web -level 0 -maxlevel 2
                }
                else
                {
                    $expWeb = Invoke-PnPSPRestMethod -Connection $siteCon -Url "/_api/web"
                }
                break
            }
            catch
            {
                Write-Error $_.Exception -ErrorAction Continue
                Write-Warning "Retrying $retries times"
                Start-Sleep -Seconds 15
                $retries--
                if ($retries -lt 0) { throw }
            }
        } while ($true)

        $dirName = $siteUrl.Replace("://","_").Replace("/","_").TrimEnd("_")
        $expDir = Join-Path $backupLocation $dirName
        Write-Host "Exporting to $($expDir)"
        if ((Test-Path $expDir -PathType Container))
        {
            Write-Host "Cleaning last export"
            Remove-Item -Path $expDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        $null = New-Item -Path $expDir -ItemType Directory -Force -ErrorAction SilentlyContinue

        if ($expSiteCol.Template -ne "RedirectSite#0")
        {
            Write-Host "Exporting lists"
            $retries = 10
            do
            {
                try
                {
                    $lists = Get-PnpList -Connection $siteCon -Includes @("ID", "Fields", "RootFolder")
                    break
                }
                catch
                {
                    Write-Error $_.Exception -ErrorAction Continue
                    Write-Warning "Retrying $retries times"
                    Start-Sleep -Seconds 15
                    $retries--
                    if ($retries -lt 0) { throw }
                }
            } while ($true)
            
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
                        $null = New-Item -Path $listDir -ItemType Directory -Force
                    }

                    $retries = 10
                    do
                    {
                        try
                        {
                            if ($exportMode -eq "Detailed")
                            {
                                $expList = Get-ExportObject -obj $list -level 0 -maxlevel 2 -exportFields $true -exportLists $true -exportContentTypes $true -exportFolders $true
                            }
                            else
                            {
                                $expList = Invoke-PnPSPRestMethod -Connection $siteCon -Url ("/_api/web/lists(guid'$($list.Id.Guid)')")
                            }
                            break
                        }
                        catch
                        {
                            Write-Error $_.Exception -ErrorAction Continue
                            Write-Warning "Retrying $retries times"
                            Start-Sleep -Seconds 15
                            $retries--
                            if ($retries -lt 0) { throw }
                        }
                    } while ($true)

                    $retries = 10
                    do
                    {
                        try
                        {
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
                                $allItems = Invoke-PnPSPRestMethod -Connection $siteCon -Url ("/_api/web/lists(guid'$($list.Id.Guid)')/items")
                            }
                            break
                        }
                        catch
                        {
                            Write-Error $_.Exception -ErrorAction Continue
                            Write-Warning "Retrying $retries times"
                            Start-Sleep -Seconds 15
                            $retries--
                            if ($retries -lt 0) { throw }
                        }
                    } while ($true)

                    $allItems | ConvertTo-JSON -Depth 3 | Set-Content -Path (Join-Path $listDir "listItems.metadata") -Force
                    $expList | ConvertTo-JSON -Depth 3 | Set-Content -Path (Join-Path $listDir "listDefinition.metadata") -Force
                } catch
                {
					try { Write-Error ($_.Exception | ConvertTo-Json -Depth 3) -ErrorAction Continue } catch {}
					Write-Error ($_.Exception) -ErrorAction Continue
                    Write-Error "Error exporting list" -ErrorAction Continue
                }
            }

            Write-Host "Exporting files"

            if ((Test-Path "C:\AlyaExport"))
            {
                cmd /c rmdir "C:\AlyaExport"
            }
            cmd /c mklink /d "C:\AlyaExport" "$expDir"
            if (-Not (Test-Path "C:\AlyaExport"))
            {
                throw "Not able to create symbolic link"
            }
            Download-FolderRecursive -folderObj $web.RootFolder -webUrl $web.ServerRelativeUrl -parentDir "C:\AlyaExport"
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
