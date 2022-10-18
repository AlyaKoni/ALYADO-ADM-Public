#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2021

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
    29.09.2020 Konrad Brunner       Initial Version
    23.10.2021 Konrad Brunner       Added apps path

#>

[CmdletBinding()]
Param(
    [string]$CreateOnlyAppWithName = $null,
    [string]$ContinueAtAppWithName = $null,
    [string]$AppsPath = "Win32Apps"
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Create-IntuneWin32Packages-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$DataRoot = Join-Path (Join-Path $AlyaData "intune") $AppsPath
if (-Not (Test-Path $DataRoot))
{
    $tmp = New-Item -Path $DataRoot -ItemType Directory -Force
}

& "$PSScriptRoot\Download-Win32AppPrepTool.ps1"

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Create-IntuneWin32Packages | Local" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$packageDirs = Get-ChildItem -Path $DataRoot -Directory
$continue = $true
foreach($packageDir in $packageDirs)
{
    if ($ContinueAtAppWithName -and $packageDir.Name -eq $ContinueAtAppWithName) { $continue = $false }
    if ($ContinueAtAppWithName -and $continue) { continue }
    if ($CreateOnlyAppWithName -and $packageDir.Name -ne $CreateOnlyAppWithName) { continue }
    if ($packageDir.Name -like "*unused*" -or $packageDir.Name -like "*donotuse*") { continue }
    Write-Host "Updating package $($packageDir.Name)" -ForegroundColor $CommandInfo

    Write-Host "  Cleaning content directory"
    $contentPath = Join-Path $packageDir.FullName "Content"
    $contentZipPath = Join-Path $packageDir.FullName "ContentZip"
    $scriptPath = Join-Path $packageDir.FullName "Scripts"
    $packagePath = Join-Path $packageDir.FullName "Package"
    if ((Test-Path $contentPath))
    {
        try
        {
            $tmp = Remove-Item -Path $contentPath -Recurse -Force -Confirm:$false
        } catch
        {
            Write-Warning "Was not able to delete directory. Please delete $contentPath.deleteMe by hand"
            $tmp = Move-Item -Path $contentPath -Destination "$contentPath.deleteMe"
        }
    }
    $tmp = New-Item -Path $contentPath -ItemType Directory
    if ((Test-Path $packagePath))
    {
        try
        {
            $tmp = Remove-Item -Path $packagePath -Recurse -Force -Confirm:$false
        } catch
        {
            Write-Warning "Was not able to delete directory. Please delete $packagePath.deleteMe by hand"
            $tmp = Move-Item -Path $packagePath -Destination "$packagePath.deleteMe"
        }
    }
    $tmp = New-Item -Path $packagePath -ItemType Directory

    Write-Host "  Updating scripts if required"
    $prepareScript = Get-Item -Path (Join-Path $packageDir.FullName "PrepareScripts.ps1") -ErrorAction SilentlyContinue
    if ($prepareScript)
    {
        & "$($prepareScript.FullName)"
        Start-Sleep -Seconds 2
    }

    Write-Host "  Copying scripts"
    if ((Test-Path $scriptPath))
    {
        Get-ChildItem -Path $scriptPath | Copy-Item -Destination $contentPath
    }

    Write-Host "  Downloading installer"
    $downloadShortcut = Get-Item -Path (Join-Path $packageDir.FullName "Download.url") -ErrorAction SilentlyContinue
    if (-Not $downloadShortcut)
    {
        $downloadScript = Get-Item -Path (Join-Path $packageDir.FullName "Download.ps1") -ErrorAction SilentlyContinue
        if ($downloadScript)
        {
            & "$($downloadScript.FullName)"
        }
    }
    else
    {
        $downloadUpdateScript = Get-Item -Path (Join-Path $packageDir.FullName "DownloadLinkUpdate.ps1") -ErrorAction SilentlyContinue
        if ($downloadUpdateScript)
        {
            & "$($downloadUpdateScript.FullName)"
        }
        $profile = [Environment]::GetFolderPath("UserProfile")
        $downloads = $profile+"\downloads"
        $lastfilename = $null
        $file = Get-ChildItem -path $downloads | sort LastWriteTime | select -last 1
        if ($file)
        {
            $lastfilename = $file.Name
        }
        $filename = $null
        $content = $downloadShortcut | Get-Content -Raw -Encoding UTF8
        [regex]$regex = "URL=.*"
        $downloadUrl = [regex]::Match($content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value.Substring(4)
        $attempts = 10
        while ($attempts -ge 0)
        {
            Write-Host "    from $downloadUrl"
            Write-Host "      please don't start any other download!" -ForegroundColor $CommandWarning
            try {
                #TODO Better download!
                start $downloadUrl
                do
                {
                    Start-Sleep -Seconds 10
                    $file = Get-ChildItem -path $downloads | sort LastWriteTime | select -last 1
                    if ($file)
                    {
                        $filename = $file.Name
                        if ($filename.Contains("crdownload")) { $filename = $lastfilename }
                        if ($filename.Contains("partial")) { $filename = $lastfilename }
                    }
                } while ($lastfilename -eq $filename)
                $attempts = -1
            } catch {
                Write-Host "Catched exception $($_.Exception.Message)" -ForegroundColor $CommandError
                Write-Host "Retrying $attempts times" -ForegroundColor $CommandError
                $attempts--
                if ($attempts -lt 0) { throw }
                Start-Sleep -Seconds 10
            }
        }
        Start-Sleep -Seconds 3
        if ($filename)
        {
            $sourcePath = $downloads+"\"+$filename
            $filename = $filename -replace "\s\(.*\)", ""
            $destPath = $contentPath+"\"+$filename
            Move-Item -Path $sourcePath -Destination $destPath -Force
            if ($filename.EndsWith(".zip"))
            {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                $zip = [System.IO.Compression.ZipFile]::OpenRead($destPath)
                $entries = $zip.Entries | Where-Object { $_.Name -like "*.msi" }
                if ($entries.Count -gt 0)
                {
                    foreach($entry in $entries)
                    {
                        $entryPath = $contentPath+"\"+$entry.Name
                        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $entryPath, $true)
                    }
                    $zip.Dispose()
                    Remove-Item -Path $destPath -Force
                }
            }
        }
        else
        {
            Write-Error "Was not able to download installer" -ErrorAction Continue
        }
    }

    Write-Host "  Preparing content zip"
    if ((Test-Path $contentZipPath))
    {
        $zipPath = Join-Path $contentPath "Content.zip"
        Compress-Archive -Path $contentZipPath -DestinationPath $zipPath
        $zipFile = Get-Item -Path $zipPath
    }

    Write-Host "  Preparing version if required"
    $incrementScript = Get-Item -Path (Join-Path $packageDir.FullName "PrepareVersion.ps1") -ErrorAction SilentlyContinue
    if ($incrementScript)
    {
        & "$($incrementScript.FullName)"
        Start-Sleep -Seconds 2
        $versionFile = Get-Item -Path (Join-Path $packageDir.FullName "version.json") -ErrorAction SilentlyContinue
        Copy-Item -Path $versionFile -Destination $contentPath -Force
    }

    Write-Host "  Packaging"
    $tool = Join-Path (Join-Path $AlyaTools "IntuneWinAppUtil") "IntuneWinAppUtil.exe"

    $firstTry = "msi"
    $secondTry = "exe"
    $packagePreference = Get-Item -Path (Join-Path $packageDir.FullName "PackagePreference.txt") -ErrorAction SilentlyContinue
    if ($packagePreference)
    {
        $packagePreference = $packagePreference | Get-Content
        if ($packagePreference -eq "exe")
        {
            $firstTry = "exe"
            $secondTry = "msi"
        }
    }

    $toInstall = Get-ChildItem -Path $contentPath -Filter "*.$firstTry" | Sort-Object -Property Name
    if (-Not $toInstall)
    {
        $toInstall = Get-ChildItem -Path $contentPath -Filter "*.$secondTry" | Sort-Object -Property Name
        if (-Not $toInstall)
        {
            $toInstall = Get-ChildItem -Path $contentPath -Filter "Install.cmd"
            if (-Not $toInstall)
            {
                $toInstall = Get-ChildItem -Path $contentPath -Filter "Install.ps1"
                if (-Not $toInstall)
                {
                    Write-Error "Can't find installer file for this package" -ErrorAction Continue
                    continue
                }
            }
        }
    }
    if ($toInstall.Count -gt 1)
    {
        $toInstall = $toInstall[0]
    }

    $Command = "& `"$tool`" -c `"$contentPath`" -s `"$($toInstall.Name)`" -o `"$packagePath`" -q"
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
    $EncodedCommand =[Convert]::ToBase64String($Bytes)
    Start-Process PowerShell.exe -ArgumentList "-EncodedCommand $EncodedCommand" -Wait -NoNewWindow
    
    $intunewinFile = Get-ChildItem -Path $packagePath -Filter "*.intunewin"
    if (-Not $intunewinFile)
    {
        Write-Error "Intune package not created!" -ErrorAction Continue
    }
    if ($intunewinFile.Count -gt 1)
    {
        Write-Warning "Found more than 1 Intune packages!"
        Write-Warning "Please delete older once"
    }

    Write-Host "  Running post package task if required"
    $incrementScript = Get-Item -Path (Join-Path $packageDir.FullName "PostPackageTask.ps1") -ErrorAction SilentlyContinue
    if ($incrementScript)
    {
        & "$($incrementScript.FullName)"
    }

}

#Stopping Transscript
Stop-Transcript
