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


    History:
    Date       Author     Description
    ---------- -------------------- ----------------------------
    18.06.2023 Konrad Brunner       Initial Version


IMPORTANT!!
The script expects, images in $picDir are named like $upn.$ext

#>

# Parameters
[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\microsoft365\ProfilePictures\Prepare-ProfilePics-$($AlyaTimeString).log" | Out-Null

#Prepare PicDir
$picDir = "$($AlyaData)\aad\ProfilePictures"
if (-Not (Test-Path $picDir))
{
    New-Item -Path $picDir -ItemType Directory -Force
}
$picDirAAD = "$($AlyaData)\aad\ProfilePictures\AAD"
if (-Not (Test-Path $picDirAAD))
{
    New-Item -Path $picDirAAD -ItemType Directory -Force
}
$picDirEXO = "$($AlyaData)\aad\ProfilePictures\EXO"
if (-Not (Test-Path $picDirEXO))
{
    New-Item -Path $picDirEXO -ItemType Directory -Force
}
$picDirSPO = "$($AlyaData)\aad\ProfilePictures\SPO"
if (-Not (Test-Path $picDirSPO))
{
    New-Item -Path $picDirSPO -ItemType Directory -Force
}

# =============================================================
# Local stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Local | Prepare-ProfilePics | ONPREMISES" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
Write-Host "Getting all pictures"
$pics = Get-ChildItem -Path $picDir -File
$picsAAD = Get-ChildItem -Path $picDirAAD -File
$picsEXO = Get-ChildItem -Path $picDirEXO -File
$picsSPO = Get-ChildItem -Path $picDirSPO -File

Write-Host "Getting all upn's"
$upns = @()
Write-Host " from $picDir"
foreach($pic in $pics)
{
    $upn = $pic.Name -replace $pic.Extension, ""
    if ($upns -notcontains $upn)
    {
        $upns += $upn
    }
}
Write-Host " from $picDirAAD"
foreach($pic in $picsAAD)
{
    $upn = $pic.Name -replace $pic.Extension, ""
    if ($upns -notcontains $upn)
    {
        $upns += $upn
    }
}
Write-Host " from $picDirEXO"
foreach($pic in $picsEXO)
{
    $upn = $pic.Name -replace $pic.Extension, ""
    if ($upns -notcontains $upn)
    {
        $upns += $upn
    }
}
Write-Host " from $picDirSPO"
foreach($pic in $picsSPO)
{
    $filename = $pic.Name -replace $pic.Extension, ""
    $parts = $filename.Split("_")
    $upn = $parts[0]
    if (-Not $upn.contains("@"))
    {
        $upn = "$($parts[0])_$($parts[1])"
    }
    if (-Not $upn.contains("@"))
    {
        $upn = "$($parts[0])_$($parts[1])_$($parts[2])"
    }
    if ($upn.Contains("UNKNOWN")) { continue }
    if (-Not $upn.Contains("@")) { continue }
    if ($upns -notcontains $upn)
    {
        $upns += $upn
    }
}

Write-Host "Comparing pictures"
foreach($upn in $upns)
{
    Write-Host "User $upn"
    $picFileToUse = $null
    $picItemToUse = $null
    
    $picFile = "$picDir\$upn.jpg"
    if (Test-Path $picFile)
    {
        $picFileToUse = $picFile
        $picItemToUse = Get-Item -Path $picFileToUse
    }
    $picFile = "$picDirAAD\$upn.jpg"
    if (Test-Path $picFile)
    {
        $picItem = Get-Item -Path $picFile
        if ($picItem.Length -gt $picItemToUse.Length)
        {
            $picFileToUse = $picFile
            $picItemToUse = Get-Item -Path $picFileToUse
        }
    }
    $picFile = "$picDirEXO\$upn.jpg"
    if (Test-Path $picFile)
    {
        $picItem = Get-Item -Path $picFile
        if ($picItem.Length -gt $picItemToUse.Length)
        {
            $picFileToUse = $picFile
            $picItemToUse = Get-Item -Path $picFileToUse
        }
    }
    $testFile = Get-ChildItem -Path $picDirSPO -Filter "$upn*LThumb.jpg"
    if ($testFile)
    {
        $picFile = $testFile.FullName
        $picItem = Get-Item -Path $picFile
        if ($picItem.Length -gt $picItemToUse.Length)
        {
            $picFileToUse = $picFile
            $picItemToUse = Get-Item -Path $picFileToUse
        }
    }

    $picFile = "$picDir\$upn.jpg"
    if ($picFileToUse -ne $picFile)
    {
        Copy-Item -Path $picFileToUse -Destination "$picFile"
    }

}

#Stopping Transscript
Stop-Transcript
