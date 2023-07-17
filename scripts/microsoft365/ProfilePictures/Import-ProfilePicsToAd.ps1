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
    Date       Author     Description
    ---------- -------------------- ----------------------------
    16.06.2023 Konrad Brunner       Initial Version


IMPORTANT!!
The script expects, images in $picDir are named like $upn.$ext
Picture size: 96*96

#>

# Parameters
[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\microsoft365\ProfilePictures\Import-ProfilePicsToAd-$($AlyaTimeString).log" | Out-Null

#Prepare PicDir
$picDir = "$($AlyaData)\aad\ProfilePictures"
if (-Not (Test-Path $picDir))
{
    New-Item -Path $picDir -ItemType Directory -Force
}
Write-Host "Profile pictures will be imported from:"
Write-Host "$picDir`n"

# =============================================================
# aad OnPrem stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AD | Import-ProfilePicsToAd | ONPREMISES" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
$addomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $AlyaLocalDomainName)))
$root = $addomain.GetDirectoryEntry()
$search = [System.DirectoryServices.DirectorySearcher]$root

$pics = Get-ChildItem -Path $picDir -File
foreach($pic in $pics)
{
    $upn = $pic.Name -replace $pic.Extension, ""
    Write-Host "User $upn"
    $search.Filter = "(&(objectclass=user)(objectcategory=person)(userPrincipalName=$upn))"
    $result = $search.FindOne()
    if ($result -ne $null)
    {
        Write-Host "  Converting image"
        $img = [System.Drawing.Image]::FromFile($pic)
        [int32]$new_width = 96
        [int32]$new_height = 96
        $stream = New-Object -TypeName System.IO.MemoryStream
        $format = [System.Drawing.Imaging.ImageFormat]::Jpeg
        if ($img.Width -gt $new_width -or $img.Height -gt $new_height)
        {
            $sw = $new_width / $img.Width
            $sh = $new_height / $img.Height
            $s = [System.Math]::Min($sw,$sh)
            $new_width = $img.Width * $s
            $new_height = $img.Height * $s
            $img2 = New-Object System.Drawing.Bitmap($new_width, $new_height)
            $graphic = [System.Drawing.Graphics]::FromImage($img2)
            $graphic.DrawImage($img, 0, 0, $new_width, $new_height)
            $img2.Save($stream, $format)
            $stream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
        }
        else
        {
            $img.Save($stream, $format)
            $stream.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
        }
        $binary = $stream.ToArray()

        Write-Host "  Uploading"
        $user = $result.GetDirectoryEntry()
        $user.Put("thumbnailPhoto", $binary)
        $user.SetInfo()
    }
    else
    {
        Write-Host "  user not found!"
    }
}

#Stopping Transscript
Stop-Transcript
