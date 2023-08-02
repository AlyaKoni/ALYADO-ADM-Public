#Requires -Version 7.0

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
    18.06.2023 Konrad Brunner       Initial Version

IMPORTANT!!
The script expects, images in $picDir are named like $upn.$ext
Picture sizes:
    SP-S 48*48
    SP-M 72*72
    SP-L 200*200

#>

# Parameters
[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\microsoft365\ProfilePictures\Import-ProfilePicsToSpo-$($AlyaTimeString).log" | Out-Null

#Prepare PicDir
$picDir = "$($AlyaData)\aad\ProfilePictures"
if (-Not (Test-Path $picDir))
{
    New-Item -Path $picDir -ItemType Directory -Force
}
Write-Host "Profile pictures will be imported from:"
Write-Host "$picDir`n"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "User.Read.All","Contacts.Read"
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Import-ProfilePicsToSpo | M365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
$myUrl = "https://$AlyaTenantNameId-my.sharepoint.com/"
$myCon = LoginTo-PnP -Url $myUrl
$docLibNameEn = "User Photos"
$docLibNameDe = "Benutzerfotos"
$folderNameEn = "Profile Pictures"
$folderNameDe = "Profilbilder"

Write-Host "Getting list"
$list = $null
try { $list = Get-PnPList -Connection $myCon -Identity $docLibNameEn } catch {}
if (-Not $list)
{
    try { $list = Get-PnPList -Connection $myCon -Identity $docLibNameDe } catch {}
}
if (-Not $list)
{
    throw "Can't find list '$docLibNameEn'"
}

function Upload-SpoPicture($con, $folderUrl, $fileName, $size, $img)
{
    [int32]$new_width = $size
    [int32]$new_height = $size
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

    $temp = New-TemporaryFile
    [System.Io.File]::WriteAllBytes($temp, $binary)
    Add-PnPFile -Connection $con -Path $temp -Folder $folderUrl -NewFileName $fileName -CheckinType MajorCheckIn -CheckInComment "Uploaded by Alya scipt"
    Remove-Item -Path $temp -Force
}

Write-Host "Uploading Profile Pictures"
$pics = Get-ChildItem -Path $picDir -File
foreach($pic in $pics)
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
    Write-Host "User $upn"
    $user = $null
    try { $user = Get-MgBetaUser -UserId $upn } catch{}
    if ($user)
    {
        Write-Host "  Uploading"
        $image = [System.Drawing.Image]::FromFile($pic)
        Upload-SpoPicture -con  $myCon -folderUrl "$docLibNameEn/$folderNameDe" -fileName "$($user.Id)_SThumb.jpg" -size 48 -img $image
        Upload-SpoPicture -con  $myCon -folderUrl "$docLibNameEn/$folderNameDe" -fileName "$($user.Id)_MThumb.jpg" -size 72 -img $image
        Upload-SpoPicture -con  $myCon -folderUrl "$docLibNameEn/$folderNameDe" -fileName "$($user.Id)_LThumb.jpg" -size 200 -img $image
    }
    else
    {
        Write-Host "  user not found!"
    }
}

#Stopping Transscript
Stop-Transcript
