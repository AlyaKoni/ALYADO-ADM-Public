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
    01.02.2025 Konrad Brunner       Initial Version


#>

# Parameters
[CmdletBinding()]
Param(
    [bool]$SetOnAllUsers = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Set-ProfilePicsOnAllUsers-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "User.ReadWrite.All"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Set-ProfilePicsOnAllUsers | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
Write-Host "Preparing Profile Picture" -ForegroundColor $CommandInfo
$ppicPath = "$AlyaData\azure\publicStorage\logos\UserProfile.png"
$ppic = Get-Item -Path $ppicPath -ErrorAction SilentlyContinue
if (-Not $ppic)
{
    $pics = Get-ChildItem -Path "$AlyaData\azure\publicStorage\logos\*.*" -Include "*.png","*.jpg"
    $qpics = $pics | Where-Object { $_.Name -like "*Quad*"}
    if ($qpics.Count -gt 0)
    {
        $qpic = Select-Item -list $qpics -message "Pleas eselect the profile picture to be used" -outputMode Single
    }
    if (-Not $qpic)
    {
        $qpic = Select-Item -list $pics -message "Pleas eselect the profile picture to be used" -outputMode Single
    }
    if (-Not $qpic)
    {
        throw "Can't get profile picture to be used"
    }

    Write-Host "  Converting image" -ForegroundColor $CommandInfo
    $img = [System.Drawing.Image]::FromFile($qpic.FullName)
    [int32]$new_width = 648
    [int32]$new_height = 648
    $stream = New-Object -TypeName System.IO.MemoryStream
    $format = [System.Drawing.Imaging.ImageFormat]::Png
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
    [System.IO.File]::WriteAllBytes($ppicPath, $binary)
}

Write-Host "Gettting users" -ForegroundColor $CommandInfo
$users = Get-MgBetaUser -Property "id,userPrincipalName" -All
foreach($user in $users)
{
    Write-Host "Processing $($user.userPrincipalName)"
    $photo = $null
    try { $photo = Get-MgBetaUserPhoto -UserId $user.Id } catch{}
    if ($SetOnAllUsers -or -not $photo)
    {
        Write-Host "  Uploading"
        Set-MgBetaUserPhotoContent -UserId $user.Id -InFile $ppicPath
    }
}

#Stopping Transscript
Stop-Transcript
