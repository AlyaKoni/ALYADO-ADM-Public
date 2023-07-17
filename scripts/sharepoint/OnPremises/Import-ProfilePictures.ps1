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
    13.03.2019 Konrad Brunner       Initial Version


IMPORTANT!!
The script expects, images in $picDir are named like $upn.$ext

#>

# Parameters
[CmdletBinding()]
Param(
    $picDir = $null #Defaults to "$($AlyaData)\sharepoint\ProfilePictures"
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\onprem\Import-ProfilePictures-$($AlyaTimeString).log" | Out-Null

#Checking modules
Check-Module "Microsoft.SharePoint.PowerShell"
Add-PSSnapin "Microsoft.SharePoint.PowerShell" -ErrorAction Stop

# =============================================================
# SharePoint OnPrem stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Import-ProfilePictures | OnPrem" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
if (-Not $picDir)
{
    $picDir = "$($AlyaData)\sharepoint\ProfilePictures"
}
$mySiteUrl = $AlyaSharePointOnPremMySiteUrl

function Upload-PhotosToSP
{
    Param
    (
        [parameter(Mandatory=$true)]$image
    )
    $mySiteHostSite = Get-SPSite $mySiteUrl
    $mySiteHostWeb = $mySiteHostSite.OpenWeb()
    $context = Get-SPServiceContext $mySiteHostSite
    $profileManager = New-Object Microsoft.Office.Server.UserProfiles.UserProfileManager($context)
    try
    {   
        $spPhotosFolder = $mySiteHostWeb.GetFolder("User Photos")
        $spFullPath = $spPhotosFolder.Url + "/" + $image.Name
        $spFile = $spPhotosFolder.Files.Add($spFullPath, $image.OpenRead(), $true)
        $spImagePath = $mySiteHostWeb.Url + "/" + $spFile.Url
        $upn = $image.Name -replace $image.Extension, ""
        $accName = $AlyaSharePointOnPremClaimPrefix + $upn
        if ($profileManager.UserExists($accName))
        {
            $up = $profileManager.GetUserProfile($accName)
            $up["PictureURL"].Value = $spImagePath
            $up.Commit()
        }
        else
        {
            write-host "Profile for user"$upn "cannot be found"
        }
    }
    catch
    { 
        write-host "The script has stopped because there has been an error: "$image
    }
    finally
    {
        $mySiteHostWeb.Dispose()
        $mySiteHostSite.Dispose()
    }
}

$pics = Get-ChildItem -Path $picDir -File
foreach($pic in $pics)
{
    Write-Host "Importing $($pic.Name)"
    Upload-PhotosToSP -image $pic
}

Write-Host "Updating Photo Store"
Update-SPProfilePhotoStore -MySiteHostLocation $mySiteUrl

#Stopping Transscript
Stop-Transcript
