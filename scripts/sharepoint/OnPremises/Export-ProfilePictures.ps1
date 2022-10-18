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
    Date       Author     Description
    ---------- -------------------- ----------------------------
    13.03.2019 Konrad Brunner       Initial Version

#>

# Parameters
[CmdletBinding()]
Param(
    $picDir = $null #Defaults to "$($AlyaData)\sharepoint\ProfilePictures"
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\onprem\Export-ProfilePictures-$($AlyaTimeString).log" | Out-Null

#Checking modules
Check-Module "Microsoft.SharePoint.PowerShell"
Add-PSSnapin "Microsoft.SharePoint.PowerShell" -ErrorAction Stop

# =============================================================
# SharePoint OnPrem stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Export-ProfilePictures | OnPrem" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
if (-Not $picDir)
{
    $picDir = "$($AlyaData)\sharepoint\ProfilePictures"
}
$mySiteUrl = $AlyaSharePointOnPremMySiteUrl

$site = Get-SPWeb $mySiteUrl
$context = Get-SPServiceContext (Get-SPSite $mySiteUrl)
$profileManager = New-Object Microsoft.Office.Server.UserProfiles.UserProfileManager($context)
$allprofiles = $profileManager.GetEnumerator()
if (-Not (Test-Path $picDir -PathType Container)) { New-Item $picDir -ItemType Directory }

foreach($profile in $allprofiles) {
  $pictureUrl = $profile["PictureUrl"].Value
  $sccountName = $profile.AccountName.Substring($profile.AccountName.LastIndexOf("|") + 1).Replace("\", "_")
  if ($null -ne $pictureUrl -and $pictureUrl.Length -gt 0){
    $success = $true
    try{
      $pictureUrlL = ($pictureUrl).Replace("MThumb","LThumb")
      $library = $site.GetList($pictureUrlL.Remove($pictureUrlL.LastIndexOf("/") + 1))
      $file = $library.Folders[0].Folder.Files[$pictureUrlL.Substring($pictureUrlL.LastIndexOf("/") + 1)]
      $binary = $file.OpenBinary()
    }catch{
      $success = $false
    }
    if ($success){
        #Export the image
        [System.IO.File]::WriteAllBytes("$picDir\$($accountName).png", $binary)
    }
    else { Write-Host "Can't export profile picture for user $($sccountName)" -ForegroundColor $CommandError }
  }
  else { Write-Host "$($sccountName) does not have profile picture" -ForegroundColor $CommandWarning }
}

#Stopping Transscript
Stop-Transcript
