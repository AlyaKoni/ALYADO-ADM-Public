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

#>

# Parameters
[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\microsoft365\ProfilePictures\Export-ProfilePicsFromSpo-$($AlyaTimeString).log" | Out-Null

#Prepare PicDir
$picDir = "$($AlyaData)\aad\ProfilePictures\SPO"
if (-Not (Test-Path $picDir))
{
    New-Item -Path $picDir -ItemType Directory -Force
}
Write-Host "Profile pictures will be exported to:"
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
Write-Host "SharePoint | Export-ProfilePicsFromSpo | M365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
$myUrl = "https://$AlyaTenantNameId-my.sharepoint.com/"
$myCon = LoginTo-PnP -Url $myUrl
$docLibNameEn = "User Photos"
$docLibNameDe = "Benutzerfotos"
$folderNameEn = "Profile Pictures"
$folderNameDe = "Profilbilder"

Write-Host "Gettting Profile Pictures"
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

$items = Get-PnPListItem -Connection $myCon -List $list -PageSize 5000
foreach($item in $items)
{
    $fileName = $item["FileLeafRef"]
    if ($fileName -like "*.jpg")
    {
        $userId = $fileName.Split("_")[0]
        $size = $fileName.Split("_")[-1].Split(".")[0]
        $mgUser = $null
        $upn = $userId
        try { $mgUser = Get-MgBetaUser -UserId $userId } catch {}
        if ($mgUser) { $upn = $mgUser.UserPrincipalName }
        else {
            if ($fileName.Split("_").Count -eq 5)
            {
                $parts = $fileName.Split("_")
                $upn = "$($parts[0])@$($parts[1]).$($parts[2]).$($parts[3])"
                try { $mgUser = Get-MgBetaUser -UserId $upn } catch {}
                if ($mgUser) { 
                    $upn = $mgUser.UserPrincipalName
                    $userId = $mgUser.Id
                } else {
                    $upn = "$($parts[0]).$($parts[1])@$($parts[2]).$($parts[3])"
                    try { $mgUser = Get-MgBetaUser -UserId $upn } catch {}
                    if ($mgUser) { 
                        $upn = $mgUser.UserPrincipalName
                        $userId = $mgUser.Id
                    } else {
                        $upn = "$($parts[0])_$($parts[1])_$($parts[2])_$($parts[3])"
                        $userId = "UNKNOWN"
                    }
                }
            }
            else
            {
                if ($fileName.Split("_").Count -eq 6)
                {
                    $parts = $fileName.Split("_")
                    $upn = "$($parts[0])_$($parts[1])@$($parts[2]).$($parts[3]).$($parts[4])"
                    try { $mgUser = Get-MgBetaUser -UserId $upn } catch {}
                    if ($mgUser) { 
                        $upn = $mgUser.UserPrincipalName
                        $userId = $mgUser.Id
                    } else {
                        $upn = "$($parts[0]).$($parts[1])@$($parts[2]).$($parts[3]).$($parts[4])"
                        try { $mgUser = Get-MgBetaUser -UserId $upn } catch {}
                        if ($mgUser) { 
                            $upn = $mgUser.UserPrincipalName
                            $userId = $mgUser.Id
                        } else {
                            $upn = "UNKNOWN"
                            $a = 1
                        }
                    }
                }
                else
                {
                    $upn = "UNKNOWN"
                    $a = 1
                }
            }
        }
        $localName = "$($upn)_$($userId)_$($size).jpg"
        Write-Host "$($localName)"
        if (Test-Path $localName) { continue }
        $temp = Get-PnPFile -Connection $myCon -Url "$docLibNameEn/$folderNameDe/$fileName" -Path $picDir -Filename $localName -AsFile -Force
    }
}

#Stopping Transscript
Stop-Transcript
