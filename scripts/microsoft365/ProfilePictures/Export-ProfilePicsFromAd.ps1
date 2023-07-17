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

#>

# Parameters
[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\microsoft365\ProfilePictures\Export-ProfilePicsFromAd-$($AlyaTimeString).log" | Out-Null

#Prepare PicDir
$picDir = "$($AlyaData)\aad\ProfilePictures\AD"
if (-Not (Test-Path $picDir))
{
    New-Item -Path $picDir -ItemType Directory -Force
}
Write-Host "Profile pictures will be exported to:"
Write-Host "$picDir`n"

# =============================================================
# aad OnPrem stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AD | Export-ProfilePicsFromAd | ONPREMISES" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
$addomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $AlyaLocalDomainName)))
$root = $addomain.GetDirectoryEntry()
$search = [System.DirectoryServices.DirectorySearcher]$root
$search.Filter = "(&(objectclass=user)(objectcategory=person))"
$results = $search.FindAll()

foreach($result in $results)
{
    if ($null -ne $result)
    {
        $user = $result.GetDirectoryEntry()
        if ($null -ne $user.thumbnailPhoto -and $user.thumbnailPhoto.Length -gt 0)
        {
            $picPath = "$picDir\$($user.userPrincipalName).jpg"
            $bytes = [byte[]]$user.Properties["thumbnailPhoto"][0]
            [System.Io.File]::WriteAllBytes($picPath, $bytes)
        }
    }
}

#Stopping Transscript
Stop-Transcript
