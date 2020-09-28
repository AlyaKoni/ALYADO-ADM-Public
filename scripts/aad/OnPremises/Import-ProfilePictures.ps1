#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2019, 2020

    This file is part of the Alya Base Configuration.
    The Alya Base Configuration is free software: you can redistribute it
	and/or modify it under the terms of the GNU General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
	Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
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
    24.09.2020 Konrad Brunner       Initial Version


IMPORTANT!!
The script expects, images in $picDir are named like $upn.$ext

#>

# Parameters
[CmdletBinding()]
Param(
    $picDir = $null #Defaults to "$($AlyaData)\aad\ProfilePictures"
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\onprem\Import-ProfilePictures-$($AlyaTimeString).log" | Out-Null

# =============================================================
# aad OnPrem stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AD | Import-ProfilePictures | ONPREMISES" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
if (-Not $picDir)
{
    $picDir = "$($AlyaData)\aad\ProfilePictures"
}

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
        $user = $result.GetDirectoryEntry()
        $binary = [System.IO.File]::ReadAllBytes($pic.FullName)
        $user.put("thumbnailPhoto", $binary)
        $user.setinfo()
        Write-Host "  - updated"
    }
    else
    {
        Write-Host "  - does not exist in domain " $domainname
    }
}

#Stopping Transscript
Stop-Transcript