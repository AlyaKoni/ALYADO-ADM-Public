#Requires -Version 2.0
#Requires -RunAsAdministrator

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
    03.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    $dryRun = $false
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Importing modules
Import-Module "ActiveDirectory" -ErrorAction Stop

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\upnchange\Change-UpnInAdFromCsv-$($AlyaTimeString).log" | Out-Null

# =============================================================
# AD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "UPNCHANGE | Change-UpnInAdFromCsv | AD" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
Write-Host "Starting" -ForegroundColor $CommandInfo

Write-Host "Reading input file from '$AlyaData\aad\upnchange\upnChange.csv'"
if (-Not (Test-Path "$AlyaData\aad\upnchange\upnChange.csv"))
{
    throw "Input file not found!"
}

$usersToChange = Import-Csv -Delimiter "," -encoding UTF8 "$AlyaData\aad\upnchange\upnChange.csv" -ErrorAction Stop
if ([string]::IsNullOrEmpty($usersToChange[0].samAccountName))
{
	$usersToChange = Import-Csv -Delimiter ";" -encoding UTF8 "$AlyaData\aad\upnchange\upnChange.csv" -ErrorAction Stop
}
if ([string]::IsNullOrEmpty($usersToChange[0].samAccountName))
{
	throw "Wrong delimiter found. Right format:\nRole,samAccountName,..."
}

Write-Host "Processing list" -ForegroundColor $CommandInfo
$cnt = 0
foreach ($userToChange in $usersToChange)
{
    if ([string]::IsNullOrEmpty($userToChange.userPrincipalNameNeu))
    {
        continue
    }
    $cnt++
    Write-Host "  Changing UPN from $($userToChange.userPrincipalNameAlt)"
    $user = Get-ADUser $userToChange.samAccountName -Properties *
    if ($user -And $user.UserPrincipalName)
    {
        if ($user.UserPrincipalName -eq $userToChange.userPrincipalNameNeu)
        {
	        Write-Host "   - UPN was already '$($userToChange.userPrincipalNameNeu)'"
	        Write-Host "   - No change!"
        }
        else
        {
	        Write-Host "   - to '$($userToChange.userPrincipalNameNeu)'"
            try {
                if (-Not $dryRun)
                {
	                Set-ADUser -Identity $userToChange.samAccountName -UserPrincipalName $userToChange.userPrincipalNameNeu
                }
            } catch {
	            Write-Host "   - Error occured changing the UPN"
            }
        }
    }
    else
    {
        Write-Host "   - Error: Can't find user"
    }

}

if (-Not $dryRun)
{
    repadmin /syncall /AdeP
}

Get-Date
Write-Host "Finished changing $($cnt) UPNs" -ForegroundColor $CommandInfo


#Stopping Transscript
Stop-Transcript
