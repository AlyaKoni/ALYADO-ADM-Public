#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2021

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
    Date       Author               Description
    ---------- -------------------- ----------------------------
    03.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Reading configuration
Import-Module "ActiveDirectory" -ErrorAction Stop

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\upnchange\Export-UsersAndContacts-$($AlyaTimeString).log" | Out-Null


# =============================================================
# AD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "UPNCHANGE | Export-UsersAndContacts | AD" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
if (-Not (Test-Path "$AlyaData\aad\upnchange"))
{
    $tmp = New-Item -ItemType Directory -Path "$AlyaData\aad\upnchange" -Force
}

# Exporting contacts
Write-Host "Exporting contacts" -ForegroundColor $CommandInfo
Get-ADobject -Filter {(ObjectClass -eq "Contact")} -Property * | Select-Object samAccountName,sn,givenname,userPrincipalName,DistinguishedName,objectguid,CN,DisplayName,Name,Mail,Mailnickname,telephonenumber,Description | Export-Csv "$AlyaData\aad\upnchange\exportContacts.csv" -NoTypeInformation -Encoding UTF8
Write-Host " to $AlyaData\aad\upnchange\exportContacts.csv" -ForegroundColor $CommandSuccess

# Exporting users
Write-Host "Exporting users" -ForegroundColor $CommandInfo
Get-ADobject -Filter {(ObjectClass -eq "User")} -Property * | Select-Object samAccountName,sn,givenname,userPrincipalName,DistinguishedName,objectguid,CN,DisplayName,Name,Mail,Mailnickname,telephonenumber,Description | Export-Csv "$AlyaData\aad\upnchange\exportUsers.csv" -NoTypeInformation -Encoding UTF8
Write-Host " to $AlyaData\aad\upnchange\exportUsers.csv" -ForegroundColor $CommandSuccess

#Stopping Transscript
Stop-Transcript