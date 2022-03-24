#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2022

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
    04.02.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\onprem\Get-ExtensionAttributeStatistic-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Check-Module ActiveDirectory

# =============================================================
# AD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Get-ExtensionAttributeStatistic | ONPREMISES" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Reading users from AD and setting license
Write-Host "Reading users from AD" -ForegroundColor $CommandInfo
$adUsers = Get-ADUser -Filter {UserPrincipalName -like '*'} -Properties UserPrincipalName,extensionAttribute1,extensionAttribute2,extensionAttribute3,extensionAttribute4,extensionAttribute5,extensionAttribute6,extensionAttribute7,extensionAttribute8,extensionAttribute9,extensionAttribute10,extensionAttribute11,extensionAttribute12,extensionAttribute13,extensionAttribute14,extensionAttribute15
$extensionAttribute1 = 0
$extensionAttribute2 = 0
$extensionAttribute3 = 0
$extensionAttribute4 = 0
$extensionAttribute5 = 0
$extensionAttribute6 = 0
$extensionAttribute7 = 0
$extensionAttribute8 = 0
$extensionAttribute9 = 0
$extensionAttribute10 = 0
$extensionAttribute11 = 0
$extensionAttribute12 = 0
$extensionAttribute13 = 0
$extensionAttribute14 = 0
$extensionAttribute15 = 0

$adUsers | foreach {
    
    $adUser = $_
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute1)) { $extensionAttribute1++ }
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute2)) { $extensionAttribute2++ }
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute3)) { $extensionAttribute3++ }
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute4)) { $extensionAttribute4++ }
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute5)) { $extensionAttribute5++ }
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute6)) { $extensionAttribute6++ }
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute7)) { $extensionAttribute7++ }
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute8)) { $extensionAttribute8++ }
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute9)) { $extensionAttribute9++ }
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute10)) { $extensionAttribute10++ }
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute11)) { $extensionAttribute11++ }
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute12)) { $extensionAttribute12++ }
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute13)) { $extensionAttribute13++ }
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute14)) { $extensionAttribute14++ }
    if (-Not [string]::IsNullOrEmpty($adUser.extensionAttribute15)) { $extensionAttribute15++ }

}

Write-Host "Number of users, having an extension attribute defined:"
Write-Host "  extensionAttribute1 : $($extensionAttribute1)"
Write-Host "  extensionAttribute2 : $($extensionAttribute2)"
Write-Host "  extensionAttribute3 : $($extensionAttribute3)"
Write-Host "  extensionAttribute4 : $($extensionAttribute4)"
Write-Host "  extensionAttribute5 : $($extensionAttribute5)"
Write-Host "  extensionAttribute6 : $($extensionAttribute6)"
Write-Host "  extensionAttribute7 : $($extensionAttribute7)"
Write-Host "  extensionAttribute8 : $($extensionAttribute8)"
Write-Host "  extensionAttribute9 : $($extensionAttribute9)"
Write-Host "  extensionAttribute10: $($extensionAttribute10)"
Write-Host "  extensionAttribute11: $($extensionAttribute11)"
Write-Host "  extensionAttribute12: $($extensionAttribute12)"
Write-Host "  extensionAttribute13: $($extensionAttribute13)"
Write-Host "  extensionAttribute14: $($extensionAttribute14)"
Write-Host "  extensionAttribute15: $($extensionAttribute15)"

#Stopping Transscript
Stop-Transcript