﻿#Requires -Version 2.0

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
    Date       Author               Description
    ---------- -------------------- ----------------------------
    16.09.2020 Konrad Brunner       Initial Version
    28.12.2021 Konrad Brunner       Switch to teams module

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\pstn\List-User-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MicrosoftTeams"

# Logins
LoginTo-Teams

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "PSTN | List-User | Teams" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main 
Write-Host "CsOnline User accounts:" -ForegroundColor $CommandInfo
Get-CsOnlineUser | Select-Object -Property AccountType, UserPrincipalName, AccountEnabled, AssignedPlan | Format-Table

Write-Host "CsOnline User lines:" -ForegroundColor $CommandInfo
Get-CsOnlineUser | Select-Object -Property UserPrincipalName, LineURI, OnPremLineURI | Where-Object { -Not [string]::IsNullOrEmpty($_.LineUri) } | Format-Table

Write-Host "CsOnline Application instances:" -ForegroundColor $CommandInfo | Format-Table
Get-CsOnlineApplicationInstance | Select-Object -Property UserPrincipalName, DisplayName, PhoneNumber | Format-Table

Write-Host "Cs Phone Number Assignment:" -ForegroundColor $CommandInfo | Format-Table
Get-CsPhoneNumberAssignment | Select-Object -Property TelephoneNumber, NumberType, ActivationState, NumberSource, City, PstnAssignmentStatus | Format-Table

Write-Host "CsOnline Lis Location:" -ForegroundColor $CommandInfo
Get-CsOnlineLisLocation | Format-Table

Write-Host "CsOnline Lis Civic Address:" -ForegroundColor $CommandInfo
Get-CsOnlineLisCivicAddress | Format-Table

#Stopping Transscript
Stop-Transcript
