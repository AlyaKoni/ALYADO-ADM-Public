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
    16.09.2020 Konrad Brunner       Initial Version
    28.12.2021 Konrad Brunner       Switch to teams module

#>

[CmdletBinding()]
Param(
    [ValidateSet("User", "AutoAttendant", "CallQueue", IgnoreCase = $true)]
    $type = "User",
    [ValidateNotNullOrEmpty()]
    $upn = "konrad.brunner@alyaconsulting.ch",
    [ValidateNotNullOrEmpty()]
    $number = "+41625620460"
)

#Checking parms
if ($number.StartsWith("tel:"))
{
    Write-Error "The number must not start with 'tel:'" -ErrorAction Continue
    exit
}

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\pstn\Activate-User-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MicrosoftTeams"

# Logins
LoginTo-Teams

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "PSTN | Activate-User | Teams" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main 
if ($type -eq "User")
{
    Write-Host "Setting user $upn lineuri to $number" -ForegroundColor $CommandInfo
    Set-CsPhoneNumberAssignment -Identity $upn -PhoneNumber $number -PhoneNumberType DirectRouting
    Grant-CsOnlineVoiceRoutingPolicy -Identity $upn -PolicyName $AlyaPstnVoiceRoutePolicyName
    #Set-CsTenantDialPlan -Identity $upn -PolicyName "Global"
    Set-CsUserCallingSettings -Identity $upn -IsUnansweredenabled $False
    Get-CsUserCallingSettings -Identity $upn
}
if ($type -eq "AutoAttendant" -or $type -eq "CallQueue")
{
    Write-Host "Setting auto attendant or call queue $upn lineuri to $number" -ForegroundColor $CommandInfo
    Set-CsOnlineApplicationInstance -Identity $upn -OnpremPhoneNumber $number
    Grant-CsOnlineVoiceRoutingPolicy -Identity $upn -PolicyName $AlyaPstnVoiceRoutePolicyName
}

#Stopping Transscript
Stop-Transcript
