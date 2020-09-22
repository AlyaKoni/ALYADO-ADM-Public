#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

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
    Date       Author               Description
    ---------- -------------------- ----------------------------
    16.09.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [ValidateSet("User", "AutoAttendant", "CallQueue", IgnoreCase = $true)]
    $type = "User",
    [ValidateNotNullOrEmpty]
    $upn = "konrad.brunner@alyaconsulting.ch",
    [ValidateNotNullOrEmpty]
    $number = "tel:+41625620460"
)

#Checking parms
if ($type -eq "User")
{
    if (-Not $number.StartsWith("tel:"))
    {
        Write-Error "If type 'User', the number has to start with 'tel:'"
        exit
    }
}
if ($type -eq "AutoAttendant" -or $type -eq "CallQueue")
{
    if ($number.StartsWith("tel:"))
    {
        Write-Error "If type is not 'User', the number must to start with 'tel:'"
        exit
    }
}

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\pstn\Activate-User-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Check-Module "SkypeOnlineConnector"

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "PSTN | Activate-User | CsOnline" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main 
$sfbSession = New-CsOnlineSession
Import-PSSession $sfbSession -AllowClobber

if ($type -eq "User")
{
    Set-CsUser -Identity $upn -OnPremLineURI $number -EnterpriseVoiceEnabled $true -HostedVoiceMail $true
    Grant-CsOnlineVoiceRoutingPolicy -Identity $upn -PolicyName "Unrestricted"
}

if ($type -eq "AutoAttendant" -or $type -eq "CallQueue")
{
    Set-CsOnlineApplicationInstance -Identity $upn -OnpremPhoneNumber $number
    Grant-CsOnlineVoiceRoutingPolicy -Identity $upn -PolicyName "Unrestricted"
}

Get-PSSession | Remove-PSSession

#Stopping Transscript
Stop-Transcript