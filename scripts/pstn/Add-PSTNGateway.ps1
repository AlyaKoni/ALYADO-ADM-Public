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
    16.09.2020 Konrad Brunner       Initial Version
    28.12.2021 Konrad Brunner       Switch to teams module

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\pstn\Add-PSTNGateway-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MicrosoftTeams"

# Logins
LoginTo-Teams

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "PSTN | Add-PSTNGateway | Teams" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main 
if ((Get-CsTenant).VerifiedDomains.Name -notcontains $AlyaPstnGateway)
{
    Write-Host "$AlyaPstnGateway is not yet in the VerifiedDomains list" -ForegroundColor Red
    Write-Host "Please create a user in this domain, assign a O365E1 license and wait up to some hours or days" -ForegroundColor Red
    exit 1
}
if (((Get-CsTenant).VerifiedDomains | where { $_.Name -eq $AlyaPstnGateway }).Status -ne "Enabled")
{
    Write-Host "$AlyaPstnGateway is not yet enabled" -ForegroundColor Red
    Write-Host "Please enbale the domain $AlyaPstnGateway" -ForegroundColor Red
    exit 2
}

$PSTNGateway = Get-CsOnlinePSTNGateway -Identity $AlyaPstnGateway -ErrorAction SilentlyContinue
if (-Not $PSTNGateway)
{
    New-CsOnlinePSTNGateway -Fqdn $AlyaPstnGateway -SipSignalingPort $AlyaPstnPort -MaxConcurrentSessions 100 -Enabled $true -ForwardPai $true -ForwardCallHistory $true
}
else
{
    Write-Host "Gateway already exists!"
}

#Stopping Transscript
Stop-Transcript