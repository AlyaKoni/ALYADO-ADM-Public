#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

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
    29.09.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aip\Install-AIPClient-$($AlyaTimeString).log" | Out-Null

# =============================================================
# AADRM stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AIP | Install-AIPClient | ONPREMISES" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

. $PSScriptRoot\Get-AIPServiceLocation.ps1

Write-Host "Checking office deploy tool installation" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$($AlyaTools)\Setups"))
{
    $tmp = New-Item -Path "$($AlyaTools)\Setups" -ItemType Directory -Force
}
if (-Not (Test-Path "$($AlyaTools)\Setups\AzInfoProtection_UL.exe"))
{
    $req = Invoke-WebRequest -Uri $AlyaAipClientDownload -UseBasicParsing -Method Get
    [regex]$regex = "[^`"]*AzInfoProtection_UL[^`"]*.exe"
    $url = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
    $req = Invoke-WebRequest -Uri $url -Method Get -OutFile "$($AlyaTools)\Setups\AzInfoProtection_UL.exe"
}

Write-Host "Install now the AIP Client with the following command:" -ForegroundColor $CommandInfo
Write-Host "$($AlyaTools)\Setups\AzInfoProtection_UL.exe /quiet ServiceLocation=$serviceLocation" -ForegroundColor $CommandSuccess

#Stopping Transscript
Stop-Transcript