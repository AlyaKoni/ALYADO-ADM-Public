#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019, 2020

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

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\client\office\Install-Office365-WVD-$($AlyaTimeString).log" | Out-Null

#Checking prepare tool
& "$PSScriptRoot\PrepareDeployTool.ps1"

#Installing office
Write-Host "Downloading office to $($AlyaTemp)\Office" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$AlyaTemp\Office"))
{
    $tmp = New-Item -Path "$AlyaTemp\Office" -ItemType Directory -Force
}
Push-Location "$AlyaTemp\Office"
&("$DeployToolRoot\setup.exe") /download "$AlyaData\client\office\office_WVD_deploy_config.xml"

Write-Host "Installing office" -ForegroundColor $CommandInfo
&("$DeployToolRoot\setup.exe") /configure "$AlyaData\client\office\office_WVD_deploy_config.xml"
Pop-Location

Write-Host "Cleaning downloads" -ForegroundColor $CommandInfo
Remove-Item -Path "$AlyaTemp\Office" -Recurse -Force

#Stopping Transscript
Stop-Transcript