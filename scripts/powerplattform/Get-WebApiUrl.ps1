#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2021

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
    17.01.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\powerplattform\Get-WebApiUrl-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.PowerApps.Administration.PowerShell"
Install-ModuleIfNotInstalled "Microsoft.PowerApps.PowerShell"

# Logins
LoginTo-PowerApps

# =============================================================
# PowerPlatform stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "PowerPlatform | Get-WebApiUrl | PowerPlatform" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$env = Get-AdminPowerAppEnvironment

$prot = "https://"
switch ($env.Location)
{
    "europe" { $reg = "crm4" }
    "northamerica" { $reg = "crm" }
    "southamerica" { $reg = "crm2" }
    #TODO
    default { $reg = "crm4" }
}

$AlyaPpfWebApiUrl = "$prot$AlyaTenantNameId.$reg.dynamics.com"
$AlyaPpfWebApiAdminUrl = "$($prot)admin.services.$reg.dynamics.com"

# Power Automate Web API 
Write-Host "Your web api url is: $AlyaPpfWebApiUrl" -ForegroundColor $CommandSuccess

# Online Management API 
Write-Host "Your admin web api url is: $AlyaPpfWebApiAdminUrl" -ForegroundColor $CommandSuccess

$token = Get-AzAccessToken($AlyaPpfWebApiAdminUrl)
$uri = "$($AlyaPpfWebApiAdminUrl)/api/v1.2/Instances"
$headers = @{
    "Content-Type"  = "application/json"
    "Authorization" = "Bearer $($token)"
}
$envs = Invoke-RestMethod -Headers $headers -Uri $uri -UseBasicParsing -Method "GET" -ContentType "application/json"


#Stopping Transscript
Stop-Transcript
