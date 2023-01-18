#Requires -Version 7.0

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
    20.12.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [String[]]$InstallerUpns = $null,
    [String[]]$InstallerApplicationIds = $null,
    [String[]]$InstallerObjectIds = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\powerplattform\Add-DataGatewayInstaller-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "DataGateway"
Install-ModuleIfNotInstalled "MSAL.PS"
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
$dgwCon = LoginTo-DataGateway

# =============================================================
# PowerPlatform stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "OnPremisesDataGateways | Add-DataGatewayInstaller | PowerPlatform" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n`n" -ForegroundColor $CommandInfo

if ($InstallerUpns -ne $null -and $InstallerUpns.Count -gt 0)
{
    if ($InstallerObjectIds -eq $null)
    {
        $InstallerObjectIds = @()
    }
    foreach($InstallerUpn in $InstallerUpns)
    {
        $user = Get-AzAdUser -UserPrincipalName $InstallerUpn
        if ($InstallerObjectIds -notcontains $user.Id)
        {
            $InstallerObjectIds += $user.Id
        }
    }
}
if ($InstallerApplicationIds -ne $null -and $InstallerApplicationIds.Count -gt 0)
{
    if ($InstallerObjectIds -eq $null)
    {
        $InstallerObjectIds = @()
    }
    foreach($InstallerApplicationId in $InstallerApplicationIds)
    {
        $app = Get-AzADServicePrincipal -ApplicationId $InstallerApplicationId
        if ($InstallerObjectIds -notcontains $app.Id)
        {
            $InstallerObjectIds += $app.Id
        }
    }
}

if ($InstallerObjectIds -ne $null -and $InstallerObjectIds.Count -gt 0)
{
    Set-DataGatewayInstaller -PrincipalObjectIds $InstallerObjectIds -Operation Add -GatewayType Resource
}
else
{
    Write-Error "Please specify parameter InstallerObjectIds or InstallerUpns"
}

#Stopping Transscript
Stop-Transcript
