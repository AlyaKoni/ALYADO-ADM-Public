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
    23.06.2021 Konrad Brunner       Initial Version

#>


[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Extract-LogicApps-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Automation | Extract-LogicApps | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Exporting all logic apps
Write-Host "Exporting all logic apps" -ForegroundColor $CommandInfo
$LogicApps = Get-AzLogicApp
$LogicAppRoot = "$($AlyaData)\azure\logicApps"
if (-Not (Test-Path -Path $LogicAppRoot -PathType Container))
{
    New-Item -Path $LogicAppRoot -ItemType Directory -Force | Out-Null
}
foreach($logicApp in $LogicApps)
{
    Write-Host "Exporting app $($logicApp.Id)"
    $logicAppName = $logicApp.Id.Substring($logicApp.Id.IndexOf("resourceGroups")+15, $logicApp.Id.IndexOf("providers")-$logicApp.Id.IndexOf("resourceGroups")-16) + "-" + $logicApp.Name
    if ($logicApp.Definition) { $logicApp.Definition.ToString() | Set-Content -Path "$LogicAppRoot\$($logicAppName)_Definition.json" -Force -Encoding UTF8 }
    if ($logicApp.Parameters -and $logicApp.Parameters.'$connections' -and $logicApp.Parameters.'$connections'.Value) { $logicApp.Parameters.'$connections'.Value.ToString() | Set-Content -Path "$LogicAppRoot\$($logicAppName)_Connections.json" -Force -Encoding UTF8 }
}

#Stopping Transscript
Stop-Transcript