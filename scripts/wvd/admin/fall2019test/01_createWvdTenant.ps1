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
    10.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\fall2019test\01_createWvdTenant-$($AlyaTimeString).log" | Out-Null

# Constants

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionNameTest
#LoginTo-Wvd
if (-Not $Global:RdsContext)
{
    Write-Host "Login to WVD" -ForegroundColor $CommandInfo
    $Global:RdsContext = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker
}

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 01_createWvdTenant | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

#Members
$SubscriptionId = (Get-AzSubscription).Id

#Checking wvd context
Write-Host "Checking wvd context" -ForegroundColor $CommandInfo
if ( (Get-RdsContext).TenantGroupName -ne $AlyaWvdTenantGroupName)
{
    Set-RdsContext -TenantGroupName $AlyaWvdTenantGroupName -ErrorAction Stop
}

#Checking tenant
Write-Host "Checking tenant" -ForegroundColor $CommandInfo
$WvdTenant = Get-RdsTenant -Name $AlyaWvdTenantNameTest -ErrorAction SilentlyContinue
if (-Not $WvdTenant)
{
    Write-Warning "WVD tenant not found. Creating the WVD tenant $WvdTenant"
    $WvdTenant = New-RdsTenant -Name $AlyaWvdTenantNameTest -AadTenantId $AlyaTenantId -AzureSubscriptionId $SubscriptionId
}

Get-RdsTenant -Name $AlyaWvdTenantNameTest -ErrorAction Stop | Format-List

#Get-RdsDiagnosticActivities -Detailed
#Remove-RdsTenant -Name $AlyaWvdTenantNameTest

#Stopping Transscript
Stop-Transcript
