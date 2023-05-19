#Requires -Version 7.0
#Requires -RunAsAdministrator

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
    12.01.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$GatewayName,
    [Parameter(Mandatory=$false)]
    [SecureString]$RecoverKey = $null,
    [Parameter(Mandatory=$false)]
    [String]$RegionKey = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\powerplattform\Install-NewDataGateway-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "DataGateway"
Install-ModuleIfNotInstalled "MSAL.PS"
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
$dgwCon = LoginTo-DataGateway

# =============================================================
# PowerPlatform stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "OnPremisesDataGateways | Install-NewDataGateway | PowerPlatform" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n`n" -ForegroundColor $CommandInfo

Write-Host "`n`nInstalling gateway" -ForegroundColor $CommandInfo
$service = Get-Service -Name PBIEgwService
if ($service)
{
    Write-Host "On-premises data gateway service already installed"
}
else
{
    Write-Warning "On-premises data gateway service not yet installed, installing now"
    Install-DataGateway -AcceptConditions
}

Write-Host "`n`nChecking recovery key" -ForegroundColor $CommandInfo
if (-Not $RecoverKey)
{
    $key = [Guid]::NewGuid()
    $RecoverKey = ConvertTo-SecureString -String $key -AsPlainText -Force
    Write-Warning "Please save the following recovery key for gateway $GatewayName on a secure place"
    Write-Host $key -ForegroundColor $CommandSuccess
}

Write-Host "`n`nInstalling gateway cluster" -ForegroundColor $CommandInfo
$GatewayDetails = Get-DataGatewayCluster -Scope Organization -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $GatewayName }
if (-Not $GatewayDetails)
{
    Write-Warning "Gateway cluster not yet installed, installing now"
    if ($RegionKey)
    {
        $GatewayDetails = Add-DataGatewayCluster -Name $GatewayName -RecoveryKey $RecoverKey -RegionKey $RegionKey
    }
    else
    {
        $GatewayDetails = Add-DataGatewayCluster -Name $GatewayName -RecoveryKey $RecoverKey
    }
}
else
{
    Write-Host "Gateway cluster already installed"
}
$GatewayDetails = Get-DataGatewayCluster -Scope Organization -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $GatewayName }

Write-Host "`n`nAdding $((Get-AzContext).Account.Id) as gateway cluster admin" -ForegroundColor $CommandInfo
$AdminUserId = (Get-AzContext).Account.ExtendedProperties["HomeAccountId"].Split(".")[0]
Add-DataGatewayClusterUser -GatewayClusterId $GatewayDetails.Id -PrincipalObjectId $AdminUserId -AllowedDataSourceTypes $null -Role Admin

#Stopping Transscript
Stop-Transcript
