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
    09.08.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$ForwarderResourceGroupName,
    [Parameter(Mandatory=$true)]
    [string]$ForwarderVMNicName
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Set-OnPremDnsForwarderRules-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Constants
$allDomains = @(
    "core.windows.net",
    "$($AlyaLocation).privatelink.siterecovery.windowsazure.com",
    "privatelink.$($AlyaLocation).azmk8s.io",
    "privatelink.$($AlyaLocation).backup.windowsazure.com",
    "privatelink.adf.azure.com",
    "privatelink.afs.azure.net",
    "privatelink.agentsvc.azure-automation.net",
    "privatelink.api.azureml.ms",
    "privatelink.azconfig.io",
    "privatelink.azure-automation.net",
    "privatelink.azurecr.io",
    "privatelink.azure-devices.net",
    "privatelink.azurewebsites.net",
    "privatelink.blob.core.windows.net",
    "privatelink.cassandra.cosmos.azure.com",
    "privatelink.cognitiveservices.azure.com",
    "privatelink.database.windows.net",
    "privatelink.datafactory.azure.net",
    "privatelink.dfs.core.windows.net",
    "privatelink.documents.azure.com",
    "privatelink.eventgrid.azure.net",
    "privatelink.file.core.windows.net",
    "privatelink.gremlin.cosmos.azure.com",
    "privatelink.mariadb.database.azure.com",
    "privatelink.mongo.cosmos.azure.com",
    "privatelink.monitor.azure.com",
    "privatelink.mysql.database.azure.com",
    "privatelink.notebooks.azure.net",
    "privatelink.ods.opinsights.azure.com",
    "privatelink.oms.opinsights.azure.com",
    "privatelink.postgres.database.azure.com",
    "privatelink.queue.core.windows.net",
    "privatelink.redis.cache.windows.net",
    "privatelink.search.windows.net",
    "privatelink.service.signalr.net",
    "privatelink.servicebus.windows.net",
    "privatelink.servicebus.windows.net1",
    "privatelink.sql.azuresynapse.net",
    "privatelink.table.core.windows.net",
    "privatelink.table.cosmos.azure.com",
    "privatelink.vaultcore.azure.net",
    "privatelink.web.core.windows.net"
)

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Network"
Check-Module -moduleName "DnsServer"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Infrastructure | Set-OnPremDnsForwarderRules | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ForwarderResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    throw "Ressource Group not found. Pleas ecreate the Ressource Group $ForwarderResourceGroupName"
}

# Checking vm nic
Write-Host "Checking vm nic" -ForegroundColor $CommandInfo
$VMNic = Get-AzNetworkInterface -ForwarderResourceGroupName $ForwarderResourceGroupName -Name $ForwarderVMNicName -ErrorAction SilentlyContinue
if (-Not $VMNic)
{
    throw "VM nic not found. Please create the vm nic $ForwarderVMNicName"
}
$forwarderIp = $VMNic.IpConfigurations[0].PrivateIpAddress

# Setting forwarder rules
Write-Host "Setting forwarder rules" -ForegroundColor $CommandInfo
foreach($domain in $allDomains)
{
    Write-Host "  Forwarding $domain to $forwarderIp"
    Add-DnsServerConditionalForwarderZone -Name $domain -ReplicationScope "Forest" -MasterServers $forwarderIp
}

#Stopping Transscript
Stop-Transcript
