#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2024

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
    25.09.2024 Konrad Brunner       Initial version


    https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-dns
    
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({$_ -match [IPAddress]$_ })]
    [string]$forwarderIp = $null,
    [Parameter(Mandatory=$true)]
    [ValidateSet("australiacentral","australiacentral2","australiaeast","australiasoutheast","brazilsouth","brazilsoutheast","brazilus","canadacentral","canadaeast","centralindia","centralus","centraluseuap","eastasia","eastus","eastus2","eastus2euap","eastusstg","francecentral","francesouth","germanynorth","germanywestcentral","israelcentral","italynorth","japaneast","japanwest","jioindiacentral","jioindiawest","koreacentral","koreasouth","mexicocentral","northcentralus","northeurope","norwayeast","norwaywest","polandcentral","qatarcentral","southafricanorth","southafricawest","southcentralus","southcentralusstg","southeastasia","southindia","spaincentral","swedencentral","switzerlandnorth","switzerlandwest","uaecentral","uaenorth","uksouth","ukwest","westcentralus","westeurope","westindia","westus","westus2","westus3")]
    [string]$regionName = $null,
    [string]$subzone = $null,
    [string]$dnsPrefix = $null,
    [int]$dnsTimeout = 10,
    [bool]$onlyShowValues = $true
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\network\Set-DnsServerConditionalForwarderZonesMinProfile-$($AlyaTimeString).log" | Out-Null

# Constants
$allDomains = @(
    "{regionName}.data.privatelink.azurecr.io",
    "{subzone}.privatelink.{regionName}.azmk8s.io",
    "privatelink.{dnsPrefix}.database.windows.net",
    "privatelink.{regionName}.azurestaticapps.net",
    "privatelink.{regionName}.backup.windowsazure.com",
    "privatelink.{regionName}.azmk8s.io",
    "privatelink.{regionName}.kusto.windows.net",
    "privatelink.adf.azure.com",
    "privatelink.afs.azure.net",
    "privatelink.agentsvc.azure-automation.net",
    "privatelink.analysis.windows.net",
    "privatelink.analytics.cosmos.azure.com",
    "privatelink.api.adu.microsoft.com",
    "privatelink.api.azureml.ms",
    "privatelink.attest.azure.net",
    "privatelink.azconfig.io",
    "privatelink.azure.com",
    "privatelink.azure-api.net",
    "privatelink.azure-automation.net",
    "privatelink.azurecr.io",
    "privatelink.azuredatabricks.net",
    "privatelink.azure-devices.net",
    "privatelink.azure-devices-provisioning.net",
    "privatelink.azurehdinsight.net",
    "privatelink.azureiotcentral.com",
    "privatelink.azurestaticapps.net",
    "privatelink.azuresynapse.net",
    "privatelink.azurewebsites.net",
    "privatelink.batch.azure.com",
    "privatelink.blob.core.windows.net",
    "privatelink.cassandra.cosmos.azure.com",
    "privatelink.cognitiveservices.azure.com",
    "privatelink.database.windows.net",
    "privatelink.datafactory.azure.net",
    "privatelink.dev.azuresynapse.net",
    "privatelink.dfs.core.windows.net",
    "privatelink.dicom.azurehealthcareapis.com",
    "privatelink.digitaltwins.azure.net",
    "privatelink.directline.botframework.com",
    "privatelink.documents.azure.com",
    "privatelink.dp.kubernetesconfiguration.azure.com",
    "privatelink.eventgrid.azure.net",
    "privatelink.fhir.azurehealthcareapis.com",
    "privatelink.file.core.windows.net",
    "privatelink.grafana.azure.com",
    "privatelink.gremlin.cosmos.azure.com",
    "privatelink.guestconfiguration.azure.com",
    "privatelink.his.arc.azure.com",
    "privatelink.managedhsm.azure.net",
    "privatelink.mariadb.database.azure.com",
    "privatelink.media.azure.net",
    "privatelink.mongo.cosmos.azure.com",
    "privatelink.monitor.azure.com",
    "privatelink.mysql.database.azure.com",
    "privatelink.notebooks.azure.net",
    "privatelink.ods.opinsights.azure.com",
    "privatelink.oms.opinsights.azure.com",
    "privatelink.openai.azure.com",
    "privatelink.pbidedicated.windows.net",
    "privatelink.postgres.cosmos.azure.com",
    "privatelink.postgres.database.azure.com",
    "privatelink.prod.migration.windowsazure.com",
    "privatelink.purview.azure.com",
    "privatelink.purviewstudio.azure.com",
    "privatelink.queue.core.windows.net",
    "privatelink.redis.cache.windows.net",
    "privatelink.redisenterprise.cache.azure.net",
    "privatelink.search.windows.net",
    "privatelink.service.signalr.net",
    "privatelink.servicebus.windows.net",
    "privatelink.servicebus.windows.net1",
    "privatelink.siterecovery.windowsazure.com",
    "privatelink.sql.azuresynapse.net",
    "privatelink.table.core.windows.net",
    "privatelink.table.cosmos.azure.com",
    "privatelink.tip1.powerquery.microsoft.com",
    "privatelink.token.botframework.com",
    "privatelink.ts.eventgrid.azure.net",
    "privatelink.vaultcore.azure.net",
    "privatelink.web.core.windows.net",
    "privatelink.workspace.azurehealthcareapis.com",
    "privatelink.wvd.microsoft.com",
    "privatelink-global.wvd.microsoft.com",
    "scm.privatelink.azurewebsites.net"
)

# =============================================================
# DNS stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "DNS | Set-DnsServerConditionalForwarderZonesMinProfile | ON-PREMISES" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

if ([string]::IsNullOrEmpty($subzone))
{
    for ($i=0; $i -lt $allDomains.Count; $i++)
    {
        $allDomains[$i] = $allDomains[$i].Replace("{subzone}.", "")
    }
}
if ([string]::IsNullOrEmpty($dnsPrefix))
{
    for ($i=0; $i -lt $allDomains.Count; $i++)
    {
        $allDomains[$i] = $allDomains[$i].Replace("{dnsPrefix}.", "")
    }
}
for ($i=0; $i -lt $allDomains.Count; $i++)
{
    $allDomains[$i] = $allDomains[$i].Replace("{regionName}", $regionName)
}

foreach($domain in $allDomains)
{
    Write-Host "  Forwarding $domain to $forwarderIp"
    if (-Not $onlyShowValues) { Add-DnsServerConditionalForwarderZone -Name $domain -ReplicationScope "Forest" -MasterServers $forwarderIp -ForwarderTimeout $dnsTimeout }
}

#Stopping Transscript
Stop-Transcript
