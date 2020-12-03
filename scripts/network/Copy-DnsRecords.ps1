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
    01.12.2020 Konrad Brunner       Initial version

#>

[CmdletBinding()]
Param(
    [string]$fromServer = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\network\Copy-DnsRecords-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainNetwork)"
$additionalCopies = @("_autodiscover._tcp","_caldav._tcp","_caldavs._tcp","_carddav._tcp","_carddavs._tcp","_ischedule._tcp","_xmpp-client._tcp","_xmpp-server._tcp","autodiscover","ftp","imap","mail","pop","smtp","www","xas","xwa")

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Azure | Copy-DnsRecords | AZURE" -ForegroundColor $CommandInfo
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
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Error "Ressource Group not found. Please create first the Ressource Group $ResourceGroupName"
}

# Checking main DNS zone
Write-Host "Checking main DNS zone" -ForegroundColor $CommandInfo
$dnsZone = Get-AzDnsZone -Name $AlyaDomainName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $dnsZone)
{
    Write-Error "DNS zone not found. Please create first the DNS zone $AlyaDomainName"
}

# Checking additional DNS zones
Write-Host "Checking additional DNS zones" -ForegroundColor $CommandInfo
foreach($zone in $AlyaAdditionalDomainNames)
{
    $addDnsZone = Get-AzDnsZone -Name $zone -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if (-Not $addDnsZone)
    {
        Write-Error "DNS zone not found. Please create first the DNS zone $zone"
    }
}

# Checking DNS server
if (-Not $fromServer)
{
    $nameServer = Resolve-DnsName -Name $AlyaDomainName -Type NS -DnsOnly -NoHostsFile
    $fromDnsServer = $nameServer[0].Server
}
else
{
    $fromDnsServer = $fromServer
}

# Function definitions
function CopyDomain
{
    param(
        [string]$domainName,
        [string]$fromServer,
        [string]$toServer
    )
    Write-Host "Copying domain to zone: $domainName" -ForegroundColor $CommandInfo
    $records = Resolve-DnsName -Name $domainName -Type All -Server $fromServer -DnsOnly -NoHostsFile
    $allRecords = @()
    foreach($record in $records)
    {
        $allRecords += $record
    }
    foreach($additionalCopy in $additionalCopies)
    {
        $record = Resolve-DnsName -Name ($additionalCopy+"."+$domainName) -Type All -Server $fromServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | where { $_.Section -eq "Answer" }
        $allRecords += $record
    }
    foreach($record in $allRecords)
    {
        Write-Host "Record $($record.Type) Name:$($record.Name)"
        switch($record.Type)
        {
            "SOA" {
                $fromRecord = Resolve-DnsName -Name $record.Name -Type SOA -Server $fromServer -DnsOnly -NoRecursion -NoHostsFile | where { $_.Type -eq "SOA" }
                $toRecord = Resolve-DnsName -Name $record.Name -Type SOA -Server $toServer -DnsOnly -NoRecursion -NoHostsFile | where { $_.Type -eq "SOA" }
                Write-Warning "  We do not update SOA records. Please check difference and update by hand!"
                Write-Warning "  From record:"
                Write-Host (($fromRecord | fl | Out-String).Trim())
                Write-Warning "  To record:"
                Write-Host (($toRecord | fl | Out-String).Trim())
            }
            "MX" {
                $fromRecord = Resolve-DnsName -Name $record.Name -Type MX -Server $fromServer -DnsOnly -NoRecursion -NoHostsFile | where { $_.Section -eq "Answer" }
                $toRecord = Resolve-DnsName -Name $record.Name -Type MX -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | where { $_.Section -eq "Answer" }
                if (-Not $toRecord)
                {
                    Write-Host "  Creating MX record"
                    New-AzDnsRecordSet -Name "@" -RecordType MX -ZoneName $domainName -ResourceGroupName $ResourceGroupName -Ttl $fromRecord.TTL -DnsRecords (New-AzDnsRecordConfig -Exchange $fromRecord.NameExchange -Preference $fromRecord.Preference)
                }
                else
                {
                    Write-Host "  Updating MX record"
                    $recSet = Get-AzDnsRecordSet -Name "@" -RecordType MX -ZoneName $domainName -ResourceGroupName $ResourceGroupName
                    $recSet.Records[0].Exchange = $fromRecord.NameExchange
                    $recSet.Records[0].Preference = $fromRecord.Preference
                    $recSet.Ttl = $fromRecord.TTL
                    Set-AzDnsRecordSet -RecordSet $recSet -Overwrite
                }
            }
            "TXT" {
                $fromRecord = Resolve-DnsName -Name $record.Name -Type TXT -Server $fromServer -DnsOnly -NoRecursion -NoHostsFile | where { $_.Section -eq "Answer" }
                $toRecord = Resolve-DnsName -Name $record.Name -Type TXT -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | where { $_.Section -eq "Answer" }
                $recordName = $record.Name -replace ("."+$domainName), ""
                if ($record.Name -eq $domainName)
                {
                    $recordName = "@"
                }
                $value = New-Object System.Collections.ArrayList
                $ttl = 3600
                foreach($from in $fromRecord)
                {
                    $value.Add((New-AzDnsRecordConfig -Value $from.Strings.Trim())) | Out-Null
                    $ttl = $from.TTL
                }
                if (-Not $toRecord)
                {
                    Write-Host "  Creating TXT record"
                    New-AzDnsRecordSet -Name $recordName -RecordType TXT -ZoneName $domainName -ResourceGroupName $ResourceGroupName -Ttl $ttl -DnsRecords $value
                }
                else
                {
                    Write-Host "  Updating TXT record"
                    $recSet = Get-AzDnsRecordSet -Name $recordName -RecordType TXT -ZoneName $domainName -ResourceGroupName $ResourceGroupName
                    $recSet.Records.Clear()
                    foreach($txt in $value)
                    {
                        $recSet.Records.Add($txt) | Out-Null
                    }
                    $recSet.Ttl = $ttl
                    Set-AzDnsRecordSet -RecordSet $recSet -Overwrite
                }
            }
            "A" {
                $fromRecord = Resolve-DnsName -Name $record.Name -Type A -Server $fromServer -DnsOnly -NoRecursion -NoHostsFile | where { $_.Section -eq "Answer" }
                $toRecord = Resolve-DnsName -Name $record.Name -Type A -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | where { $_.Section -eq "Answer" }
                if (-Not $toRecord)
                {
                    $toRecord = Resolve-DnsName -Name ($record.Name+"."+$domainName) -Type A -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | where { $_.Section -eq "Answer" }
                }
                $recordName = $record.Name -replace ("."+$domainName), ""
                if ($record.Name -eq $domainName)
                {
                    $recordName = "@"
                }
                if (-Not $toRecord)
                {
                    Write-Host "  Creating A record"
                    New-AzDnsRecordSet -Name $recordName -RecordType A -ZoneName $domainName -ResourceGroupName $ResourceGroupName -Ttl $fromRecord.TTL -DnsRecords (New-AzDnsRecordConfig -Ipv4Address $fromRecord.IpAddress )
                }
                else
                {
                    Write-Host "  Updating A record"
                    $recSet = Get-AzDnsRecordSet -Name $recordName -RecordType A -ZoneName $domainName -ResourceGroupName $ResourceGroupName
                    $recSet.Records[0].Ipv4Address = $fromRecord.IpAddress
                    $recSet.Ttl = $fromRecord.TTL
                    Set-AzDnsRecordSet -RecordSet $recSet -Overwrite
                }
            }
            "SRV" {
                $fromRecord = Resolve-DnsName -Name $record.Name -Type SRV -Server $fromServer -DnsOnly -NoRecursion -NoHostsFile | where { $_.Section -eq "Answer" }
                $toRecord = Resolve-DnsName -Name $record.Name -Type SRV -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | where { $_.Section -eq "Answer" }
                $recordName = $record.Name -replace ("."+$domainName), ""
                if ($record.Name -eq $domainName)
                {
                    $recordName = "@"
                }
                if (-Not $toRecord)
                {
                    Write-Host "  Creating SRV record"
                    New-AzDnsRecordSet -Name $recordName -RecordType SRV -ZoneName $domainName -ResourceGroupName $ResourceGroupName -Ttl $fromRecord.TTL -DnsRecords (New-AzDnsRecordConfig -Target $fromRecord.NameTarget -Priority $fromRecord.Priority -Weight $fromRecord.Weight -Port $fromRecord.Port )
                }
                else
                {
                    Write-Host "  Updating SRV record"
                    $recSet = Get-AzDnsRecordSet -Name $recordName -RecordType SRV -ZoneName $domainName -ResourceGroupName $ResourceGroupName
                    $recSet.Records[0].Target = $fromRecord.NameTarget
                    $recSet.Records[0].Priority = $fromRecord.Priority
                    $recSet.Records[0].Weight = $fromRecord.Weight
                    $recSet.Records[0].Port = $fromRecord.Port
                    $recSet.Ttl = $fromRecord.TTL
                    Set-AzDnsRecordSet -RecordSet $recSet -Overwrite
                }
            }
            "NS" {
            }
            default {
                Write-Error "Record type $($record.Type) is not yet implemented!"
            }
        }

    }
}

# Copying main DNS zone
Write-Host "Copying main DNS zone" -ForegroundColor $CommandInfo
$toDnsServer = $dnsZone.NameServers[0]
CopyDomain -domainName $AlyaDomainName -fromServer $fromDnsServer -toServer $toDnsServer

# Copying additional DNS zones
Write-Host "Copying additional DNS zones" -ForegroundColor $CommandInfo
foreach($zone in $AlyaAdditionalDomainNames)
{
    $addDnsZone = Get-AzDnsZone -Name $zone -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    $toDnsServer = $addDnsZone.NameServers[0]
    CopyDomain -domainName $zone -fromServer $fromDnsServer -toServer $toDnsServer
}

#Stopping Transscript
Stop-Transcript