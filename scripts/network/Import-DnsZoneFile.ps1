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
    28.06.2023 Konrad Brunner       Initial version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [String]$Domain,
    [Parameter(Mandatory=$true)]
    [String]$ZoneFile
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\network\Import-DnsZoneFile-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainNetwork)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Dns"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "DNS | Import-DnsZoneFile | AZURE" -ForegroundColor $CommandInfo
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
    throw "Ressource Group not found."
}

# Checking DNS zone
Write-Host "Checking DNS zone $($Domain)" -ForegroundColor $CommandInfo
$dnsZone = Get-AzDnsZone -Name $Domain -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $dnsZone)
{
    throw "DNS zone not found."
}

# Checking DNS server
Write-Host "Checking DNS server" -ForegroundColor $CommandInfo
$nameServer = Resolve-DnsName -Name $Domain -Type NS -DnsOnly -NoHostsFile
$fromServer = $nameServer[0].Server
$toServer = $dnsZone.NameServers[0]
Write-Host "  fromServer: $fromServer" -ForegroundColor $CommandInfo
Write-Host "  toServer: $toServer" -ForegroundColor $CommandInfo

# Importing zone file 
Write-Host "Importing zone file $($ZoneFile)" -ForegroundColor $CommandInfo
if (-Not (Test-Path $ZoneFile))
{
    throw "Zone file $($ZoneFile) not found"
}

$entries = Get-Content -Path $ZoneFile -Encoding $AlyaUtf8Encoding
$firstEntry = $true
foreach($entry in $entries)
{
    Write-Host "Entry: $entry"
    $values = $entry.Split("`t")
    if ($firstEntry)
    {
        $firstEntry = $false
        if ($values[0].ToLower() -ne "name" -or $values[5].ToLower() -ne "content")
        {
            Write-Warning "Unknown zone file format!"
            Write-Warning "Needs to be tab delemitted and header needs to be:"
            Write-Warning "name	ttl	IN	type	prio	content"
            throw
        }
        continue
    }
    $tmp = [int]::Parse($values[1])
    if ($values[2] -ne "IN") { throw "Don't know what to do with $($values[2])"}
    $created = @()
    switch ($values[3])
    {
        "NS" { }
        "SOA" { 
            $fromRecord = Resolve-DnsName -Name $values[0] -Type SOA -Server $fromServer -DnsOnly -NoRecursion -NoHostsFile | Where-Object { $_.Type -eq "SOA" }
            $toRecord = Resolve-DnsName -Name $values[0] -Type SOA -Server $toServer -DnsOnly -NoRecursion -NoHostsFile | Where-Object { $_.Type -eq "SOA" }
            Write-Warning "  We do not update SOA records. Please check difference and update by hand if required!"
            Write-Warning "  From record:"
            Write-Host (($fromRecord | Format-List | Out-String).Trim())
            Write-Warning "  To record:"
            Write-Host (($toRecord | Format-List | Out-String).Trim())
        }
        "SRV" {
            $toRecord = Resolve-DnsName -Name $values[0] -Type SRV -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
            if (-Not $toRecord)
            {
                $toRecord = Resolve-DnsName -Name $values[0].TrimEnd(".") -Type SRV -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
                if (-Not $toRecord)
                {
                    $toRecord = Resolve-DnsName -Name ($values[0]+"."+$Domain) -Type SRV -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
                }
            }
            $recordName = $values[0] -replace ("."+$Domain+"."), "" -replace ("."+$Domain), ""
            if ($recordName -eq $Domain -or $recordName -eq $Domain+".")
            {
                $recordName = "@"
            }
            $srvPrts = $values[4].Split()
            if (-Not $toRecord)
            {
                Write-Host "  Creating SRV record"
                try {
                    $created += New-AzDnsRecordSet -Name $recordName -RecordType SRV -ZoneName $Domain -ResourceGroupName $ResourceGroupName -Ttl $values[1] -DnsRecords (New-AzDnsRecordConfig -Target $srvPrts[3] -Priority $srvPrts[0] -Weight $srvPrts[1] -Port $srvPrts[2] )
                }
                catch {
                    Write-Host "Error creating record: $($_.Exception.Message)" -ForegroundColor $CommandError
                }
            }
            else
            {
                Write-Host "  Updating SRV record"
                $recSet = Get-AzDnsRecordSet -Name $recordName -RecordType SRV -ZoneName $Domain -ResourceGroupName $ResourceGroupName
                $recSet.Records[0].Target = $srvPrts[3]
                $recSet.Records[0].Priority = $srvPrts[0]
                $recSet.Records[0].Weight = $srvPrts[1]
                $recSet.Records[0].Port = $srvPrts[2]
                $recSet.Ttl = $values[1]
                Set-AzDnsRecordSet -RecordSet $recSet -Overwrite
            }
        }
        "A" {
            $toRecord = Resolve-DnsName -Name $values[0] -Type A -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
            if (-Not $toRecord)
            {
                $toRecord = Resolve-DnsName -Name $values[0].TrimEnd(".") -Type A -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
                if (-Not $toRecord)
                {
                    $toRecord = Resolve-DnsName -Name ($values[0]+"."+$Domain) -Type A -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
                }
            }
            $recordName = $values[0] -replace ("."+$Domain+"."), "" -replace ("."+$Domain), ""
            if ($recordName -eq $Domain -or $recordName -eq $Domain+".")
            {
                $recordName = "@"
            }
            if (-Not $toRecord)
            {
                Write-Host "  Creating A record"
                try {
                    $created += New-AzDnsRecordSet -Name $recordName -RecordType A -ZoneName $Domain -ResourceGroupName $ResourceGroupName -Ttl $values[1] -DnsRecords (New-AzDnsRecordConfig -Ipv4Address $values[5] )
                }
                catch {
                    Write-Host "Error creating record: $($_.Exception.Message)" -ForegroundColor $CommandError
                }
            }
            else
            {
                Write-Host "  Updating A record"
                $recSet = Get-AzDnsRecordSet -Name $recordName -RecordType A -ZoneName $Domain -ResourceGroupName $ResourceGroupName
                $recSet.Records[0].Ipv4Address = $values[5]
                $recSet.Ttl = $values[1]
                Set-AzDnsRecordSet -RecordSet $recSet -Overwrite
            }
        }
        "AAAA" {
            $toRecord = Resolve-DnsName -Name $values[0] -Type AAAA -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
            if (-Not $toRecord)
            {
                $toRecord = Resolve-DnsName -Name $values[0].TrimEnd(".") -Type AAAA -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
                if (-Not $toRecord)
                {
                    $toRecord = Resolve-DnsName -Name ($values[0]+"."+$Domain) -Type AAAA -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
                }
            }
            $recordName = $values[0] -replace ("."+$Domain+"."), "" -replace ("."+$Domain), ""
            if ($recordName -eq $Domain -or $recordName -eq $Domain+".")
            {
                $recordName = "@"
            }
            if (-Not $toRecord)
            {
                Write-Host "  Creating A record"
                try {
                    $created += New-AzDnsRecordSet -Name $recordName -RecordType AAAA -ZoneName $Domain -ResourceGroupName $ResourceGroupName -Ttl $values[1] -DnsRecords (New-AzDnsRecordConfig -Ipv6Address $values[5] )
                }
                catch {
                    Write-Host "Error creating record: $($_.Exception.Message)" -ForegroundColor $CommandError
                }
            }
            else
            {
                Write-Host "  Updating A record"
                $recSet = Get-AzDnsRecordSet -Name $recordName -RecordType AAAA -ZoneName $Domain -ResourceGroupName $ResourceGroupName
                $recSet.Records[0].Ipv6Address = $values[5]
                $recSet.Ttl = $values[1]
                Set-AzDnsRecordSet -RecordSet $recSet -Overwrite
            }
        }
        "CNAME" {
            if ([string]::IsNullOrEmpty($values[5]))
            {
                $serverName =  $values[4].TrimEnd(".")
            }
            else
            {
                $serverName =  $values[5].TrimEnd(".")
            }
            $toRecord = Resolve-DnsName -Name $values[0] -Type CNAME -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
            if (-Not $toRecord)
            {
                $toRecord = Resolve-DnsName -Name $values[0].TrimEnd(".") -Type CNAME -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
                if (-Not $toRecord)
                {
                    $toRecord = Resolve-DnsName -Name ($values[0]+"."+$Domain) -Type CNAME -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
                }
            }
            $recordName = $values[0] -replace ("."+$Domain+"."), "" -replace ("."+$Domain), ""
            if ($recordName -eq $Domain -or $recordName -eq $Domain+".")
            {
                $recordName = "@"
            }
            if (-Not $toRecord)
            {
                Write-Host "  Creating CNAME record"
                try {
                    $created += New-AzDnsRecordSet -Name $recordName -RecordType CNAME -ZoneName $Domain -ResourceGroupName $ResourceGroupName -Ttl $values[1] -DnsRecords (New-AzDnsRecordConfig -Cname $serverName )
                }
                catch {
                    Write-Host "Error creating record: $($_.Exception.Message)" -ForegroundColor $CommandError
                }
            }
            else
            {
                Write-Host "  Updating CNAME record"
                $recSet = Get-AzDnsRecordSet -Name $recordName -RecordType CNAME -ZoneName $Domain -ResourceGroupName $ResourceGroupName
                $recSet.Records[0].Cname = $serverName
                $recSet.Ttl = $values[1]
                Set-AzDnsRecordSet -RecordSet $recSet -Overwrite
            }
        }
        "MX" {
            $toRecord = Resolve-DnsName -Name $values[0] -Type MX -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
            if (-Not $toRecord)
            {
                $toRecord = Resolve-DnsName -Name $values[0].TrimEnd(".") -Type MX -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
                if (-Not $toRecord)
                {
                    $toRecord = Resolve-DnsName -Name ($values[0]+"."+$Domain) -Type MX -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
                    if (-Not $toRecord)
                    {
                        $toRecord = Resolve-DnsName -Name $Domain -Type MX -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
                    }
                }
            }
            $recordName = $values[0] -replace ("."+$Domain+"."), "" -replace ("."+$Domain), ""
            if ($recordName -eq $Domain -or $recordName -eq $Domain+".")
            {
                $recordName = "@"
            }
            if (-Not $toRecord)
            {
                Write-Host "  Creating MX record"
                try {
                    $created += New-AzDnsRecordSet -Name $recordName -RecordType MX -ZoneName $Domain -ResourceGroupName $ResourceGroupName -Ttl $values[1] -DnsRecords (New-AzDnsRecordConfig -Exchange $values[5].TrimEnd(".") -Preference $values[4])
                }
                catch {
                    Write-Host "Error creating record: $($_.Exception.Message)" -ForegroundColor $CommandError
                }
            }
            else
            {
                Write-Host "  Updating MX record"
                $recSet = Get-AzDnsRecordSet -Name "@" -RecordType MX -ZoneName $Domain -ResourceGroupName $ResourceGroupName
                $recSet.Records[0].Exchange = $values[5].TrimEnd(".")
                $recSet.Records[0].Preference = $values[4]
                $recSet.Ttl = $values[1]
                Set-AzDnsRecordSet -RecordSet $recSet -Overwrite
            }
        }
        "TXT" {
            $toRecord = Resolve-DnsName -Name $values[0] -Type TXT -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
            if (-Not $toRecord)
            {
                $toRecord = Resolve-DnsName -Name $values[0].TrimEnd(".") -Type TXT -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
                if (-Not $toRecord)
                {
                    $toRecord = Resolve-DnsName -Name ($values[0]+"."+$Domain) -Type TXT -Server $toServer -DnsOnly -NoRecursion -NoHostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Section -eq "Answer" }
                }
            }
            $recordName = $values[0] -replace ("."+$Domain+"."), "" -replace ("."+$Domain), ""
            if ($recordName -eq $Domain -or $recordName -eq $Domain+".")
            {
                $recordName = "@"
            }
            if (-Not $toRecord)
            {
                $toRecord = $created | Where-Object { $_.RecordType -eq "TXT" -and $_.Name -eq $recordName }
            }
            if (-Not $toRecord)
            {
                Write-Host "  Creating TXT record"
                try {
                    $created += New-AzDnsRecordSet -Name $recordName -RecordType TXT -ZoneName $Domain -ResourceGroupName $ResourceGroupName -Ttl $values[1] -DnsRecords (New-AzDnsRecordConfig -Value $values[5].TrimStart("`"").TrimEnd("`""))
                }
                catch {
                    Write-Host "Error creating record: $($_.Exception.Message)" -ForegroundColor $CommandError
                }
            }
            else
            {
                Write-Host "  Updating TXT record"
                $recSet = Get-AzDnsRecordSet -Name $recordName -RecordType TXT -ZoneName $Domain -ResourceGroupName $ResourceGroupName
                $fnd = $false
                $spfFnd = $false
                foreach($rec in $recSet.Records)
                {
                    if ($rec.Value.StartsWith("v=spf"))
                    {
                        $spfFnd = $true
                    }
                    if ($rec.Value -eq $values[5].TrimStart("`"").TrimEnd("`""))
                    {
                        $fnd = $true
                    }
                }
                if (-Not $fnd)
                {
                    if ($values[5].TrimStart("`"").TrimEnd("`"").StartsWith("v=spf") -And $spfFnd) {
                        foreach($rec in $recSet.Records)
                        {
                            if ($rec.Value.StartsWith("v=spf"))
                            {
                                $rec.Value = $values[5].TrimStart("`"").TrimEnd("`"")
                            }
                        }
                    } else {
                        $rec = New-AzDnsRecordConfig -Value $values[5].TrimStart("`"").TrimEnd("`"")
                        $recSet.Records.Add($rec)
                    }
                }
                $recSet.Ttl = $values[1]
                Set-AzDnsRecordSet -RecordSet $recSet -Overwrite
            }
        }
        default {
            throw "  unknown record type!"
        }
    }
}

# Reporting name server
Write-Host "Name servers for domain $($Domain)" -ForegroundColor $CommandInfo
Write-Host ($dnsZone.NameServers | Out-String)

#Stopping Transscript
Stop-Transcript
