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
    20.04.2020 Konrad Brunner       Initial Version
    10.10.2020 Konrad Brunner       Added parameters and generalized

#>

[CmdletBinding()]
Param(
    [string]$ResourceGroupNumber,
    [int]$NumberOfInstances
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\fall2019prod\12_AddLoadBalancer-$($AlyaTimeString).log" | Out-Null

# Constants
$ErrorActionPreference = "Stop"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($ResourceGroupNumber)"
$NamePrefix = "$($AlyaNamingPrefix)vd$($ResourceGroupNumber.TrimStart("0"))"
$WvdHostName = "$($NamePrefix)-"
$WvdNicSuffix = "-nic"
$LoadBalancerName = "$($AlyaNamingPrefix)ldbl$($ResourceGroupNumber)"
$FeName = $LoadBalancerName+"fe"
$FeNameIn = $LoadBalancerName+"fein"
$FeNameOut = $LoadBalancerName+"feout"
$NameBackPool = $LoadBalancerName+"bp"
$NameBackPoolIn = $LoadBalancerName+"bpin"
$NameBackPoolOut = $LoadBalancerName+"bpout"
$NameHealthProbe = $LoadBalancerName+"hp"
$FePipIn = $FeName+"pip4in"
$FePipOut = $FeName+"pip4out"
$RuleNameIn = $LoadBalancerName+"ir"
$RuleNameOut = $LoadBalancerName+"or"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 12_AddLoadBalancer | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

Write-Host "Checking load balancer" -ForegroundColor $CommandInfo
$lb = Get-AzLoadBalancer -ResourceGroupName $ResourceGroupName -Name $LoadBalancerName -ErrorAction SilentlyContinue
if (-Not $lb)
{
    Write-Host " - Creating"
    $tmp = New-AzLoadBalancer -ResourceGroupName $ResourceGroupName -Name $LoadBalancerName -Location $AlyaLocation -Sku Standard
    $lb = Get-AzLoadBalancer -ResourceGroupName $ResourceGroupName -Name $LoadBalancerName
}
#Remove-AzLoadBalancer -ResourceGroupName $ResourceGroupName -Name $LoadBalancerName -Force

Write-Host "Checking public ips" -ForegroundColor $CommandInfo
$pipIn = Get-AzPublicIpAddress -ResourceGroupName  $ResourceGroupName -Name $FePipIn -ErrorAction SilentlyContinue
if (-Not $pipIn)
{
    Write-Host " - Creating incoming public ip $FePipIn"
    $tmp = New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $FePipIn -Location $AlyaLocation -Sku Standard -IpAddressVersion IPv4 -IdleTimeoutInMinutes 10 -AllocationMethod Static -DomainNameLabel $FeNameIn
    $pipIn = Get-AzPublicIpAddress -ResourceGroupName  $ResourceGroupName -Name $FePipIn
}
#Remove-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $FePipIn -Force
$pipOut = Get-AzPublicIpAddress -ResourceGroupName  $ResourceGroupName -Name $FePipOut -ErrorAction SilentlyContinue
if (-Not $pipOut)
{
    Write-Host " - Creating outgoing public ip $FePipOut"
    $tmp = New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $FePipOut -Location $AlyaLocation -Sku Standard -IpAddressVersion IPv4 -IdleTimeoutInMinutes 10 -AllocationMethod Static -DomainNameLabel $FeNameOut
    $pipOut = Get-AzPublicIpAddress -ResourceGroupName  $ResourceGroupName -Name $FePipOut
}
#Remove-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $FePipOut -Force

Write-Host "Checking frontend ip configurations" -ForegroundColor $CommandInfo
$ipConfigIn = $lb.FrontendIpConfigurations | where { $_.Name -eq $FeNameIn }
if (-Not $ipConfigIn)
{
    Write-Host " - Creating ip configuration $FeNameIn"
    $tmp = Add-AzLoadBalancerFrontendIpConfig -LoadBalancer $lb -Name $FeNameIn -PublicIpAddress $pipIn
    $lb | Set-AzLoadBalancer
    $lb = Get-AzLoadBalancer -ResourceGroupName $ResourceGroupName -Name $LoadBalancerName
    $ipConfigIn = $lb.FrontendIpConfigurations | where { $_.Name -eq $FeNameIn }
}
$ipConfigOut = $lb.FrontendIpConfigurations | where { $_.Name -eq $FeNameOut }
if (-Not $ipConfigOut)
{
    Write-Host " - Creating ip configuration $FeNameOut"
    $tmp = Add-AzLoadBalancerFrontendIpConfig -LoadBalancer $lb -Name $FeNameOut -PublicIpAddress $pipOut
    $lb | Set-AzLoadBalancer
    $lb = Get-AzLoadBalancer -ResourceGroupName $ResourceGroupName -Name $LoadBalancerName
    $ipConfigOut = $lb.FrontendIpConfigurations | where { $_.Name -eq $FeNameOut }
}

Write-Host "Checking backend pools" -ForegroundColor $CommandInfo
$backPoolIn = $lb.BackendAddressPools | where { $_.Name -eq $NameBackPoolIn }
if (-Not $backPoolIn)
{
    Write-Host " - Creating incoming backend pool $NameBackPoolIn"
    $tmp = Add-AzLoadBalancerBackendAddressPoolConfig -LoadBalancer $lb -Name $NameBackPoolIn
    $lb | Set-AzLoadBalancer
    $lb = Get-AzLoadBalancer -ResourceGroupName $ResourceGroupName -Name $LoadBalancerName
    $backPoolIn = $lb.BackendAddressPools | where { $_.Name -eq $NameBackPoolIn }
}
$backPoolOut = $lb.BackendAddressPools | where { $_.Name -eq $NameBackPoolOut }
if (-Not $backPoolOut)
{
    Write-Host " - Creating outgoing backend pool $NameBackPoolOut"
    $tmp = Add-AzLoadBalancerBackendAddressPoolConfig -LoadBalancer $lb -Name $NameBackPoolOut
    $lb | Set-AzLoadBalancer
    $lb = Get-AzLoadBalancer -ResourceGroupName $ResourceGroupName -Name $LoadBalancerName
    $backPoolOut = $lb.BackendAddressPools | where { $_.Name -eq $NameBackPoolOut }
}

Write-Host "Checking host probe" -ForegroundColor $CommandInfo
$hostProbe = $lb.Probes | where { $_.Name -eq $NameHealthProbe }
if (-Not $hostProbe)
{
    Write-Host " - Creating host probe $NameHealthProbe"
    $tmp = Add-AzLoadBalancerProbeConfig -LoadBalancer $lb -Name $NameHealthProbe `
            -Protocol TCP `
            -Port 3389 `
            -IntervalInSeconds 30 `
            -ProbeCount 5
    $lb | Set-AzLoadBalancer
    $lb = Get-AzLoadBalancer -ResourceGroupName $ResourceGroupName -Name $LoadBalancerName
    $hostProbe = $lb.Probes | where { $_.Name -eq $NameHealthProbe }
}

<#
Write-Host "Configuring inboundNatRule" -ForegroundColor $CommandInfo
$inRule = $lb.InboundNatRules | where { $_.Name -eq $RuleNameIn }
if (-Not $inRule)
{
    Write-Host " - Creating $RuleNameIn"
    $tmp = Add-AzLoadBalancerInboundNatRuleConfig -Name $RuleNameIn `
                    -LoadBalancer $lb `
                    -FrontendIpConfiguration $ipConfigIn `
                    -BackendAddressPool $backPoolIn `
                    -Protocol TCP `
                    -FrontendPort 3389 `
                    -BackendPort 3389
    $lb | Set-AzLoadBalancer
    $lb = Get-AzLoadBalancer -ResourceGroupName $ResourceGroupName -Name $LoadBalancerName
    $inRule = $lb.InboundNatRules | where { $_.Name -eq $RuleNameIn }
}
#$lb.InboundNatRules.Remove($inRule)
#$lb | Set-AzLoadBalancer
#>

Write-Host "Configuring outboundRule" -ForegroundColor $CommandInfo
$outRule = $lb.OutboundRules | where { $_.Name -eq $RuleNameOut }
if (-Not $outRule)
{
    Write-Host " - Creating $RuleNameOut"
    $tmp = Add-AzLoadBalancerOutboundRuleConfig -Name $RuleNameOut `
                    -LoadBalancer $lb `
                    -FrontendIpConfiguration $ipConfigOut `
                    -BackendAddressPool $backPoolOut `
                    -Protocol All `
                    -EnableTcpReset:$false `
                    -IdleTimeoutInMinutes 10
    $lb | Set-AzLoadBalancer
    $lb = Get-AzLoadBalancer -ResourceGroupName $ResourceGroupName -Name $LoadBalancerName
    $outRule = $lb.OutboundRules | where { $_.Name -eq $RuleNameOut }
}
#$lb.OutboundRules.Remove($outRule)
#$lb | Set-AzLoadBalancer

for ($hi=0; $hi -lt $NumberOfInstances; $hi++)
{
    #$hi=0
    $VmNicName = "$($WvdHostName)$($hi)$($WvdNicSuffix)"

    <#
    Write-Host "Configuring nics inboundNatRule" -ForegroundColor $CommandInfo
    $nic = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $VmNicName
    $nicInRule = $nic.IpConfigurations[0].LoadBalancerInboundNatRules | where { $_.Name -eq $RuleNameIn -or $_.Id -like "*$($RuleNameIn)"}
    if (-Not $nicInRule)
    {
        Write-Host " - Creating rule for nic $VmNicName"
        $nic.IpConfigurations[0].LoadBalancerInboundNatRules.Add($inRule)
        $nic | Set-AzNetworkInterface
        $nic = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $VmNicName
        $nicInRule = $nic.IpConfigurations[0].LoadBalancerInboundNatRules | where { $_.Name -eq $RuleNameIn -or $_.Id -like "*$($RuleNameIn)"}
    }
    #$nic.IpConfigurations[0].LoadBalancerInboundNatRules.Remove($nicInRule)
    #$nic | Set-AzNetworkInterface
    #>

    Write-Host "Configuring nics outbound rule" -ForegroundColor $CommandInfo
    $nic = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $VmNicName
    $nicOutRule = $nic.IpConfigurations[0].LoadBalancerBackendAddressPools | where { $_.Name -eq $RuleNameOut -or $_.Id -like "*$($RuleNameOut)"}
    if (-Not $nicOutRule)
    {
        Write-Host " - Creating rule for nic $VmNicName"
        $nic.IpConfigurations[0].LoadBalancerBackendAddressPools.Add($backPoolOut)
        $nic | Set-AzNetworkInterface
        $nic = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $VmNicName
        $nicOutRule = $nic.IpConfigurations[0].LoadBalancerBackendAddressPools | where { $_.Name -eq $RuleNameOut -or $_.Id -like "*$($RuleNameOut)"}
    }
    #$nic.IpConfigurations[0].LoadBalancerBackendAddressPools.Remove($nicOutRule)
    #$nic | Set-AzNetworkInterface

}

#Stopping Transscript
Stop-Transcript
