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
    02.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\network\Add-MyIpToSecGroups-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainNetwork)"
$VirtualNetworkName = "$($AlyaNamingPrefix)vnet$($AlyaResIdVirtualNetwork)"
$VirtualNetworkNameJumpHost = "$($AlyaNamingPrefix)vnet$($AlyaResIdVirtualNetwork)"
$VMSubnetNameJumpHost = "$($VirtualNetworkNameJumpHost)snet$($AlyaResIdJumpHostSNet)"
$subnetsToSecure = @($VMSubnetNameJumpHost)
$SecGroupRuleName = "AllowRdpSpecific"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Network | Add-MyIpToSecGroups | Azure" -ForegroundColor $CommandInfo
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
    throw "Ressource Group not found. Please create the Ressource Group $ResourceGroupName"
}

# Checking virtual network
Write-Host "Checking virtual network" -ForegroundColor $CommandInfo
$VNet = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName -ErrorAction SilentlyContinue
if (-Not $VNet)
{
    throw "Virtual network not found. Please create the virtual network $VirtualNetworkName"
}

# Getting my ip
Write-Host "Getting my ip" -ForegroundColor $CommandInfo
$myIpTest = (Invoke-WebRequest "https://myexternalip.com/raw?$($guid)=1" -ErrorAction SilentlyContinue).content
$myIp = $null
if (-not $myIpTest -or $myIp -ne $myIpTest)
{
    $myIp = $myIpTest
    $myIpTest = (Invoke-WebRequest "https://api.ipify.org?$($guid)=1" -ErrorAction SilentlyContinue).content
    if (-not $myIpTest -or $myIp -ne $myIpTest)
    {
        $myIp = $myIpTest
        $myIpTest = (Invoke-WebRequest "https://ifconfig.me/ip?$($guid)=1" -ErrorAction SilentlyContinue).content
        if (-not $myIpTest -or $myIp -ne $myIpTest)
        {
            $myIp = $myIpTest
            $myIpTest = (Invoke-WebRequest "http://checkip.amazonaws.com/?$($guid)=1" -ErrorAction SilentlyContinue).content
            if (-not $myIpTest -or $myIp -ne $myIpTest)
            {
                $myIp = $myIpTest
                $myIpTest = (Invoke-WebRequest "http://checkip.dyndns.org/?$($guid)=1" -ErrorAction SilentlyContinue).content
                $myIpTest = ($myIpTest  |  Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches).Matches.Value
                if (-not $myIpTest -or $myIp -ne $myIpTest)
                {
                    $myIpTest = (Invoke-WebRequest "http://www.myip.ch/?$($guid)=1" -ErrorAction SilentlyContinue).content
                    $myIp = ($myIpTest  |  Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches).Matches.Value
                }
            }
        }
    }
}
$myIp = $myIp + "/32"
$myIp

# Checking network subnets and security groups
Write-Host "Checking network subnets and security groups" -ForegroundColor $CommandInfo
$VNet = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName -ErrorAction SilentlyContinue
$Subnets = $VNet.Subnets
foreach ($Subnet in $Subnets)
{
    if (-Not $subnetsToSecure.Contains($Subnet.Name))
    {
        continue
    }
    if ($Subnet.NetworkSecurityGroup)
    {
        $SecGroupRes = Get-AzResource -ResourceId $Subnet.NetworkSecurityGroup.Id
        Write-Host "Checking security group $($SecGroupRes.Name)"
        $SecGroup = Get-AzNetworkSecurityGroup -Name $SecGroupRes.Name -ResourceGroupName $SecGroupRes.ResourceGroupName
        $Rule = $SecGroup.SecurityRules | where { $_.Name -eq $SecGroupRuleName }
        $dirty = $false
        if (-Not $Rule)
        {
            Write-Warning "Rule not found. Creating the rule $($SecGroupRuleName) on network security group $($SecGroupRes.Name)"
            $tmp = $SecGroup | Add-AzNetworkSecurityRuleConfig -Name $SecGroupRuleName -Description "Allows RDP for specific addresses" -Access Allow `
                -Protocol * -Direction Inbound -Priority 3333 -SourceAddressPrefix $myIp -SourcePortRange * `
                -DestinationAddressPrefix * -DestinationPortRange 3389
            $dirty = $true
        }
        else
        {
            $Rule = Get-AzNetworkSecurityRuleConfig -Name $SecGroupRuleName -NetworkSecurityGroup $SecGroup
            if ($Rule.SourceAddressPrefix -notcontains $myIp)
            {
                Write-Warning "IP not found in rule. Adding the ip $($myIp) on network security group $($SecGroupRes.Name)"
                $tmp = $Rule.SourceAddressPrefix.Add($myIp)
                $dirty = $true
            }
        }
        if ($dirty)
        {
            $tmp = $SecGroup | Set-AzNetworkSecurityGroup
        }
    }
}

#Stopping Transscript
Stop-Transcript