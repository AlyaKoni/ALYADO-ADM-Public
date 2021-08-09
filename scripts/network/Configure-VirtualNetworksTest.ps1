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
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\network\Configure-VirtualNetworksTest-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupNameProd = "$($AlyaNamingPrefix)resg$($AlyaResIdMainNetwork)"
$VirtualNetworkNameProd = "$($AlyaNamingPrefix)vnet$($AlyaResIdVirtualNetwork)"
$ResourceGroupNameTest = "$($AlyaNamingPrefixTest)resg$($AlyaResIdMainNetwork)"
$VirtualNetworkNameTest = "$($AlyaNamingPrefixTest)vnet$($AlyaResIdVirtualNetwork)"
$DefaultSubnetName = "$($VirtualNetworkNameTest)snet{0}"
$DefaultSubnetSecGrpName = "$($VirtualNetworkNameTest)snet{0}sgrp"
$VirtualNetworkProdPeeringName = "$($VirtualNetworkNameProd)peer$($VirtualNetworkNameTest)"
$VirtualNetworkTestPeeringName = "$($VirtualNetworkNameTest)peer$($VirtualNetworkNameProd)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Network | Configure-VirtualNetworksTest | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking ressource group prod
Write-Host "Checking ressource group prod" -ForegroundColor $CommandInfo
$ResGrpProd = Get-AzResourceGroup -Name $ResourceGroupNameProd -ErrorAction SilentlyContinue
if (-Not $ResGrpProd)
{
    throw "Ressource Group not found. Please create the Ressource Group $ResourceGroupNameProd"
}

# Checking ressource group test
Write-Host "Checking ressource group test" -ForegroundColor $CommandInfo
$ResGrpTest = Get-AzResourceGroup -Name $ResourceGroupNameTest -ErrorAction SilentlyContinue
if (-Not $ResGrpTest)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ResourceGroupNameTest"
    $ResGrpTest = New-AzResourceGroup -Name $ResourceGroupNameTest -Location $AlyaLocation -Tag @{displayName="Main Test Network Services";ownerEmail=$Context.Account.Id}
}

# Checking virtual network prod
Write-Host "Checking virtual network prod" -ForegroundColor $CommandInfo
$VNetProd = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupNameProd -Name $VirtualNetworkNameProd -ErrorAction SilentlyContinue
if (-Not $VNetProd)
{
    throw "Virtual network not found. Please create the virtual network $VirtualNetworkNameProd"
}

# Checking virtual network test
Write-Host "Checking virtual network test" -ForegroundColor $CommandInfo
$VNetTest = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupNameTest -Name $VirtualNetworkNameTest -ErrorAction SilentlyContinue
if (-Not $VNetTest)
{
    Write-Warning "Virtual network not found. Creating the virtual network $VirtualNetworkNameTest"
    $VNetTest = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupNameTest -Name $VirtualNetworkNameTest -Location $AlyaLocation -AddressPrefix $AlyaTestNetwork
}

# Calculating subnets
Write-Host "Calculating subnets" -ForegroundColor $CommandInfo
$Networks = Split-NetworkAddressWithoutGateway -netwandcidr $AlyaTestNetwork -splitcidr $AlyaSubnetPrefixLength

# Checking network subnets and security groups
Write-Host "Checking network subnets and security groups" -ForegroundColor $CommandInfo
$VNet = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupNameTest -Name $VirtualNetworkNameTest -ErrorAction SilentlyContinue
$Subnets = $VNet.Subnets
$dirty = $false
for ($i = 1; $i -lt ($Networks.Count+1); $i++)
{
    $SubnetName = "$DefaultSubnetName" -f "$i".PadLeft(2, "0")
    $SubnetSecGrpName = "$DefaultSubnetSecGrpName" -f "$i".PadLeft(2, "0")
    $Subnet = $Networks[$i-1]
    $exist = $Subnets | where { $_.Name -eq $SubnetName }
    if (-Not $exist)
    {
        $SubnetSecGrp = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupNameTest -Name $SubnetSecGrpName -ErrorAction SilentlyContinue
        if (-Not $SubnetSecGrp)
        {
            Write-Warning "Network security group not found. Creating the network security group $SubnetSecGrpName"
            $SubnetSecGrp = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupNameTest -Name $SubnetSecGrpName -Location $AlyaLocation
        }
        Write-Warning "Subnet not found. Creating the subnet $SubnetName"
        Add-AzVirtualNetworkSubnetConfig -VirtualNetwork $VNet -Name $SubnetName -AddressPrefix $Subnet -NetworkSecurityGroup $SubnetSecGrp
        $dirty = $true
    }
}
if ($dirty)
{
    $VNet | Set-AzVirtualNetwork
}

# Checking peering test
Write-Host "Checking peering test" -ForegroundColor $CommandInfo
$PeerTest = Get-AzVirtualNetworkPeering -ResourceGroupName $ResourceGroupNameTest -VirtualNetworkName $VirtualNetworkNameTest -Name $VirtualNetworkTestPeeringName -ErrorAction SilentlyContinue
if (-Not $PeerTest)
{
    Write-Warning "Virtual network peering not found. Creating the virtual network peering $VirtualNetworkTestPeeringName"
    if ($AlyaDeployGateway)
    {
        $PeerTest = Add-AzVirtualNetworkPeering -VirtualNetwork $VNetTest -Name $VirtualNetworkTestPeeringName -RemoteVirtualNetworkId $VNetProd.Id -UseRemoteGateways
    }
    else
    {
        $PeerTest = Add-AzVirtualNetworkPeering -VirtualNetwork $VNetTest -Name $VirtualNetworkTestPeeringName -RemoteVirtualNetworkId $VNetProd.Id
    }
}

# Checking peering prod
Write-Host "Checking peering prod" -ForegroundColor $CommandInfo
$PeerProd = Get-AzVirtualNetworkPeering -ResourceGroupName $ResourceGroupNameProd -VirtualNetworkName $VirtualNetworkNameProd -Name $VirtualNetworkProdPeeringName -ErrorAction SilentlyContinue
if (-Not $PeerProd)
{
    Write-Warning "Virtual network peering not found. Creating the virtual network peering $VirtualNetworkProdPeeringName"
    if ($AlyaDeployGateway)
    {
        $PeerProd = Add-AzVirtualNetworkPeering -VirtualNetwork $VNetProd -Name $VirtualNetworkProdPeeringName -RemoteVirtualNetworkId $VNetTest.Id -AllowGatewayTransit
    }
    else
    {
        $PeerProd = Add-AzVirtualNetworkPeering -VirtualNetwork $VNetProd -Name $VirtualNetworkProdPeeringName -RemoteVirtualNetworkId $VNetTest.Id
    }
}

#Stopping Transscript
Stop-Transcript