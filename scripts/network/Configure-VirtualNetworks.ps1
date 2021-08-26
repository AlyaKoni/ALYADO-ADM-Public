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
	16.08.2021 Konrad Brunner		Added provider registration

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\network\Configure-VirtualNetworks-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainNetwork)"
$VirtualNetworkName = "$($AlyaNamingPrefix)vnet$($AlyaResIdVirtualNetwork)"
$DefaultSubnetName = "$($VirtualNetworkName)snet{0}"
$DefaultSubnetSecGrpName = "$($VirtualNetworkName)snet{0}sgrp"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Network | Configure-VirtualNetworks | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking resource provider registration
Write-Host "Checking resource provider registration Microsoft.Network" -ForegroundColor $CommandInfo
$resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Network" -Location $AlyaLocation
if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
{
    Write-Warning "Resource provider Microsoft.Network not registered. Registering now resource provider Microsoft.Network"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Network" | Out-Null
    do
    {
        Start-Sleep -Seconds 5
        $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Network" -Location $AlyaLocation
    } while ($resProv[0].RegistrationState -ne "Registered")
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ResourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $ResourceGroupName -Location $AlyaLocation -Tag @{displayName="Main Network Services";ownerEmail=$Context.Account.Id}
}

# Checking virtual network
Write-Host "Checking virtual network" -ForegroundColor $CommandInfo
$VNet = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName -ErrorAction SilentlyContinue
if (-Not $VNet)
{
    Write-Warning "Virtual network not found. Creating the virtual network $VirtualNetworkName"
    $VNet = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName -Location $AlyaLocation -AddressPrefix $AlyaProdNetwork
}

# Calculating subnets
Write-Host "Calculating subnets" -ForegroundColor $CommandInfo
$Networks = Split-NetworkAddressWithGateway -netwandcidr $AlyaProdNetwork -gwcidr $AlyaGatewayPrefixLength -splitcidr $AlyaSubnetPrefixLength

# Checking network subnets and security groups
Write-Host "Checking network subnets and security groups" -ForegroundColor $CommandInfo
$VNet = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VirtualNetworkName -ErrorAction SilentlyContinue
$Subnets = $VNet.Subnets
$dirty = $false
for ($i = 1; $i -lt $Networks.Count; $i++)
{
    $SubnetName = "$DefaultSubnetName" -f "$i".PadLeft(2, "0")
    $SubnetSecGrpName = "$DefaultSubnetSecGrpName" -f "$i".PadLeft(2, "0")
    $Subnet = $Networks[$i-1]
    $exist = $Subnets | where { $_.Name -eq $SubnetName }
    if (-Not $exist)
    {
        $SubnetSecGrp = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $SubnetSecGrpName -ErrorAction SilentlyContinue
        if (-Not $SubnetSecGrp)
        {
            Write-Warning "Network security group not found. Creating the network security group $SubnetSecGrpName"
            $SubnetSecGrp = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $SubnetSecGrpName -Location $AlyaLocation
        }
        Write-Warning "Subnet not found. Creating the subnet $SubnetName"
        Add-AzVirtualNetworkSubnetConfig -VirtualNetwork $VNet -Name $SubnetName -AddressPrefix $Subnet -NetworkSecurityGroup $SubnetSecGrp
        $dirty = $true
    }
}
$GatewaySubnetName = "GatewaySubnet"
$exist = $Subnets | where { $_.Name -eq $GatewaySubnetName }
if (-Not $exist)
{
    Add-AzVirtualNetworkSubnetConfig -VirtualNetwork $VNet -Name $GatewaySubnetName -AddressPrefix $Networks[$Networks.Count-1]
    $dirty = $true
}
if ($dirty)
{
    $VNet | Set-AzVirtualNetwork
}

#Stopping Transscript
Stop-Transcript