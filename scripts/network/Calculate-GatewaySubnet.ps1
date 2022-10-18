#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2021

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
    Date       Author     Description
    ---------- -------------------- ----------------------------
    13.03.2019 Konrad Brunner       Initial Version

#>

[CmdletBinding()] 
Param  
(
    [Parameter(Mandatory=$false)]
    [string] $vnetAdressRange,
    [Parameter(Mandatory=$false)]
    [string] $gatewayPrefixLength
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\network\Calculate-GatewaySubnet-$((Get-Date).ToString("yyyyMMddHHmmss")).log" | Out-Null

# https://gallery.technet.microsoft.com/scriptcenter/Address-prefix-calculator-a94b6eed

if (-Not $vnetAdressRange)
{
    Write-Host "Please specify the Vnet IP address range (w.x.y.z/n):"
    $vnetAdressRange = Read-Host
}
if (-Not $gatewayPrefixLength)
{
    Write-Host "Please specify the prefix length of your gateway subnet (n):"
    $gatewayPrefixLength = Read-Host
}

# Specify the values of w.x.y.z/n for your VNet address space and g, the prefix length of your gateway subnet: 
$parts = $vnetAdressRange.Split("/")
$ipps = $parts[0].Split(".")
$w = [int]$ipps[0]
$x = [int]$ipps[1]
$y = [int]$ipps[2]
$z = [int]$ipps[3]
$n = [int]$parts[1]
$g = [int]$gatewayPrefixLength

# Calculate 
$wOctet = 16777216 
$xOctet = 65536 
$yOctet = 256 
[long]$D = $w * $wOctet + $x * $xOctet + $y * $yOctet + $z; 
for ($i = $n + 1; $i -lt $g + 1; $i++) 
{ 
    $D = $D + [math]::pow(2, 32 - $i) 
} 
$w2 = [math]::floor($D / $wOctet) 
$x2 = [math]::floor( ($D - $w2 * $wOctet) / $xOctet ) 
$y2 = [math]::floor( ($D - $w2 * $wOctet - $x2 * $xOctet) / $yOctet ) 
$z2 = $D - $w2 * $wOctet - $x2 * $xOctet - $y2 * $yOctet 

# Display the result 
$dx = [string]$w2 + "." + [string]$x2 + "." + [string]$y2 + "." + [string]$z2 + "/" + [string]$g 

Write-Host "Your gateway address prefix is: " $dx 

#Stopping Transscript
Stop-Transcript
