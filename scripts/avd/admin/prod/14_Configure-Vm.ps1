#Requires -Version 2.0
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
    16.11.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$hostpoolShareServer = "alyapinfserv001.alyaconsulting.ch",
    [string]$hostpoolShareName = "alyapinfavdh002$",
    [string[]]$LocalAdmins = @("konrad.brunner@alyaconsulting.ch", "alyaconsulting.ch\AAD DC Administrators")
)

$uncPath = "\\$($hostpoolShareServer)\$($hostpoolShareName)"
if (-Not (Test-Path $uncPath))
{
    Write-Error "Not able to access unc path $uncPath" -ErrorAction Continue
}
if (-Not $LocalAdmins)
{
	$LocalAdmins = @("$($env:COMPUTERNAME)Admin")
}
else
{
	$LocalAdmins += "$($env:COMPUTERNAME)Admin"
}

# Configure Regional Settings
Set-Timezone -Id "W. Europe Standard Time"
Set-WinHomeLocation -GeoId 223

# Enable PSRemoting
Enable-PSRemoting -Force
New-NetFirewallRule -Name "Allow WinRM HTTPS" -DisplayName "WinRM HTTPS" -Enabled True -Profile Any -Action Allow -Direction Inbound -LocalPort 5986 -Protocol TCP
$cert = Get-ChildItem "Cert:\LocalMachine\My" -Recurse | Where-Object { $_.DnsNameList -eq $env:COMPUTERNAME }
if(-Not $cert)
{
    $thumbprint = (New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation "Cert:\LocalMachine\My").Thumbprint
}
else
{
    $thumbprint = $cert.Thumbprint
}
$command = "winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=""$env:computername""; CertificateThumbprint=""$thumbprint""}"
cmd.exe /C $command

# Configure FSLogix
$fslogixAppsRegPath = "HKLM:\SOFTWARE\FSLogix\Apps"
$fslogixProfileRegPath = "HKLM:\SOFTWARE\FSLogix\Profiles"
$fslogixContainerRegPath = "HKLM:\SOFTWARE\Policies\FSLogix\ODFC"
if (!(Test-Path $fslogixAppsRegPath))
{
    New-Item -Path $fslogixAppsRegPath -Force
}
if (!(Test-Path $fslogixProfileRegPath))
{
    New-Item -Path $fslogixProfileRegPath -Force
}
New-ItemProperty -Path $fslogixProfileRegPath -Name "Enabled" -Value "1" -PropertyType DWORD -Force
New-ItemProperty -Path $fslogixProfileRegPath -Name "VHDLocations" -Value "$uncPath\Profiles" -PropertyType MultiString -Force
if (!(Test-Path $fslogixContainerRegPath))
{
    New-Item -Path $fslogixContainerRegPath -Force
}
New-ItemProperty -Path $fslogixContainerRegPath -Name "Enabled" -Value "1" -PropertyType DWORD -Force
New-ItemProperty -Path $fslogixContainerRegPath -Name "VHDLocations" -Value "$uncPath\Containers" -PropertyType MultiString -Force
foreach($LocalAdmin in $LocalAdmins)
{
    Add-LocalGroupMember -Group "Administrators" -Member $LocalAdmin -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "Administrators" -Member $LocalAdmin -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "Administratoren" -Member $LocalAdmin -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "Administratoren" -Member $LocalAdmin -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "FSLogix ODFC Exclude List" -Member $LocalAdmin -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "FSLogix Profile Exclude List" -Member $LocalAdmin -ErrorAction SilentlyContinue
}

#Get-Service -Name "WSearch" | Set-Service -StartupType Automatic
$drv = Get-WmiObject win32_volume -filter 'DriveLetter = "E:"'
if ($drv)
{
    $drv.DriveLetter = "G:"
    $drv.Put()
}

sfc /scannow
