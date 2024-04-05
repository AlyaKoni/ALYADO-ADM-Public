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
    01.04.2024 Konrad Brunner       Initial Creation

#>

[CmdletBinding()]
Param(
    [string]$certSubject = $null,
    [string]$certThumbPrint = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Export-SMIMERootCasToSst-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "EXCHANGE | Export-SMIMERootCasToSst | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

if ([string]::IsNullOrEmpty($certSubject) -and [string]::IsNullOrEmpty($certSerial) -and [string]::IsNullOrEmpty($certThumbPrint))
{
    throw "You need to specify certSubject or certThumbPrint"
}

$cert = $null
$certs = Get-ChildItem -Path Cert:\CurrentUser -Recurse
if ($null -eq $cert -and -Not [string]::IsNullOrEmpty($certThumbPrint))
{
    $cert = $certs | Where-Object { $_.Thumbprint -eq $certThumbPrint }
}
if ($null -eq $cert -and -Not [string]::IsNullOrEmpty($certSubject))
{
    $cert = $certs | Where-Object { $_.Subject -eq $certSubject }
}
if ($null -eq $cert)
{
    throw "Certificate not found"
}

$rCert = $cert
$certExp = @()
$certExp += $cert
do
{
    $issuer = $certs | Where-Object { $_.Subject -eq $cert.Issuer }
    if (($Issuer | Get-Unique).Thumbprint -in $certExp.Thumbprint)
    {
        break
    }
    if ($null -ne $issuer)
    {
        $certExp += $issuer | Get-Unique
        $cert = $issuer | Get-Unique
    }
} while ($null -ne $issuer)


if (-Not (Test-Path "$AlyaData\exchange"))
{
    New-Item -Path "$AlyaData\exchange" -ItemType "Directory" -Force
}
if (-Not (Test-Path "$AlyaData\exchange\smime"))
{
    New-Item -Path "$AlyaData\exchange\smime" -ItemType "Directory" -Force
}
$fileName = "$AlyaData\exchange\smime\$($rCert.Thumbprint).sst"
$certExp | Export-Certificate -FilePath $fileName -Type "SST" -Force

Write-Host "SST exported to $AlyaData\exchange\smime\$($rCert.Thumbprint).sst"

#Stopping Transscript
Stop-Transcript
