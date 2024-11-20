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
    01.05.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Create-IntuneMACPackagesCertificate-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$DataRoot = Join-Path (Join-Path $AlyaData "intune") $AppsPath
if (-Not (Test-Path $DataRoot))
{
    $null = New-Item -Path $DataRoot -ItemType Directory -Force
}
$outputPath = "$($DataRoot)\Certificate"
if (-Not (Test-Path $outputPath))
{
    $null = New-Item -Path $outputPath -ItemType Directory -Force
}

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Create-IntuneMACPackagesCertificate | Local" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$keyName = "$($outputPath )/InstallerCertificate_$($AlyaMacPackageInstallCertName)_Key.pem".Replace("\", "/")
$crtName = "$($outputPath )/InstallerCertificate_$($AlyaMacPackageInstallCertName)_Cert.pem".Replace("\", "/")
$cerName = "$($outputPath )/InstallerCertificate_$($AlyaMacPackageInstallCertName)_Cert.cer".Replace("\", "/")
openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -sha256 -addext basicConstraints=critical,CA:false -addext keyUsage=critical,digitalSignature -set_serial "0x$(openssl rand -hex 4)" -subj "/CN=Installer Certificate ($AlyaMacPackageInstallCertName)" -out "$crtName" -keyout "$keyName"
cp "$crtName" "$cerName"
security import "$crtName"
security import "$keyName" -T /usr/bin/productbuild -T /usr/bin/pkgbuild

Write-Host "Please backup and secure the private key: $keyName" -ForegroundColor $CommandSuccess

#Stopping Transscript
Stop-Transcript
