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
    03.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\client\os\Set-ClientRegionalSettings-$($AlyaTimeString).log" | Out-Null

# Checking TimeZone
Write-Host "Checking TimeZone" -ForegroundColor $CommandInfo
$TimeZone = Get-TimeZone
if ($TimeZone -ne $AlyaTimeZone)
{
    Write-Warning "Setting TimeZone to $AlyaTimeZone"
    Set-TimeZone -Id $AlyaTimeZone
}

# Checking WinHomeLocation
Write-Host "Checking WinHomeLocation" -ForegroundColor $CommandInfo
$WinHomeLocation = Get-WinHomeLocation
if ($WinHomeLocation -ne $AlyaGeoId)
{
    Write-Warning "Setting WinHomeLocation to $AlyaGeoId"
    Set-WinHomeLocation -GeoId $AlyaGeoId
}

#TODO Set-WinSystemLocale -SystemLocale en-US

#Stopping Transscript
Stop-Transcript
