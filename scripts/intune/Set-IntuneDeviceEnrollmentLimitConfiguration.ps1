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
    19.02.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Set-IntuneDeviceEnrollmentLimitConfiguration-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.DeviceManagement.Enrollment"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @(
    "DeviceManagementServiceConfig.ReadWrite.All",
    "Directory.Read.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Set-IntuneDeviceEnrollmentLimitConfiguration | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting actual DeviceEnrollmentConfigurations
Write-Host "Getting actual DeviceEnrollmentConfiguration - limit" -ForegroundColor $CommandInfo
$deviceEnrollmentConfigurations = Get-MgDeviceManagementDeviceEnrollmentConfiguration
$deviceEnrollmentLimitConfiguration = $deviceEnrollmentConfigurations | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.deviceEnrollmentLimitConfiguration" }

# Setting actual DeviceEnrollmentConfigurations
Write-Host "Setting actual DeviceEnrollmentConfiguration - limit" -ForegroundColor $CommandInfo
if ($deviceEnrollmentLimitConfiguration.AdditionalProperties.limit -eq 15) {
    Write-Host "Limit was alreadey set to 15"
} else {
    Write-Warning "Updating limit from $($deviceEnrollmentLimitConfiguration.AdditionalProperties.limit) to 15"
    $params = @{
        "@odata.type" = "#microsoft.graph.deviceEnrollmentLimitConfiguration"
        limit = 15
    }
    $null = Update-MgDeviceManagementDeviceEnrollmentConfiguration -DeviceEnrollmentConfigurationId $deviceEnrollmentLimitConfiguration.Id -BodyParameter $params
}

#Stopping Transscript
Stop-Transcript
