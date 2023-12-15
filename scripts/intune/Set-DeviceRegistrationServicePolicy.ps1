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
    06.10.2020 Konrad Brunner       Initial Version
    24.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Set-DeviceRegistrationServicePolicy-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @(
    "Policy.ReadWrite.DeviceConfiguration",
    "Directory.Read.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Set-DeviceRegistrationServicePolicy | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
Write-Host "Getting actual DeviceRegistrationServicePolicy" -ForegroundColor $CommandInfo
$policy = Get-MgBetaPolicyDeviceRegistrationPolicy
$policy | ConvertTo-Json -Depth 5

Write-Host "Setting DeviceRegistrationServicePolicy" -ForegroundColor $CommandInfo
$allowedGroups = @()
if ($AlyaAllowDeviceRegistration -and -Not [string]::IsNullOrEmpty($AlyaAllowDeviceRegistration) -and `
    $AlyaAllowDeviceRegistration -is [System.Array]) {
    foreach ($grpName in $AlyaAllowDeviceRegistration) {
        $allowedGroup = Get-MgBetaGroup -Filter "DisplayName eq '$($grpName)'"
        if ($allowedGroup) {
            $allowedGroups += $allowedGroup
        } else {
            Write-Wrning "Group $grpName not found!"
        }
    }
}
if ($AlyaAllowDeviceRegistration -and -Not [string]::IsNullOrEmpty($AlyaAllowDeviceRegistration) -and `
    $AlyaAllowDeviceRegistration -isnot [System.Array] -and $AlyaAllowDeviceRegistration -ne "None" -and $AlyaAllowDeviceRegistration -ne "All") {
    $allowedGroup = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaAllowDeviceRegistration)'"
    if ($allowedGroup) {
        $allowedGroups += $allowedGroup
    } else {
        Write-Wrning "Group $AlyaAllowDeviceRegistration not found!"
    }
}

try
{
    if ($allowedGroups.Count -gt 0)
    {
        $allowedIds = "`"" + ($allowedGroups.Id -join "`",`"") + "`""
        $body = @"
    {
        "Id": "deviceRegistrationPolicy",
        "DisplayName": "Device Registration Policy",
        "Description": "Tenant-wide policy that manages intial provisioning controls using quota restrictions, additional authentication and authorization checks",      
        "MultiFactorAuthConfiguration": "0",
        "UserDeviceQuota": 50,
        "AzureAdJoin": {
            "AllowedGroups": [$($allowedIds)],
            "AllowedUsers": [],
            "AppliesTo": "2",
            "IsAdminConfigurable": true
        },
        "AzureAdRegistration": {
            "AllowedGroups": [],
            "AllowedUsers": [],
            "AppliesTo": "1",
            "IsAdminConfigurable": false
        },
        "localAdminPassword": {
            "isEnabled": true
        }
    }
"@
        Put-MsGraph -Uri "/beta/policies/deviceRegistrationPolicy" -Body $body
    }
    else
    {
        $body = @"
    {
        "Id": "deviceRegistrationPolicy",
        "DisplayName": "Device Registration Policy",
        "Description": "Tenant-wide policy that manages intial provisioning controls using quota restrictions, additional authentication and authorization checks",      
        "MultiFactorAuthConfiguration": "0",
        "UserDeviceQuota": 50,
        "AzureAdJoin": {
            "AllowedGroups": [],
            "AllowedUsers": [],
            "AppliesTo": "1",
            "IsAdminConfigurable": true
        },
        "AzureAdRegistration": {
            "AllowedGroups": [],
            "AllowedUsers": [],
            "AppliesTo": "1",
            "IsAdminConfigurable": false
        },
        "localAdminPassword": {
            "isEnabled": true
        }
    }
"@
        Put-MsGraph -Uri "/beta/policies/deviceRegistrationPolicy" -Body $body
    }
}
catch
{
    Write-Error $_.Exception -ErrorAction Continue
    Write-Host "We have actually an issue, configuring the DeviceRegistrationOption by script."
    Write-Host "Please go to https://portal.azure.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings/menuId~/null"
    Write-Host " - Select Join allowed for $AlyaDeviceAdminsGroupName"
    Write-Host " - 50 devices per user"
    Write-Host " - Enable LAPS"
    Write-Host " - Save"
    Start-Process "https://portal.azure.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings/menuId~/null"
    pause
}

Write-Host "Getting new DeviceRegistrationServicePolicy" -ForegroundColor $CommandInfo
$policy = Get-MgBetaPolicyDeviceRegistrationPolicy
$policy | ConvertTo-Json -Depth 99

#Stopping Transscript
Stop-Transcript
