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
    Date       Author               Description
    ---------- -------------------- ----------------------------
    06.10.2020 Konrad Brunner       Initial Version

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
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "MSOnline"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MSOL

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Set-DeviceRegistrationServicePolicy | MsOnline" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
Write-Host "Getting actual DeviceRegistrationServicePolicy" -ForegroundColor $CommandInfo
Get-MsolDeviceRegistrationServicePolicy

Write-Host "Setting DeviceRegistrationServicePolicy" -ForegroundColor $CommandInfo
if ($AlyaAllowDeviceRegistration -and $AlyaAllowDeviceRegistration -ne "None" -and $AlyaAllowDeviceRegistration -ne "All")
{
    $AlyaAllowDeviceRegistrationOption = "Selected"
    $AlyaAllowedGroups = Get-MsolGroup -SearchString $AlyaAllowDeviceRegistration
    #TODO Next part does not makes sense, may set cmdlt requires the user param filled!
    $caRole = Get-MsolRole -RoleName "Company Administrator"
    $caRoleMembs = Get-MsolRoleMember -RoleObjectId $caRole.ObjectId
    $AlyaAllowedUsers = @()
    foreach ($caRoleMemb in $caRoleMembs)
    {
        $AlyaAllowedUsers += Get-MsolUser -UserPrincipalName $caRoleMemb.EmailAddress
    }
}
else
{
    $AlyaAllowDeviceRegistrationOption = "All"
}

if ($AlyaAllowDeviceRegistrationOption -eq "Selected")
{
    Set-MsolDeviceRegistrationServicePolicy -AllowedToAzureAdJoin $AlyaAllowDeviceRegistrationOption -AllowedToWorkplaceJoin "None" -MaximumDevicesPerUser 100 -RequireMultiFactorAuth $true -Groups $AlyaAllowedGroups -Users $AlyaAllowedUsers
}
else
{
    Set-MsolDeviceRegistrationServicePolicy -AllowedToAzureAdJoin $AlyaAllowDeviceRegistrationOption -AllowedToWorkplaceJoin "None" -MaximumDevicesPerUser 100 -RequireMultiFactorAuth $true
}

Write-Host "Getting new DeviceRegistrationServicePolicy" -ForegroundColor $CommandInfo
Get-MsolDeviceRegistrationServicePolicy

#Stopping Transscript
Stop-Transcript