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
#Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
#Install-ModuleIfNotInstalled "AzureADPreview"
Install-ModuleIfNotInstalled "MSOnline"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
#LoginTo-Az -SubscriptionName $AlyaSubscriptionName
#LoginTo-AD
Connect-MsolService
#LoginTo-MSOL

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Set-DeviceRegistrationServicePolicy | MsOnline" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Main
Write-Host "Getting actual DeviceRegistrationServicePolicy" -ForegroundColor $CommandInfo
Get-MsolDeviceRegistrationServicePolicy -ErrorAction SilentlyContinue

Write-Host "Setting DeviceRegistrationServicePolicy" -ForegroundColor $CommandInfo
if ($AlyaAllowDeviceRegistration -and $AlyaAllowDeviceRegistration -ne "None" -and $AlyaAllowDeviceRegistration -ne "All")
{
    $AlyaAllowDeviceRegistrationOption = "Selected"
    $AlyaAllowedGroups = Get-MsolGroup -SearchString $AlyaAllowDeviceRegistration
    #TODO Next part does not makes sense, may set cmdlt requires the user param filled!
    $AlyaAllowedUsers = Get-MsolUser -UserPrincipalName $Context.Account.Id
}
else
{
    $AlyaAllowDeviceRegistrationOption = "All"
}

if ($AlyaAllowDeviceRegistrationOption -eq "Selected")
{
    try
    {
        $sel = [Microsoft.Online.Administration.Automation.DeviceRegistrationServicePolicy+Scope]::Selected
        $non = [Microsoft.Online.Administration.Automation.DeviceRegistrationServicePolicy+Scope]::None
        Set-MsolDeviceRegistrationServicePolicy -MaximumDevicesPerUser 50
        Set-MsolDeviceRegistrationServicePolicy -RequireMultiFactorAuth $true
        Set-MsolDeviceRegistrationServicePolicy -AllowedToAzureAdJoin $sel -AllowedToWorkplaceJoin $non -Users $AlyaAllowedUsers -Groups $AlyaAllowedGroups
    }
    catch
    {
        Write-Error $_.Exception -ErrorAction Continue
        Write-Host "We have actually an issue, configuring the DeviceRegistrationOption by script."
        Write-Host "Please go to https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Mobility"
        Write-Host " - Select 'Microsoft Intune'"
        Write-Host " - Set for MDM and MAM 'Selected'"
        Write-Host " - Add group '$AlyaAllowDeviceRegistration'"
        Write-Host " - Save"
        start https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Mobility
        pause
    }
}
else
{
    try
    {
        $all = [Microsoft.Online.Administration.Automation.DeviceRegistrationServicePolicy+Scope]::All
        $non = [Microsoft.Online.Administration.Automation.DeviceRegistrationServicePolicy+Scope]::None
        Set-MsolDeviceRegistrationServicePolicy -MaximumDevicesPerUser 50
        Set-MsolDeviceRegistrationServicePolicy -RequireMultiFactorAuth $true
        Set-MsolDeviceRegistrationServicePolicy -AllowedToAzureAdJoin $all -AllowedToWorkplaceJoin $non
    }
    catch
    {
        Write-Error $_.Exception -ErrorAction Continue
        Write-Host "We have actually an issue, configuring the DeviceRegistrationOption by script."
        Write-Host "Please go to https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Mobility"
        Write-Host " - Select 'Microsoft Intune'"
        Write-Host " - Set for MDM and MAM 'All'"
        Write-Host " - Save"
        start https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Mobility
        pause
    }
}

# Checking azure ad join rights
Write-Host "Checking azure ad join rights" -ForegroundColor $CommandInfo
Write-Host "Please allow only group $AlyaAllowDeviceRegistration to join devices"
Write-Host "https://portal.azure.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings/menuId~/null"
start "https://portal.azure.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings/menuId~/null"
pause

Write-Host "Getting new DeviceRegistrationServicePolicy" -ForegroundColor $CommandInfo
Get-MsolDeviceRegistrationServicePolicy -ErrorAction SilentlyContinue

#Stopping Transscript
Stop-Transcript
