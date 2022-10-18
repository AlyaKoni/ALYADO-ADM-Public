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
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Set-IntuneAsMdmAuthority-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Set-IntuneAsMdmAuthority | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context and token
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}
$token = Get-AdalAccessToken

# Getting actual authority
Write-Host "Getting actual authority" -ForegroundColor $CommandInfo
$uri = "https://graph.microsoft.com/beta/organization('$AlyaTenantId')?`$select=mobiledevicemanagementauthority"
$MDMAuthority = (Get-MsGraphObject -AccessToken $token -Uri $uri).mobileDeviceManagementAuthority
Write-Host "  Actual authority: $MDMAuthority"

if($MDMAuthority -notlike "intune")
{
    try
    {
        # Setting intune as authority
        Write-Host "Setting intune as authority" -ForegroundColor $CommandInfo
        $uri = "https://graph.microsoft.com/beta/organization/$AlyaTenantId/setMobileDeviceManagementAuthority"
        $ret = Post-MsGraph -AccessToken $token -Uri $uri -Body "{}"
    }
    catch
    {
        Write-Host "We have actually an issue, configuring the MDM authority by script."
        Write-Host "Please go to https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Mobility"
        Write-Host " - Select 'Microsoft Intune'"
        Write-Host " - Set for MDM and MAM 'All'"
        Write-Host " - Save"
        start https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Mobility
        pause
    }
}

#Stopping Transscript
Stop-Transcript
