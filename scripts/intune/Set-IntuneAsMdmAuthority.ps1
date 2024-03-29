﻿#Requires -Version 2.0

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
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Set-IntuneAsMdmAuthority-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "Directory.ReadWrite.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Set-IntuneAsMdmAuthority | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting actual authority
Write-Host "Getting actual authority" -ForegroundColor $CommandInfo
$uri = "/beta/organization('$AlyaTenantId')?`$select=mobiledevicemanagementauthority"
$MDMAuthority = (Get-MsGraphObject -Uri $uri).mobileDeviceManagementAuthority
Write-Host "  Actual authority: $MDMAuthority"

# Checking authority
Write-Host "Checking authority" -ForegroundColor $CommandInfo
if($MDMAuthority -notlike "intune")
{
    try
    {
        # Setting intune as authority
        Write-Host "Setting intune as authority" -ForegroundColor $CommandInfo
        $uri = "/beta/organization/$AlyaTenantId/setMobileDeviceManagementAuthority"
        $ret = Post-MsGraph -Uri $uri -Body "{}"
    }
    catch
    {
        Write-Host "We have actually an issue, configuring the MDM authority by script."
        Write-Host "Please go to https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Mobility"
        Write-Host " - Select 'Microsoft Intune'"
        Write-Host " - Set for MDM and MAM 'All'"
        Write-Host " - Save"
        Start-Process "https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Mobility"
        pause
    }
}
else {
    Write-Host "Authority is already set to intune"
}

#Stopping Transscript
Stop-Transcript
