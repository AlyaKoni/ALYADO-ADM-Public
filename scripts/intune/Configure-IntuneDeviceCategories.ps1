#Requires -Version 2.0

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
    21.10.2020 Konrad Brunner       Initial Version
    24.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-IntuneDeviceCategories-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "DeviceManagementManagedDevices.ReadWrite.All"
)
#Disconnect-MgBetaGraph

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Configure-IntuneDeviceCategories | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Processing categories
foreach($categoryName in $AlyaDeviceCategories)
{
    Write-Host "Configuring category '$($categoryName)'" -ForegroundColor $CommandInfo

    $body = @"
{
  "@odata.type": "#Microsoft.Graph.deviceCategory",
  "displayName": "$categoryName",
  "description": "Device category to manage devices of type $categoryName"
}
"@

    # Checking if category exists
    Write-Host "  Checking if category exists"
    $searchValue = [System.Web.HttpUtility]::UrlEncode($categoryName)
    $uri = "/beta/deviceManagement/deviceCategories?`$filter=displayName eq '$searchValue'"
    $actCategory = (Get-MsGraphObject -Uri $uri).value
    if (-Not $actCategory.id)
    {
        # Creating the category
        Write-Host "    Category does not exist, creating"
        $uri = "/beta/deviceManagement/deviceCategories"
        $actCategory = Post-MsGraph -Uri $uri -Body $body
    }

    # Updating the category
    Write-Host "    Updating the category"
    $uri = "/beta/deviceManagement/deviceCategories/$($actCategory.id)"
    $actCategory = Patch-MsGraph -Uri $uri -Body $body
}

#Stopping Transscript
Stop-Transcript
