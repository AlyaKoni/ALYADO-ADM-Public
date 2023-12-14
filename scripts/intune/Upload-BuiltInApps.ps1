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
    12.12.2023 Konrad Brunner       Removed $filter odata query, was throwing bad request

#>

[CmdletBinding()]
Param(
    [string]$BuiltInAppsFile = $null #defaults to $($AlyaData)\intune\appsBuiltIn.json
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Upload-BuiltInApps-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
if (-Not [string]::IsNullOrEmpty($AlyaAppPrefix)) {
    $AppPrefix = "$AlyaAppPrefix "
}
else {
    $AppPrefix = "Win10 "
}
if (-Not $BuiltInAppsFile)
{
    $BuiltInAppsFile = "$($AlyaData)\intune\appsBuiltIn.json"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "Directory.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementApps.ReadWrite.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Upload-BuiltInApps | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$builtInApps = Get-Content -Path $BuiltInAppsFile -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json

# Processing defined builtInApps
$hadError = $false
foreach($builtInApp in $builtInApps)
{
    if (-Not $builtInApp.displayName -or $builtInApp.displayName.EndsWith("_unused")) { continue }
    Write-Host "Configuring builtInApp $($builtInApp.displayName)" -ForegroundColor $CommandInfo
    
    try {
        
        # Checking if builtInApp exists
        Write-Host "  Checking if builtInApp exists"
        if (!$AppPrefix.StartsWith("WIN "))
        {   
            $builtInApp.displayName = $builtInApp.displayName.Replace("WIN ", $AppPrefix)
        }
        $uri = "/beta/deviceAppManagement/mobileApps"
        $allApps = Get-MsGraphCollection -Uri $uri
        $actApp = $allApps | where { $_.displayName -eq $builtInApp.displayName }
        if (-Not $actApp.id)
        {
            # Creating the builtInApp
            Write-Host "    App does not exist, creating"
            $uri = "/beta/deviceAppManagement/mobileApps"
            $actApp = Post-MsGraph -Uri $uri -Body ($builtInApp | ConvertTo-Json -Depth 50)
        }

        # Updating the builtInApp
        Write-Host "    Updating the builtInApp"
        $builtInApp.PSObject.Properties.Remove("developer")
        $builtInApp.PSObject.Properties.Remove("publisher")
        $builtInApp.PSObject.Properties.Remove("owner")
        $builtInApp.PSObject.Properties.Remove("channel")
        $uri = "/beta/deviceAppManagement/mobileApps/$($actApp.id)"
        $actApp = Patch-MsGraph -Uri $uri -Body ($builtInApp | ConvertTo-Json -Depth 50)
    }
    catch {
        $hadError = $true
    }

}
if ($hadError)
{
    Write-Host "There was an error. Please see above." -ForegroundColor $CommandError
}

#Stopping Transscript
Stop-Transcript
