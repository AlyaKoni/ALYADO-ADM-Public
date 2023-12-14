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
    26.05.2023 Konrad Brunner       Initial Version
    12.12.2023 Konrad Brunner       Removed $filter odata query, was throwing bad request

#>

[CmdletBinding()]
Param(
    [string]$winGetAppsFile = $null #defaults to $($AlyaData)\intune\appsWinGet.json
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Upload-WinGetApps-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
if (-Not [string]::IsNullOrEmpty($AlyaAppPrefix)) {
    $AppPrefix = "$AlyaAppPrefix "
}
else {
    $AppPrefix = "WIN "
}
if (-Not $winGetAppsFile)
{
    $winGetAppsFile = "$($AlyaData)\intune\appsWinGet.json"
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
Write-Host "Intune | Upload-WinGetApps | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$winGetApps = Get-Content -Path $winGetAppsFile -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json

# Processing defined WinGetApps
$hadError = $false
foreach($winGetApp in $winGetApps)
{
    if (-Not $winGetApp.displayName -or $winGetApp.displayName.EndsWith("_unused")) { continue }
    Write-Host "Configuring WinGetApp $($winGetApp.displayName)" -ForegroundColor $CommandInfo
    
    try {
        
        # Checking if WinGetApp exists
        Write-Host "  Checking if WinGetApp exists"
        if (!$AppPrefix.StartsWith("WIN "))
        {   
            $winGetApp.displayName = $winGetApp.displayName.Replace("WIN ", $AppPrefix)
        }
        $uri = "/beta/deviceAppManagement/mobileApps"
        $allApps = Get-MsGraphCollection -Uri $uri
        $actApp = $allApps | where { $_.displayName -eq $winGetApp.displayName }
        if (-Not $actApp.id)
        {
            # Creating the WinGetApp
            Write-Host "    App does not exist, creating"
            $uri = "/beta/deviceAppManagement/mobileApps"
            $actApp = Post-MsGraph -Uri $uri -Body ($winGetApp | ConvertTo-Json -Depth 50)
        }

        # Waiting until published
        $uri = "/beta/deviceAppManagement/mobileApps"
        $retries = 30
        do {
            $retries--
            Start-Sleep -Seconds 5
            $allApps = Get-MsGraphCollection -Uri $uri
            $actApp = $allApps | where { $_.displayName -eq $winGetApp.displayName }
        } while ($actApp.publishingState -ne "published" -and $retries -ge 0)

        # Updating the WinGetApp
        Write-Host "    Updating the WinGetApp"
        $winGetApp.PSObject.Properties.Remove("developer")
        $winGetApp.PSObject.Properties.Remove("publisher")
        $winGetApp.PSObject.Properties.Remove("owner")
        $winGetApp.PSObject.Properties.Remove("channel")
        $winGetApp.PSObject.Properties.Remove("installExperience")
        $winGetApp.PSObject.Properties.Remove("packageIdentifier")
        $uri = "/beta/deviceAppManagement/mobileApps/$($actApp.id)"
        $actApp = Patch-MsGraph -Uri $uri -Body ($winGetApp | ConvertTo-Json -Depth 50)
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
