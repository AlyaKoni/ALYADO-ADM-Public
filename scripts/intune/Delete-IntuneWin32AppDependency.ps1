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
    21.09.2023 Konrad Brunner       Initial Version
    12.12.2023 Konrad Brunner       Removed $filter odata query, was throwing bad request

#>

[CmdletBinding()]
Param(
    [string]$AppName = $null,
    [string]$DependentAppName = $null,
    [string]$AppsPath = "Win32Apps"
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Delete-IntuneWin32AppDependency-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$AppPrefix = "Win10 "
if (-Not [string]::IsNullOrEmpty($AlyaAppPrefix)) {
    $AppPrefix = "$AlyaAppPrefix "
}
$DataRoot = Join-Path (Join-Path $AlyaData "intune") $AppsPath
if (-Not (Test-Path $DataRoot))
{
    $null = New-Item -Path $DataRoot -ItemType Directory -Force
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
Write-Host "Intune | Delete-IntuneWin32AppDependency | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking if app exists
Write-Host "Checking if app exists" -ForegroundColor $CommandInfo
$uri = "/beta/deviceAppManagement/mobileApps"
$allApps = Get-MsGraphCollection -Uri $uri
$app = $allApps | where { $_.displayName -eq $AppPrefix+$AppName }
if (-Not $app.id)
{
    Write-Warning "The app with name $($AppPrefix+$AppName) does not exist."
    return
}
$appId = $app.id
Write-Host "    appId: $appId"

# Checking if dependent app exists
Write-Host "Checking if dependent app exists" -ForegroundColor $CommandInfo
$uri = "/beta/deviceAppManagement/mobileApps"
$allApps = Get-MsGraphCollection -Uri $uri
$depApp = $allApps | where { $_.displayName -eq $AppPrefix+$DependentAppName }
if (-Not $depApp.id)
{
    Write-Warning "The app with name $($AppPrefix+$DependentAppName) does not exist."
    return
}
$depAppId = $depApp.id
Write-Host "    depAppId: $depAppId"

Write-Host "Getting existing dependencies" -ForegroundColor $CommandInfo
$uri = "/beta/deviceAppManagement/mobileApps/$appId/relationships"
$actDependencies = (Get-MsGraphObject -Uri $uri).value
$depFound = $false
if ($actDependencies -and $actDependencies.Count -gt 0)
{
    foreach ($actDependency in $actDependencies)
    {
        if ($actDependency.targetId -eq $depAppId)
        {
            Write-Host "  Dependency found. Deleting..."
            $depFound = $true
            break
        }
    }
}

if ($depFound)
{
    Write-Host "Deleting dependencies" -ForegroundColor $CommandInfo
    $newDependencies = @()
    foreach ($actDependency in ($actDependencies | where { $_.targetId -ne $depAppId }))
    {
        $newDependency = @{ "@odata.type" = "#Microsoft.Graph.mobileAppDependency" }
        $newDependency.targetId = $actDependency.targetId
        $newDependency.dependencyType = $actDependency.dependencyType
        $newDependencies += $newDependency
    }
    $uri = "/beta/deviceAppManagement/mobileApps/$appId/updateRelationships"
    $body = @{}
    $body.relationships = $newDependencies
    $appCat = Post-MsGraph -Uri $uri -Body ($body | ConvertTo-Json -Depth 50)
}

#Stopping Transscript
Stop-Transcript
