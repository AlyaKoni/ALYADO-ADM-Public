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

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Change-IntuneWinAppPrefix-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$ActAppPrefix = "Win10 "
if (-Not [string]::IsNullOrEmpty($AlyaAppPrefix)) {
    $ActAppPrefix = "$AlyaAppPrefix "
}
$NewAppPrefix = "WIN "

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
Write-Host "Intune | Change-IntuneWinAppPrefix | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting list of all apps
Write-Host "Getting list of all apps" -ForegroundColor $CommandInfo
$uri = "/beta/deviceAppManagement/mobileApps"
$apps = (Get-MsGraphCollection -Uri $uri)
if (-Not $apps -or $apps.Count -eq 0)
{
    throw "No apps found!."
}

# Renaming apps
Write-Host "Renaming apps" -ForegroundColor $CommandInfo
foreach($app in $apps)
{
    if ($app.displayName -like "$($ActAppPrefix)*")
    {
        $newName = $app.displayName.Replace($ActAppPrefix, $NewAppPrefix)
        Write-Host "Renaming app '$($app.displayName)' to '$($newName)'"
        $app.displayName = $newName
        $app."@odata.type"
        $appId = $app.id
        $app = $app | Select-Object -Property * -ExcludeProperty Owner,Publisher,Developer,updateChannel,autoAcceptEula,targetVersion,officeSuiteAppDefaultFileFormat,officeConfigurationXml,useSharedComputerActivation,updateVersion,officePlatformArchitecture,installProgressDisplayLevel,shouldUninstallOlderVersionsOfOffice,productIds,localesToInstall,excludedApps,Channel,PackageIdentifier,ManifestHash,installExperience,largeIcon,isAssigned,dependentAppCount,supersedingAppCount,supersededAppCount,committedContentVersion,size,id,createdDateTime,lastModifiedDateTime,version,'@odata.context',uploadState,packageId,appIdentifier,publishingState,usedLicenseCount,totalLicenseCount,productKey,licenseType,packageIdentityName
        $uri = "/beta/deviceAppManagement/mobileApps/$appId"
        $null = Patch-MsGraph -Uri $uri -Body ($app | ConvertTo-Json -Depth 50)
    }
}

Write-Warning "Please change `$AlyaAppPrefix to WIN in $($AlyaData)\ConfigureEnv.ps1"

#Stopping Transscript
Stop-Transcript
