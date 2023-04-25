#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2021-2023

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
    25.08.2021 Konrad Brunner       Initial Version
    03.11.2021 Konrad Brunner       Added v14_0
    24.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
    [string]$appsIOSFile = $null, #defaults to $($AlyaData)\intune\appsIOS.json
    [string]$appStoreCountry = "ch"
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Upload-iOSApps-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
if (-Not $appsIOSFile)
{
    $appsIOSFile = "$($AlyaData)\intune\appsIOS.json"
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
Write-Host "Intune | Upload-iOSApps | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$appsIOS = Get-Content -Path $appsIOSFile -Raw -Encoding UTF8 | ConvertFrom-Json

# Processing defined appsIOS
$hadError = $false
foreach($iosApp in $appsIOS)
{
    if ($iosApp.displayName.EndsWith("_unused")) { continue }
    Write-Host "Configuring iosApp $($iosApp.displayName)" -ForegroundColor $CommandInfo
    
    try {
        
        # Getting store data
        $storeApp = Invoke-RestMethod -Uri "http://itunes.apple.com/lookup?country=$appStoreCountry&bundleId=$($iosApp.bundleId)" -Method Get
        $app = $storeApp.results[0]
        $iconUrl = $app.artworkUrl60
        if ($null -eq $iconUrl)
        {
            $iconUrl = $app.artworkUrl100
        }
        if ($null -eq $iconUrl)
        {
            $iconUrl = $app.artworkUrl512
        }
        $iconResponse = Invoke-WebRequest $iconUrl
        $base64icon = [System.Convert]::ToBase64String($iconResponse.Content)
        $iconType = ($iconResponse.Headers["Content-Type"] | Out-String).Trim()
        if(($app.minimumOsVersion.Split(".")).Count -gt 2)
        {
            $Split = $app.minimumOsVersion.Split(".")
            $MOV = $Split[0] + "." + $Split[1]
            $osVersion = [Convert]::ToDouble($MOV)
        }
        else
        {
            $osVersion = [Convert]::ToDouble($app.minimumOsVersion)
        }
        if($app.supportedDevices -match "iPadMini"){ $iPad = $true } else { $iPad = $false }
        if($app.supportedDevices -match "iPhone6"){ $iPhone = $true } else { $iPhone = $false }
        $description = $app.description # -replace "[^\x00-\x7F]+",""

        $iosApp.displayName = "IOS " + $app.trackName
        $iosApp.publisher = $app.artistName
        $iosApp.description = $description
        $iosApp.largeIcon = @{
            "@odata.type" = "#microsoft.graph.mimeContent"
            type = $iconType
            value = $base64icon
        }
        $iosApp.appStoreUrl = $app.trackViewUrl
        $iosApp.applicableDeviceType = @{
            iPad = $iPad
            iPhoneAndIPod = $iPhone
        }
        $iosApp.minimumSupportedOperatingSystem = @{       
            v8_0=$osVersion -lt 9.0;
            v9_0=$osVersion.ToString().StartsWith("9")
            v10_0=$osVersion.ToString().StartsWith("10")
            v11_0=$osVersion.ToString().StartsWith("11")
            v12_0=$osVersion.ToString().StartsWith("12")
            v13_0=$osVersion.ToString().StartsWith("13")
            v14_0=$osVersion.ToString().StartsWith("14")
            v15_0=$osVersion.ToString().StartsWith("15")
            v16_0=$osVersion.ToString().StartsWith("16")
        }
            
        # Checking if iosApp exists
        Write-Host "  Checking if iosApp exists"
        $searchValue = [System.Web.HttpUtility]::UrlEncode($iosApp.displayName)
        $uri = "/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$searchValue'"
        $actApp = (Get-MsGraphObject -Uri $uri).value
        if (-Not $actApp.id)
        {
            # Creating the iosApp
            Write-Host "    App does not exist, creating"
            $uri = "/beta/deviceAppManagement/mobileApps"
            $actApp = Post-MsGraph -Uri $uri -Body ($iosApp | ConvertTo-Json -Depth 50)
        }

        <#
        # Updating the iosApp
        Write-Host "    Updating the iosApp"
        $uri = "/beta/deviceAppManagement/mobileApps/$($actApp.id)"
        $actApp = Patch-MsGraph -Uri $uri -Body ($iosApp | ConvertTo-Json -Depth 50)
        #>

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
