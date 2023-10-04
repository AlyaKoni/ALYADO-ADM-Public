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
    25.08.2021 Konrad Brunner       Initial Version
    24.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
    [string]$appsAndroidFile = $null, #defaults to $($AlyaData)\intune\appsAndroid.json
    [string]$appStoreCountry = "ch"
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Upload-AndroidApps-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
if (-Not $appsAndroidFile)
{
    $appsAndroidFile = "$($AlyaData)\intune\appsAndroid.json"
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
Write-Host "Intune | Upload-AndroidApps | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$appsAndroid = Get-Content -Path $appsAndroidFile -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json

# Processing defined appsAndroid
$hadError = $false
foreach($androidApp in $appsAndroid)
{
    if ($androidApp.displayName.EndsWith("_unused")) { continue }
    Write-Host "Configuring androidApp $($androidApp.displayName)" -ForegroundColor $CommandInfo
    
    try {
        
        # Getting store data
        $storeApp = Invoke-WebRequestIndep -Uri $androidApp.informationUrl -Method Get
        $img = $storeApp.Images | Where-Object { $_.class -eq "T75of sHb2Xb" }
        if (-Not $img)
        {
            $img = $storeApp.Images | Where-Object { $_.alt -eq "Covergestaltung" }
        }
        if ($img -and $img.src)
        {
            $iconResponse = Invoke-WebRequestIndep $img.src
            $base64icon = [System.Convert]::ToBase64String($iconResponse.Content)
            $iconType = ($iconResponse.Headers["Content-Type"] | Out-String).Trim()
            $androidApp.largeIcon = @{
                "@odata.type" = "#Microsoft.Graph.mimeContent"
                type = $iconType
                value = $base64icon
            }
        }

        # Checking if androidApp exists
        Write-Host "  Checking if androidApp exists"
        $searchValue = [System.Web.HttpUtility]::UrlEncode($androidApp.displayName)
        $uri = "/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$searchValue'"
        $actApp = (Get-MsGraphObject -Uri $uri).value
        if (-Not $actApp.id)
        {
            if ($androidApp.'@odata.type' -eq "#Microsoft.Graph.androidManagedStoreApp")
            {
                Write-Warning "Upload of managed store apps aren't supported"
                Write-Warning "Please create the app within the portal"
            }
            else
            {
                # Creating the androidApp
                Write-Host "    App does not exist, creating"
                $uri = "/beta/deviceAppManagement/mobileApps"
                $actApp = Post-MsGraph -Uri $uri -Body ($androidApp | ConvertTo-Json -Depth 50)
            }
        }

        <#
        # Updating the androidApp
        Write-Host "    Updating the androidApp"
        $uri = "/beta/deviceAppManagement/mobileApps/$($actApp.id)"
        $actApp = Patch-MsGraph -Uri $uri -Body ($androidApp | ConvertTo-Json -Depth 50)
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
