#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2021

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
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
$token = Get-AdalAccessToken

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Upload-AndroidApps | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context and token
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}
$token = Get-AdalAccessToken

# Main
$appsAndroid = Get-Content -Path $appsAndroidFile -Raw -Encoding UTF8 | ConvertFrom-Json

# Processing defined appsAndroid
foreach($androidApp in $appsAndroid)
{
    if ($androidApp.displayName.EndsWith("_unused")) { continue }
    Write-Host "Configuring androidApp $($androidApp.displayName)" -ForegroundColor $CommandInfo
    
    # Getting store data
    $storeApp = Invoke-WebRequest -Uri $androidApp.informationUrl -Method Get
    $img = $storeApp.Images | where { $_.class -eq "T75of sHb2Xb" }
    if (-Not $img)
    {
        $img = $storeApp.Images | where { $_.alt -eq "Covergestaltung" }
    }
    if ($img -and $img.src)
    {
        $iconResponse = Invoke-WebRequest $img.src
        $base64icon = [System.Convert]::ToBase64String($iconResponse.Content)
        $iconType = $iconResponse.Headers["Content-Type"]
        $androidApp.largeIcon = @{
            "@odata.type" = "#microsoft.graph.mimeContent"
            type = $iconType
            value = $base64icon
        }
    }

    # Checking if androidApp exists
    Write-Host "  Checking if androidApp exists"
    $searchValue = [System.Web.HttpUtility]::UrlEncode($androidApp.displayName)
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$searchValue'"
    $actApp = (Get-MsGraphObject -AccessToken $token -Uri $uri).value
    if (-Not $actApp.id)
    {
        if ($androidApp.'@odata.type' -eq "#microsoft.graph.androidManagedStoreApp")
        {
            Write-Warning "Upload of managed store apps aren't supported"
            Write-Warning "Please create the app within the portal"
        }
        else
        {
            # Creating the androidApp
            Write-Host "    App does not exist, creating"
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
            $actApp = Post-MsGraph -AccessToken $token -Uri $uri -Body ($androidApp | ConvertTo-Json -Depth 50)
        }
    }

    <#
    # Updating the androidApp
    Write-Host "    Updating the androidApp"
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($actApp.id)"
    $actApp = Patch-MsGraph -AccessToken $token -Uri $uri -Body ($androidApp | ConvertTo-Json -Depth 50)
    #>
}

#Stopping Transscript
Stop-Transcript