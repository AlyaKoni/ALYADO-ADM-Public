#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2019, 2020

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
    05.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$UploadOnlyAppWithName = $null,
    [string]$ContinueAtAppWithName = $null
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Upload-IntuneWebApps-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$AppPrefix = ""
$DataRoot = Join-Path (Join-Path $AlyaData "intune") "WebApps"
if (-Not (Test-Path $DataRoot))
{
    $tmp = New-Item -Path $DataRoot -ItemType Directory -Force
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Upload-IntuneWebApps | Graph" -ForegroundColor $CommandInfo
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
$packages = Get-ChildItem -Path $DataRoot -Directory
$continue = $true
foreach($packageDir in $packages)
{
    if ($ContinueAtAppWithName -and $packageDir.Name -eq $ContinueAtAppWithName) { $continue = $false }
    if ($ContinueAtAppWithName -and $continue) { continue }
    if ($UploadOnlyAppWithName -and $packageDir.Name -ne $UploadOnlyAppWithName) { continue }
    if ($packageDir.Name -like "*unused*" -or $packageDir.Name -like "*donotuse*") { continue }

    Write-Host "Uploading web app $($packageDir.Name)" -ForegroundColor $CommandInfo
    $configPath = Join-Path $packageDir.FullName "config.json"

    # Reading and preparing app configuration
    Write-Host "  Reading and preparing app configuration"
    $appConfig = Get-Content -Path $configPath -Raw -Encoding UTF8
    $appConfig = $appConfig | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty isAssigned,dependentAppCount,supersedingAppCount,supersededAppCount,committedContentVersion,size,id,createdDateTime,lastModifiedDateTime,version,'@odata.context',uploadState,packageId,appIdentifier,publishingState,usedLicenseCount,totalLicenseCount,productKey,licenseType,packageIdentityName

    $appConfig.displayName = "$AppPrefix" + $packageDir.Name
    Write-Host "    displayName: $($appConfig.displayName)"
    $appConfig.description = "Installs the " + $packageDir.Name + " web link"

    $logo = Get-ChildItem -Path $packageDir.FullName -Filter "Logo.*"
    if ($logo)
    {
        $iconResponse = Invoke-WebRequest "$($logo.FullName)"
        $base64icon = [System.Convert]::ToBase64String($iconResponse.Content)
        $iconExt = ([System.IO.Path]::GetExtension($logo.FullName)).replace(".","")
        $iconType = "image/$iconExt"
        $appConfig.largeIcon = @{ "@odata.type" = "#microsoft.graph.mimeContent" }
        $appConfig.largeIcon.type = "$iconType"
        $appConfig.largeIcon.value = "$base64icon"
    }

    $appConfigJson = $appConfig | ConvertTo-Json -Depth 50
    $appConfigJson | Set-Content -Path $configPath -Encoding UTF8

    # Checking if app exists
    Write-Host "  Checking if app exists"
    $searchValue = [System.Web.HttpUtility]::UrlEncode($appConfig.displayName)
    $uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$searchValue'"
    $app = (Get-MsGraphObject -AccessToken $token -Uri $uri).value
    if (-Not $app.id)
    {
        # Creating app
        Write-Host "  Creating app"
        $uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps"
        $app = Post-MsGraph -AccessToken $token -Uri $uri -Body $appConfigJson
    }

    # Committing the app
    Write-Host "  Committing the app"
    $appConfig.PSObject.Properties.Remove('appUrl')
    $uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps/$($app.id)"
    $appP = Patch-MsGraph -AccessToken $token -Uri $uri -Body ($appConfig | ConvertTo-Json)
}

#Stopping Transscript
Stop-Transcript