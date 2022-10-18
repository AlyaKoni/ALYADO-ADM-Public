#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2021

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
    21.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-IntuneDeviceCategories-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$categoryNames = $AlyaDeviceCategories

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Configure-IntuneDeviceCategories | Graph" -ForegroundColor $CommandInfo
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
$scripts = Get-ChildItem -Path $ScriptDir -Filter "*.ps1"

# Processing categories
foreach($categoryName in $categoryNames)
{
    Write-Host "Configuring category $($categoryName)" -ForegroundColor $CommandInfo

    $body = @"
{
  "@odata.type": "#microsoft.graph.deviceCategory",
  "displayName": "$categoryName",
  "description": "Device category to manage devices of type $categoryName"
}
"@

    # Checking if category exists
    Write-Host "  Checking if category exists"
    $searchValue = [System.Web.HttpUtility]::UrlEncode($categoryName)
    $uri = "https://graph.microsoft.com/beta//deviceManagement/deviceCategories?`$filter=displayName eq '$searchValue'"
    $actCategory = (Get-MsGraphObject -AccessToken $token -Uri $uri).value
    if (-Not $actCategory.id)
    {
        # Creating the category
        Write-Host "    Category does not exist, creating"
        $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCategories"
        $actCategory = Post-MsGraph -AccessToken $token -Uri $uri -Body $body
    }

    # Updating the category
    Write-Host "    Updating the category"
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCategories/$($actCategory.id)"
    $actCategory = Patch-MsGraph -AccessToken $token -Uri $uri -Body $body
}

#Stopping Transscript
Stop-Transcript
