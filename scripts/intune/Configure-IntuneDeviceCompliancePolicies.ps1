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
    06.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$PolicyFile = $null #defaults to $($AlyaData)\intune\deviceCompliancePolicies.json
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-IntuneDeviceCompliancePolicies-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
if (-Not $PolicyFile)
{
    $PolicyFile = "$($AlyaData)\intune\deviceCompliancePolicies.json"
}

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
Write-Host "Intune | Configure-IntuneDeviceCompliancePolicies | Graph" -ForegroundColor $CommandInfo
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
$policies = Get-Content -Path $PolicyFile -Raw -Encoding UTF8 | ConvertFrom-Json

#$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
#$actPolicy = Get-MsGraphCollection -AccessToken $token -Uri $uri
#$actPolicy | ConvertTo-Json -Depth 50 | Set-Content -Path ($PolicyFile+".txt") -Encoding UTF8

# Getting iOS configuration
Write-Host "Getting iOS configuration" -ForegroundColor $CommandInfo
$appleConfigured = $false
$uri = "https://graph.microsoft.com/beta/devicemanagement/applePushNotificationCertificate"
$appleConfiguration = Get-MsGraphObject -AccessToken $token -Uri $uri
$appleConfigured = $false
if ($appleConfiguration -and $appleConfiguration.certificateSerialNumber)
{
    $appleConfigured = $true
}
else
{
    $appleConfiguration = $appleConfiguration.value
    if ($appleConfiguration -and $appleConfiguration.certificateSerialNumber)
    {
        $appleConfigured = $true
    }
}

# Getting Android configuration
Write-Host "Getting Android configuration" -ForegroundColor $CommandInfo
$androidConfigured = $false
$uri = "https://graph.microsoft.com/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings"
$androidConfiguration = Get-MsGraphObject -AccessToken $token -Uri $uri
$androidConfigured = $false
if ($androidConfiguration -and $androidConfiguration.deviceOwnerManagementEnabled)
{
    $androidConfigured = $true
}
else
{
    $androidConfigured = $androidConfigured.Value
    if ($androidConfiguration -and $androidConfiguration.deviceOwnerManagementEnabled)
    {
        $androidConfigured = $true
    }
}

# Processing defined policies
foreach($policy in $policies)
{
    Write-Host "Configuring policy $($policy.displayName)" -ForegroundColor $CommandInfo

    # Checking if poliy is applicable
    Write-Host "  Checking if policy is applicable"
    if ($policy."@odata.type" -eq "#microsoft.graph.iosCompliancePolicy" -and -not $appleConfigured)
    {
        Write-Warning "iosCompliancePolicy is not applicable"
        continue
    }
    if ($policy."@odata.type" -eq "#microsoft.graph.androidCompliancePolicy" -and -not $androidConfigured)
    {
        Write-Warning "androidCompliancePolicy is not applicable"
        continue
    }

    # Checking if policy exists
    Write-Host "  Checking if policy exists"
    $searchValue = [System.Web.HttpUtility]::UrlEncode($policy.displayName)
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$filter=displayName eq '$searchValue'"
    $actPolicy = (Get-MsGraphObject -AccessToken $token -Uri $uri).value
    if (-Not $actPolicy.id)
    {
        # Creating the policy
        Write-Host "    Policy does not exist, creating"
        Add-Member -InputObject $policy -MemberType NoteProperty -Name "id" -Value "00000000-0000-0000-0000-000000000000"
        $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
        $actPolicy = Post-MsGraph -AccessToken $token -Uri $uri -Body ($policy | ConvertTo-Json -Depth 50)
    }

    # Updating the policy
    Write-Host "    Updating the policy"
    $policy.PSObject.Properties.Remove("localActions")
    $policy.PSObject.Properties.Remove("scheduledActionsForRule")
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($actPolicy.id)"
    $actPolicy = Patch-MsGraph -AccessToken $token -Uri $uri -Body ($policy | ConvertTo-Json -Depth 50)
}

#Stopping Transscript
Stop-Transcript
