#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2022-2023

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
    26.04.2022 Konrad Brunner       Initial Version
    24.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
    [bool]$doUserDataExport = $false
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Export-IntuneConfiguration-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$IsOneDriveDir = $true
$DataRoot = Join-Path (Join-Path $AlyaData "intune") "Reports"
if (-Not (Test-Path $DataRoot))
{
    $tmp = New-Item -Path $DataRoot -ItemType Directory -Force
}
Write-Host "Exporting Intune report to $DataRoot"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "Directory.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementApps.Read.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Export-IntuneConfiguration | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#GET /deviceAppManagement/mobileApps/{mobileAppId}/deviceStatuses
#GET /deviceAppManagement/mobileApps/{mobileAppId}/userStatuses/{userAppInstallStatusId}/deviceStatuses

#devices
$uri = "/beta/deviceManagement/managedDevices"
$managedDevices = Get-MsGraphObject -Uri $uri
while ($managedDevices.'@odata.nextLink')
{
    $nmanagedDevices = Get-MsGraphObject -Uri $managedDevices.'@odata.nextLink'
    $managedDevices.value += $nmanagedDevices.value
    $managedDevices.'@odata.nextLink' = $nmanagedDevices.'@odata.nextLink'
}
$devices = $managedDevices.value

#intuneApplications
$uri = "/beta/deviceAppManagement/mobileApps"
$intuneApplications = Get-MsGraphObject -Uri $uri
$applications = $intuneApplications.value
$report = New-Object System.Collections.ArrayList
foreach($application in $applications)
{
    #if ($application.displayName -ne "Google Recorder") {continue}
    Write-Host "App: $($application.displayName)"
    $uri = "/beta/deviceAppManagement/mobileApps/$($application.id)"
    $applicationRes = Get-MsGraphObject -Uri $uri
    $uri = "/beta/deviceAppManagement/mobileApps/$($application.id)/deviceStatuses"
    $deviceStatuses = Get-MsGraphObject -Uri $uri
    foreach($deviceStatus in $deviceStatuses.value)
    {
        if ($deviceStatus.installState -eq "failed")
        {
            Write-Host "  Dev: $($deviceStatus.deviceName)"
            $dev = $devices | Where-Object { $_.id -eq $deviceStatus.deviceId }
            <#$null = $report.Add(@{
                errType = "DeviceFailure"
                appId = $applicationRes.id
                appDisplayName = $applicationRes.displayName
                appPublisher = $applicationRes.publisher
                appPackageId = $applicationRes.packageId
                appAppStoreUrl = $applicationRes.appStoreUrl
                devDeviceName = $deviceStatus.deviceName
                devInstallState = $deviceStatus.installState
                devInstallStateDetail = $deviceStatus.installStateDetail
                devDeviceId = $deviceStatus.deviceId
                devErrorCode = $deviceStatus.errorCode
                devUserPrincipalName = $deviceStatus.userPrincipalName
                devManagedDeviceOwnerType = $dev.managedDeviceOwnerType
                devOperatingSystem = $dev.operatingSystem
                devDeviceType = $dev.deviceType
                devOsVersion = $dev.osVersion
                devModel = $dev.model
                devManufacturer = $dev.manufacturer
                devSubscriberCarrier = $dev.subscriberCarrier
                devManagedDeviceName = $dev.managedDeviceName
            })#>
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -name 'errType' -value "DeviceFailure"
            $obj | Add-Member -MemberType NoteProperty -name 'appId' -value $applicationRes.id
            $obj | Add-Member -MemberType NoteProperty -name 'appDisplayName' -value $applicationRes.displayName
            $obj | Add-Member -MemberType NoteProperty -name 'appPublisher' -value $applicationRes.publisher
            $obj | Add-Member -MemberType NoteProperty -name 'appPackageId' -value $applicationRes.packageId
            $obj | Add-Member -MemberType NoteProperty -name 'appAppStoreUrl' -value $applicationRes.appStoreUrl
            $obj | Add-Member -MemberType NoteProperty -name 'devDeviceName' -value $deviceStatus.deviceName
            $obj | Add-Member -MemberType NoteProperty -name 'devInstallState' -value $deviceStatus.installState
            $obj | Add-Member -MemberType NoteProperty -name 'devInstallStateDetail' -value $deviceStatus.installStateDetail
            $obj | Add-Member -MemberType NoteProperty -name 'devDeviceId' -value $deviceStatus.deviceId
            $obj | Add-Member -MemberType NoteProperty -name 'devErrorCode' -value $deviceStatus.errorCode
            $obj | Add-Member -MemberType NoteProperty -name 'devUserPrincipalName' -value $deviceStatus.userPrincipalName
            $obj | Add-Member -MemberType NoteProperty -name 'devManagedDeviceOwnerType' -value $managedDeviceOwnerType
            $obj | Add-Member -MemberType NoteProperty -name 'devOperatingSystem' -value $dev.operatingSystem
            $obj | Add-Member -MemberType NoteProperty -name 'devDeviceType' -value $dev.deviceType
            $obj | Add-Member -MemberType NoteProperty -name 'devOsVersion' -value $dev.osVersion
            $obj | Add-Member -MemberType NoteProperty -name 'devModel' -value $dev.model
            $obj | Add-Member -MemberType NoteProperty -name 'devManufacturer' -value $dev.manufacturer
            $obj | Add-Member -MemberType NoteProperty -name 'devSubscriberCarrier' -value $dev.subscriberCarrier
            $obj | Add-Member -MemberType NoteProperty -name 'devManagedDeviceName' -value $dev.managedDeviceName
            $null = $report.Add($obj)
        }
    }
    <#$uri = "/beta/deviceAppManagement/mobileApps/$($application.id)/userStatuses"
    $userStatuses = Get-MsGraphObject -Uri $uri
    foreach($userStatus in $userStatuses.value)
    {
        if ($userStatus.failedDeviceCount -gt 0)
        {
            Write-Host "  Usr: $($userStatus.userPrincipalName)"
            $statusId = $userStatus.id.Substring(35,36)
            #Write-Host "  Usr: $($statusId)"
            #$uri = "/beta/deviceAppManagement/mobileApps/$($application.id)/userStatuses/$($statusId)/deviceStatuses"
            #$userDeviceStatuses = Get-MsGraphObject -Uri $uri
            #$userDeviceStatuses | Format-List
        }
    }#>
}

$devices | Export-CSV "$DataRoot\deviceList.csv" -notype
$report | Export-CSV "$DataRoot\appFailures.csv" -notype

#Stopping Transscript
Stop-Transcript
