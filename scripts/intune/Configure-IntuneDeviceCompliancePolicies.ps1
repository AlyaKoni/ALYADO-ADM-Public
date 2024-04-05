#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2024

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
    06.10.2020 Konrad Brunner       Initial Version
    24.04.2023 Konrad Brunner       Switched to Graph
    05.09.2023 Konrad Brunner       Added assignment

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
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"

# Logins
LoginTo-MgGraph -Scopes @(
    "DeviceManagementServiceConfig.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.Read.All"
)
#Disconnect-MgBetaGraph

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Configure-IntuneDeviceCompliancePolicies | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$policies = Get-Content -Path $PolicyFile -Raw -Encoding $AlyaUtf8Encoding | ConvertFrom-Json

# Getting iOS configuration
Write-Host "Getting iOS configuration" -ForegroundColor $CommandInfo
$appleConfigured = $false
$uri = "/beta/devicemanagement/applePushNotificationCertificate"
$appleConfiguration = Get-MsGraphObject -Uri $uri
$appleConfigured = $false
if ($appleConfiguration -and $appleConfiguration.certificateSerialNumber)
{
    Write-Host "  Apple token is configured"
    $appleConfigured = $true
}
else
{
    $appleConfiguration = $appleConfiguration.value
    if ($appleConfiguration -and $appleConfiguration.certificateSerialNumber)
    {
        Write-Host "  Apple token is configured"
        $appleConfigured = $true
    }
}

# Getting Android configuration
Write-Host "Getting Android configuration" -ForegroundColor $CommandInfo
$androidConfigured = $false
$uri = "/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings"
$androidConfiguration = Get-MsGraphObject -Uri $uri
$androidConfigured = $false
if ($androidConfiguration -and $androidConfiguration.deviceOwnerManagementEnabled)
{
    Write-Host "  Android token is configured"
    $androidConfigured = $true
}
else
{
    Write-Host "  Android token is configured"
    $androidConfigured = $androidConfigured.Value
    if ($androidConfiguration -and $androidConfiguration.deviceOwnerManagementEnabled)
    {
        $androidConfigured = $true
    }
}

# Processing defined policies
$hadError = $false
foreach($policy in $policies)
{
    Write-Host "Configuring policy '$($policy.displayName)'" -ForegroundColor $CommandInfo

    # Checking if poliy is applicable
    Write-Host "  Checking if policy is applicable"
    if ($policy."@odata.type" -eq "#Microsoft.Graph.iosCompliancePolicy" -and -not $appleConfigured)
    {
        Write-Warning "iosCompliancePolicy is not applicable"
        continue
    }
    if ($policy."@odata.type" -eq "#Microsoft.Graph.androidCompliancePolicy" -and -not $androidConfigured)
    {
        Write-Warning "androidCompliancePolicy is not applicable"
        continue
    }

    try {
        
        # Checking if policy exists
        Write-Host "  Checking if policy exists"
        $searchValue = [System.Web.HttpUtility]::UrlEncode($policy.displayName)
        $uri = "/beta/deviceManagement/deviceCompliancePolicies?`$filter=displayName eq '$searchValue'"
        $actPolicy = (Get-MsGraphObject -Uri $uri).value
        if (-Not $actPolicy.id)
        {
            # Creating the policy
            Write-Host "    Policy does not exist, creating"
            Add-Member -InputObject $policy -MemberType NoteProperty -Name "id" -Value "00000000-0000-0000-0000-000000000000"
            $uri = "/beta/deviceManagement/deviceCompliancePolicies"
            $actPolicy = Post-MsGraph -Uri $uri -Body ($policy | ConvertTo-Json -Depth 50)
        }

        # Updating the policy
        Write-Host "    Updating the policy"
        $policy.PSObject.Properties.Remove("localActions")
        $policy.PSObject.Properties.Remove("scheduledActionsForRule")
        $uri = "/beta/deviceManagement/deviceCompliancePolicies/$($actPolicy.id)"
        $actPolicy = Patch-MsGraph -Uri $uri -Body ($policy | ConvertTo-Json -Depth 50)
    }
    catch {
        $hadError = $true
    }

}
if ($hadError)
{
    Write-Host "There was an error. Please see above." -ForegroundColor $CommandError
}

# Assigning defined policies
foreach($policy in $policies)
{
    Write-Host "Assigning policy '$($policy.displayName)'" -ForegroundColor $CommandInfo

    try {
        
        # Checking if policy exists
        Write-Host "  Checking if policy exists"
        $searchValue = [System.Web.HttpUtility]::UrlEncode($policy.displayName)
        $uri = "/beta/deviceManagement/deviceCompliancePolicies?`$filter=displayName eq '$searchValue'"
        $actPolicy = (Get-MsGraphObject -Uri $uri).value
        if ($actPolicy.id)
        {

            $tGroups = @()
            if ($policy.displayName.StartsWith("WIN "))
            {
                $sGroup = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaCompanyNameShortM365)SG-DEV-WINMDM'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-WINMDM not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }
            if ($policy.displayName.StartsWith("WIN365"))
            {
                $sGroup = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaCompanyNameShortM365)SG-DEV-WIN365MDM'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-WIN365MDM not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }
            if ($policy.displayName.StartsWith("WIN10"))
            {
                $sGroup = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaCompanyNameShortM365)SG-DEV-WINMDM10'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-WINMDM10 not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }
            if ($policy.displayName.StartsWith("WIN11"))
            {
                $sGroup = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaCompanyNameShortM365)SG-DEV-WINMDM11'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-WINMDM11 not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
                $sGroup = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaCompanyNameShortM365)SG-DEV-WIN365MDM11'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-WIN365MDM11 not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }
            if ($policy.displayName.StartsWith("AND") -and $policy.displayName -like "*Personal*")
            {
                $sGroup = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaCompanyNameShortM365)SG-DEV-ANDROIDMDMPERSONAL'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-ANDROIDMDMPERSONAL not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }
            if ($policy.displayName.StartsWith("AND") -and $policy.displayName -like "*Owned*")
            {
                $sGroup = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaCompanyNameShortM365)SG-DEV-ANDROIDMDMOWNED'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-ANDROIDMDMOWNED not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }
            if ($policy.displayName.StartsWith("IOS"))
            {
                $sGroup = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaCompanyNameShortM365)SG-DEV-IOSMDM'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-IOSMDM not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }
            if ($policy.displayName.StartsWith("MAC"))
            {
                $sGroup = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaCompanyNameShortM365)SG-DEV-MACMDM'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-MACMDM not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }

            if ($tGroups.Count -gt 0) { 
                $uri = "/beta/deviceManagement/deviceCompliancePolicies/$($actPolicy.id)/assignments"
                $asses = (Get-MsGraphObject -Uri $uri).value
                $Targets = @()
                foreach($tGroup in $tGroups) {
                    $GroupAssignment = New-Object -TypeName PSObject -Property @{
                        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                        "groupId" = $tGroup.Id
                    }
                    $Target = New-Object -TypeName PSObject -Property @{
                        "target" = $GroupAssignment
                    }
                    $Targets += $Target
                }
                foreach($ass in $asses) {
                    if ($ass.target.groupId -notin $tGroups.Id)
                    {
                        $Target = New-Object -TypeName PSObject -Property @{
                            "target" = $ass.target
                        }
                        $Targets += $Target
                    }
                }
                $Assignment = New-Object -TypeName PSObject -Property @{
                    "assignments" = $Targets
                }
                $body = ConvertTo-Json -InputObject $Assignment -Depth 10
                $uri = "/beta/deviceManagement/deviceCompliancePolicies/$($actPolicy.id)/assign"
                Post-MsGraph -Uri $uri -Body $body
            }
        } else {
            Write-Host "Not found!" -ForegroundColor $CommandError
        }
    }
    catch {
        Write-Error $_.Exception -ErrorAction Continue
        $hadError = $true
    }

}

#Stopping Transscript
Stop-Transcript
