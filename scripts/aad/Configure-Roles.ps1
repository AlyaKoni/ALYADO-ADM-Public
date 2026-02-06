#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    28.09.2020 Konrad Brunner       Initial Version
    29.06.2022 Konrad Brunner       Splittet PIM and MSOL
    21.04.2023 Konrad Brunner       Switched to Graph, removed MSOL
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Configures Azure Active Directory roles and Privileged Identity Management (PIM) settings based on an Excel configuration file.

.DESCRIPTION
The Configure-Roles.ps1 script automates the management of Azure Active Directory (AAD) roles, including the assignment and removal of permanent and eligible role members. It verifies the presence of required modules, reads configuration data from an Excel file, connects to Microsoft Graph, and applies role configurations according to the provided parameters. Optionally, it updates PIM role settings for predefined alerting roles and ensures the AAD environment is consistent with the desired state defined in the input file.

.PARAMETER inputFile
Specifies the path to the Excel file containing role assignments. If not provided, it defaults to "$AlyaData\aad\Rollen.xlsx".

.PARAMETER alertingRoles
Defines a list of Azure AD roles that require alerts and specific PIM configuration updates. Defaults include common administrator roles such as Global Administrator and Security Administrator.

.PARAMETER configurePIM
Determines whether Privileged Identity Management (PIM) settings are configured. Defaults to $true.

.PARAMETER updatePIMRoleSettings
Indicates whether the script should update PIM role settings for the defined alerting roles. Defaults to $true.

.PARAMETER askBeforeRoleRemoval
Specifies whether the user is prompted before removing existing role assignments. Defaults to $true.

.INPUTS
None. The script reads input from the specified Excel configuration file.

.OUTPUTS
Generates log files detailing the configuration progress and writes informational messages to the console.

.EXAMPLE
PS> .\Configure-Roles.ps1 -inputFile "C:\Config\Rollen.xlsx" -configurePIM $true -updatePIMRoleSettings $false

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [string]$inputFile = $null, #Defaults to "$AlyaData\aad\Rollen.xlsx"
    [string[]]$alertingRoles = @("Global Administrator","Privileged Role Administrator","SharePoint Administrator","Teams Administrator","Security Administrator","Intune Administrator","Exchange Administrator","Conditional Access Administrator","Application Administrator"),
    [bool]$configurePIM = $true,
    [bool]$updatePIMRoleSettings = $true,
    [bool]$askBeforeRoleRemoval = $true
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Configure-Roles-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $inputFile)
{
    $inputFile = "$AlyaData\aad\Rollen.xlsx"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ImportExcel"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.DeviceManagement.Enrollment"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Applications"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.Governance"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All","RoleManagement.Read.All","RoleManagement.ReadWrite.Directory"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Configure-Roles | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Reading input file
Write-Host "Reading input file from '$inputFile'" -ForegroundColor $CommandInfo
if (-Not (Test-Path $inputFile))
{
    throw "Input file not found!"
}
$roleDefs = Import-Excel $inputFile -ErrorAction Stop

# Configured roles
Write-Host "Configured roles:" -ForegroundColor $CommandInfo
$lastRole = $null
$allRoles = @{}
$eligibleRoles = @{}
$permanentRoles = @{}
foreach ($roleDef in $roleDefs)
{
    if ([string]::IsNullOrEmpty($roleDef.Role) -and [string]::IsNullOrEmpty($roleDef.Permanent) -and [string]::IsNullOrEmpty($roleDef.PermanentPIM) -and [string]::IsNullOrEmpty($roleDef.Eligible))
    {
        continue
    }

    $roleName = $roleDef.Role
    if ([string]::IsNullOrEmpty($roleName))
    {
        $roleName = $lastRole
    }
    $lastRole = $roleName

    if (-Not [string]::IsNullOrEmpty($roleName) -and $roleName -ne "Role")
    {
        $allRoles.$roleName = $false
    }

    $principal = $null
    if (-Not [string]::IsNullOrEmpty($roleDef.Eligible))
    {
        if ($roleDef.Eligible -like "##*") {
            continue
        }
        try { $principal = Get-MgBetaUser -UserId $roleDef.Eligible } catch {}
        if (-Not $principal)
        {
            $principal = Get-MgBetaGroup -Filter "DisplayName eq '$($roleDef.Eligible)'"
        }
        if (-Not $principal)
        {
            throw "Not able to find user or group $($roleDef.Eligible)"
        }
        if ($eligibleRoles.ContainsKey($roleName))
        {
            $eligibleRoles.$roleName += $principal
        }
        else
        {
            $eligibleRoles.$roleName = @($principal)
        }
    }

    if (-Not [string]::IsNullOrEmpty($roleDef.Permanent))
    {
        if ($roleDef.Permanent -like "##*") {
            $allRoles.$roleName = $true
            continue
        }
        try { $principal = Get-MgBetaUser -UserId $roleDef.Permanent } catch {}
        if (-Not $principal)
        {
            $id = $null
            $name = $roleDef.Permanent
            if ($roleDef.Permanent.IndexOf(":") -gt -1)
            {
                $id = $roleDef.Permanent.Split(":")[0]
                $name = $roleDef.Permanent.Split(":")[1]
            }
            if ($id)
            {
                try { $principal = Get-MgBetaGroup -GroupId $id } catch {}
                if (-Not $principal)
                {
                    try { $principal = Get-MgBetaServicePrincipal -Filter "AppId eq '$($id)'" } catch {}
                }
                if (-Not $principal)
                {
                    try { $principal = Get-MgBetaServicePrincipal -ServicePrincipalId $id } catch {}
                }
            }
            if (-Not $principal)
            {
                try { $principal = Get-MgBetaGroup -Filter "DisplayName eq '$($name)'" } catch {}
                if (-Not $principal)
                {
                    try { $principal = Get-MgBetaServicePrincipal -Filter "DisplayName eq '$($name)'" } catch {}
                }
            }
        }
        if (-Not $principal)
        {
            throw "Not able to find user or group $($roleDef.Permanent)"
        }
        if ($permanentRoles.ContainsKey($roleName))
        {
            $permanentRoles.$roleName += $principal
        }
        else
        {
            $permanentRoles.$roleName = @($principal)
        }
    }
}
foreach($key in $allRoles.Keys.Trim()) { Write-Host "  $key" }

# Checking  license
if ($configurePIM)
{
    Write-Host "Checking  license" -ForegroundColor $CommandInfo
    try
    {
        $actMembs = Get-MgBetaRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty Principal
    }
    catch
    {
        if ($_.Exception.ToString() -like "*AadPremiumLicenseRequired*" -or $_.Exception.ToString() -like "*AAD Premium 2*")
        {
            Write-Host "No  license available! Can't configure PIM roles."
            $configurePIM = $false
        }
        else
        {
            throw $_.Exception
        }
    }
}

# Checking built in roles
Write-Host "Checking built in roles" -ForegroundColor $CommandInfo
$allBuiltInRoles = Get-MgBetaRoleManagementDirectoryRoleDefinition -All
$missFound = $false
foreach($role in $allBuiltinRoles)
{
    $roleName = $role.DisplayName
    if ($roleName -eq "Company Administrator") { $roleName = "Global Administrator" }
    if (-Not $allRoles.Keys.Trim().Contains($roleName))
    {
        Write-Warning "The role '$($roleName)' is not present in the excel sheet. Please update it!"
        $missFound = $true
    }
}
if (-Not $missFound)
{
    Write-Host "No missing role found in the excel sheet"
}
$missFound = $false

$errorFound = $false
foreach($roleName in $allRoles.Keys.Trim())
{
    if ($allBuiltinRoles.DisplayName -notcontains $roleName)
    {
        Write-Warning "The role '$($roleName)' present in the excel sheet is not available any more. Please update it!"
        $errorFound = $true
    }
}
if ($errorFound)
{
    throw "Unused role found. Please fix!"
}

if ($configurePIM)
{
  # Checking role settings
  $assigments = Get-MgBetaPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'Directory'"
  $policies = Get-MgBetaPolicyRoleManagementPolicy -Filter "scopeId eq '/' and scopeType eq 'Directory'"
  if ($updatePIMRoleSettings)
  {
      Write-Host "Checking role settings" -ForegroundColor $CommandInfo

      foreach($alertingRole in $alertingRoles)
      {
          Write-Host "  on $alertingRole"
          $rol = $allBuiltInRoles | Where-Object { $_.DisplayName -eq $alertingRole }
          $ass = $assigments | Where-Object { $_.RoleDefinitionId -eq $rol.Id }
          $pol = $policies | Where-Object { $_.Id -eq $ass.PolicyId }
          $rules = Get-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id
          
          Write-Host "    Approval_EndUser_Assignment"
          $rul = $rules | Where-Object { $_.Id -eq "Approval_EndUser_Assignment" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyApprovalRule",
    "setting": {
        "isApprovalRequired": false,
        "isApprovalRequiredForExtension": false,
        "isRequestorJustificationRequired": true,
        "approvalMode": "SingleStage",
        "approvalStages": [
          {
              "approvalStageTimeOutInDays": 1,
              "isApproverJustificationRequired": true,
              "escalationTimeInMinutes": 0,
              "isEscalationEnabled": false,
              "primaryApprovers": [],
              "escalationApprovers": []
          }
        ]
    }
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          Write-Host "    AuthenticationContext_EndUser_Assignment"
          $rul = $rules | Where-Object { $_.Id -eq "AuthenticationContext_EndUser_Assignment" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyAuthenticationContextRule",
    "isEnabled": false,
    "claimValue": ""
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          $rul = $rules | Where-Object { $_.Id -eq "Expiration_Admin_Assignment" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyExpirationRule",
    "isExpirationRequired": false,
    "maximumDuration": "P180D"
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          Write-Host "    Expiration_Admin_Eligibility"
          $rul = $rules | Where-Object { $_.Id -eq "Expiration_Admin_Eligibility" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyExpirationRule",
    "isExpirationRequired": false,
    "maximumDuration": "P365D"
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          Write-Host "    Expiration_EndUser_Assignment"
          $rul = $rules | Where-Object { $_.Id -eq "Expiration_EndUser_Assignment" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyExpirationRule",
    "isExpirationRequired": true,
    "maximumDuration": "PT8H"
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)


          Write-Host "    Enablement_Admin_Eligibility"
          $rul = $rules | Where-Object { $_.Id -eq "Enablement_Admin_Eligibility" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyEnablementRule",
    "enabledRules": []
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          Write-Host "    Enablement_Admin_Assignment"
          $rul = $rules | Where-Object { $_.Id -eq "Enablement_Admin_Assignment" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyEnablementRule",
    "enabledRules": [
        "Justification"
    ]
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          Write-Host "    Enablement_EndUser_Assignment"
          $rul = $rules | Where-Object { $_.Id -eq "Enablement_EndUser_Assignment" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyEnablementRule",
    "enabledRules": [
      "MultiFactorAuthentication",
        "Justification"
    ]
}
"@
          if ($alertingRole -eq "Privileged Role Administrator")
          {
              $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyEnablementRule",
    "enabledRules": [
        "Justification"
    ]
}
"@
          }
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          Write-Host "    Notification_Admin_Admin_Eligibility"
          $rul = $rules | Where-Object { $_.Id -eq "Notification_Admin_Admin_Eligibility" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyNotificationRule",
    "notificationType": "Email",
    "recipientType": "Admin",
    "notificationLevel": "All",
    "isDefaultRecipientsEnabled": true,
    "notificationRecipients": [
        "$AlyaSecurityEmail"
    ]
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          Write-Host "    Notification_Admin_Admin_Assignment"
          $rul = $rules | Where-Object { $_.Id -eq "Notification_Admin_Admin_Assignment" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyNotificationRule",
    "notificationType": "Email",
    "recipientType": "Admin",
    "notificationLevel": "All",
    "isDefaultRecipientsEnabled": true,
    "notificationRecipients": [
        "$AlyaSecurityEmail"
    ]
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          Write-Host "    Notification_Admin_EndUser_Assignment"
          $rul = $rules | Where-Object { $_.Id -eq "Notification_Admin_EndUser_Assignment" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyNotificationRule",
    "notificationType": "Email",
    "recipientType": "Admin",
    "notificationLevel": "All",
    "isDefaultRecipientsEnabled": true,
    "notificationRecipients": [
        "$AlyaSecurityEmail"
    ]
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          Write-Host "    Notification_Approver_Admin_Eligibility"
          $rul = $rules | Where-Object { $_.Id -eq "Notification_Approver_Admin_Eligibility" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyNotificationRule",
    "notificationType": "Email",
    "recipientType": "Approver",
    "notificationLevel": "All",
    "isDefaultRecipientsEnabled": true,
    "notificationRecipients": [
        "$AlyaSecurityEmail"
    ]
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          Write-Host "    Notification_Approver_Admin_Assignment"
          $rul = $rules | Where-Object { $_.Id -eq "Notification_Approver_Admin_Assignment" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyNotificationRule",
    "notificationType": "Email",
    "recipientType": "Approver",
    "notificationLevel": "All",
    "isDefaultRecipientsEnabled": true,
    "notificationRecipients": [
        "$AlyaSecurityEmail"
    ]
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          Write-Host "    Notification_Approver_EndUser_Assignment"
          $rul = $rules | Where-Object { $_.Id -eq "Notification_Approver_EndUser_Assignment" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyNotificationRule",
    "notificationType": "Email",
    "recipientType": "Approver",
    "notificationLevel": "All",
    "isDefaultRecipientsEnabled": true,
    "notificationRecipients": []
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          Write-Host "    Notification_Requestor_Admin_Eligibility"
          $rul = $rules | Where-Object { $_.Id -eq "Notification_Requestor_Admin_Eligibility" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyNotificationRule",
    "notificationType": "Email",
    "recipientType": "Requestor",
    "notificationLevel": "All",
    "isDefaultRecipientsEnabled": true,
    "notificationRecipients": [
        "$AlyaSecurityEmail"
    ]
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          Write-Host "    Notification_Requestor_Admin_Assignment"
          $rul = $rules | Where-Object { $_.Id -eq "Notification_Requestor_Admin_Assignment" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyNotificationRule",
    "notificationType": "Email",
    "recipientType": "Requestor",
    "notificationLevel": "All",
    "isDefaultRecipientsEnabled": true,
    "notificationRecipients": [
        "$AlyaSecurityEmail"
    ]
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

          Write-Host "    Notification_Requestor_EndUser_Assignment"
          $rul = $rules | Where-Object { $_.Id -eq "Notification_Requestor_EndUser_Assignment" }
          #$rul.AdditionalProperties | ConvertTo-Json -Depth 99
          $json = @"
{
    "@odata.type": "#Microsoft.Graph.unifiedRoleManagementPolicyNotificationRule",
    "notificationType": "Email",
    "recipientType": "Requestor",
    "notificationLevel": "All",
    "isDefaultRecipientsEnabled": true,
    "notificationRecipients": [
        "$AlyaSecurityEmail"
    ]
}
"@
          Update-MgBetaPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $pol.Id -UnifiedRoleManagementPolicyRuleId $rul.Id -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99)

      }
  }
}

# Adding new role members
Write-Host "Adding new role members" -ForegroundColor $CommandInfo
foreach($roleName in $allRoles.Keys.Trim())
{
    Write-Host "Role '$($roleName)'"
    if ($allRoles[$roleName])
    {
        #Don't touch
    }
    else
    {
        Write-Host "  Configuring permanent role"
        $newUsers = $permanentRoles[$roleName]
        $role = $allBuiltInRoles | Where-Object { $_.DisplayName -eq $roleName }
        $actMembs = Get-MgBetaRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'" -All -ExpandProperty Principal

        #Adding new members
        $newUsers | Foreach-Object {
            $newMemb = $_
            if ($newMemb)
            {
                $actMemb = $actMembs | Where-Object { $_.PrincipalId -eq $newMemb.Id}
                if (-Not $actMemb)
                {
                    $otype = $newMemb.GetType().Name.Replace("MicrosoftGraph", "")
                    $oname = $newMemb.UserPrincipalName
                    if ([string]::IsNullOrEmpty($oname)) { $oname = $newMemb.DisplayName }
                    Write-Host "    adding $otype $oname $($newMemb.Id)" -ForegroundColor $CommandWarning
                    $actMemb = New-MgBetaRoleManagementDirectoryRoleAssignment -RoleDefinitionId $role.Id -PrincipalId $newMemb.Id -DirectoryScopeId "/"
                }
            }
        }

        if ($configurePIM)
        {
            # Configuring eligible role
            Write-Host "  Configuring eligible role"
            $newUsers = $eligibleRoles[$roleName]
            $actMembs = Get-MgBetaRoleManagementDirectoryRoleEligibilitySchedule -Filter "roleDefinitionId eq '$($role.Id)'" -All -ExpandProperty Principal

            #Adding new members
            $newUsers | Foreach-Object {
                $newMemb = $_
                if ($newMemb)
                {
                    $actMemb = $actMembs | Where-Object { $_.PrincipalId -eq $newMemb.Id}
                    if (-Not $actMemb)
                    {
                        Write-Host "    adding user $($newMemb.UserPrincipalName)" -ForegroundColor $CommandWarning
                        $json = @"
{
    "principalId": "$($newMemb.Id)",
    "roleDefinitionId": "$($role.Id)",
    "justification": "Add eligible assignment from Alya PowerShell",
    "directoryScopeId": "/",
    "action": "adminAssign",
    "scheduleInfo": {
        "startDateTime": "$((Get-Date).Date.ToString("o"))",
        "expiration": {}
    }
}
"@
                      New-MgBetaRoleManagementDirectoryRoleEligibilityScheduleRequest -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99) | Out-Null
                    }
                }
            }
        }
    }
}

# Removing role members
Write-Host "Removing old role members" -ForegroundColor $CommandInfo
foreach($roleName in $allRoles.Keys.Trim())
{
    Write-Host "Role '$($roleName)'"
    if ($allRoles[$roleName])
    {
        #Don't touch
    }
    else
    {
        # Configuring permanent roles
        Write-Host "  Configuring permanent role"
        $newUsers = $permanentRoles[$roleName]

        $role = $allBuiltInRoles | Where-Object { $_.DisplayName -eq $roleName }
        $actMembs = Get-MgBetaRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'" -All -ExpandProperty Principal
        # TODO "roleDefinitionId eq '$($role.Id)' and principalOrganizationId eq '$AlyaTenantId'" not working
        $actMembs = $actMembs | Where-Object { $_.principalOrganizationId -eq $AlyaTenantId }
        if ($configurePIM)
        {
          $actEliMembs = Get-MgBetaRoleManagementDirectoryRoleAssignmentSchedule -Filter "roleDefinitionId eq '$($role.Id)'" -All -ExpandProperty "*"
        }

        #Removing inactivated members
        $actMembs | Foreach-Object {
            $actMemb = $_
            if ($actMemb)
            {
                if ($configurePIM)
                {
                  if (($actEliMembs | Where-Object { $_.PrincipalId -eq $actMemb.PrincipalId }).AssignmentType -eq "Activated") {
                    Write-Host "  '$($actMemb.PrincipalId)' has active assignment"
                    # TODO remove active assignment
                    continue
                  }
                }
                if ((-Not $newUsers) -or ($newUsers.Id -notcontains $actMemb.PrincipalId))
                {
                    $principal = $null
                    try {
                      $principal = Get-MgBetaUser -UserId $actMemb.PrincipalId
                      Write-Host "    removing user $($principal.UserPrincipalName)" -ForegroundColor $CommandError
                    }
                    catch {
                      try {
                        $principal = Get-MgBetaGroup -GroupId $actMemb.PrincipalId
                        Write-Host "    removing group $($principal.DisplayName)" -ForegroundColor $CommandError
                      }
                      catch {
                        try {
                          $principal = Get-MgBetaServicePrincipal -ServicePrincipalId $actMemb.PrincipalId
                          Write-Host "    removing service principal $($principal.DisplayName)" -ForegroundColor $CommandError
                        }
                        catch {
                          Write-Error "Not able to find principal '$($actMemb.PrincipalId)'"
                        }
                      }
                    }

                    if ((Get-MgContext).Account -eq $principal.UserPrincipalName)
                    {
                        Write-Host "    you can't remove yourself!!!" -ForegroundColor $CommandError
                    }
                    else
                    {
                        if ($askBeforeRoleRemoval) {
                          $title = "Role Assigments"
                          $question = "Are you sure you want to remove the assignment?"
                          $choices = "&Yes", "&No"
                          $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
                        }
                        else {
                          $decision = 0
                        }
                        if ($decision -eq 0) {
                            Remove-MgBetaRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $actMemb.Id
                        }
                    }
                }
            }
        }

        if ($configurePIM)
        {
            # Configuring eligible role
            Write-Host "  Configuring eligible role"
            $newUsers = $eligibleRoles[$roleName]
            $actMembs = Get-MgBetaRoleManagementDirectoryRoleEligibilitySchedule -Filter "roleDefinitionId eq '$($role.Id)'" -All -ExpandProperty Principal

            #Adding new members
            $actMembs | Foreach-Object {
                $actMemb = $_
                if ($actMemb)
                {
                    if ((-Not $newUsers) -or ($newUsers.Id -notcontains $actMemb.PrincipalId))
                    {
                        $principal = $null
                        try {
                          $principal = Get-MgBetaUser -UserId $actMemb.PrincipalId
                          Write-Host "    removing user $($principal.UserPrincipalName)" -ForegroundColor $CommandError
                        }
                        catch {
                          try {
                            $principal = Get-MgBetaGroup -GroupId $actMemb.PrincipalId
                            Write-Host "    removing group $($principal.DisplayName)" -ForegroundColor $CommandError
                          }
                          catch {
                            try {
                              $principal = Get-MgBetaServicePrincipal -ServicePrincipalId $actMemb.PrincipalId
                              Write-Host "    removing service principal $($principal.DisplayName)" -ForegroundColor $CommandError
                            }
                            catch {
                              Write-Error "Not able to find principal '$($actMemb.PrincipalId)'"
                            }
                          }
                        }

                        if ($askBeforeRoleRemoval) {
                          $title = "Role Assigments"
                          $question = "Are you sure you want to remove the eligible assignment?"
                          $choices = "&Yes", "&No"
                          $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
                        }
                        else {
                          $decision = 0
                        }
                        if ($decision -eq 0) {
                            $json = @"
{
    "principalId": "$($actMemb.PrincipalId)",
    "roleDefinitionId": "$($role.Id)",
    "justification": "Remove eligible assignment from Alya PowerShell",
    "directoryScopeId": "/",
    "action": "adminRemove"
}
"@
                            New-MgBetaRoleManagementDirectoryRoleEligibilityScheduleRequest -AdditionalProperties ($json | ConvertFrom-Json -AsHashtable -Depth 99) | Out-Null
                        }
                    }
                }
            }
        }
    }
}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA8L8B5cpRd2iEj
# b5cyhfpSME/xc34D3C/88XWmiYB/W6CCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g604YfM/tV
# 5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD4ED6gVYD
# U/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S/gJXhZrh
# 0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp8nKmrVa4
# 6Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqtf2phU7+y
# R2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJQWTEE/bP
# 0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKXvYkPbEdx
# +QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4yMYgcMKb
# 9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmYF8T4xO2k
# 6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2mMIVpqWC
# Z1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7spNY6rQb
# 3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd2jANBgkq
# hkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy/fAHsVv1
# RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW2H3Bh6zN
# XULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0MP6pBPKO
# L6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/pFL9zlcc
# tWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcexU0bcV0hL
# Q4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf6AMOGaM5
# 6A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzECp9LnR+34
# c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9mUF5qE6Yw
# QqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+KuaJRsz+cn
# ZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/JlN6m6GM1j
# EhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutofdgNBzMUx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJYOo890Hkie5RZX
# vjfKZObeHUs77EdrrrXyf+XKXoYDMA0GCSqGSIb3DQEBAQUABIICAIEipcF47gA4
# s/G3Ox5+yEHxBvrtQAWnwzZymKgPB6vCF2u74fY4vrMKasDMWYVnl9RspZOdFtlZ
# gZmW/iOP8pUVKDLRy0hoibuANMBLk8Xq/6x7vfsXxETHVhoSDVI9iL6QXUjr65KR
# AlknY1dPrNahe7thZ0Z2QKg+dOK319HDVB652WtZqCzS6I2eGmPrh+gW6LV2S0ex
# kg/w+v6QB9okEfwBl9uYrhkQJ9/OZebqIvmLyaRHasooGSVCQBuP0+SP7QpbcQ2t
# TFemw+dwoRZgegBUxqKU7SV1KiO30kC93Jr3VWFPmMK1TzTot8VQnzdQgvm8sK6P
# A8poEKHassq2KEj9/W1fScB2S+BzZCpfGMsP712EUYpFs3jA4lPipXasuSTsL0/K
# OhQyIrV8CfzsdEEK2oBnsG4lCbpGvZjQy5V3IHJRS82BpVPn5m/vtvbJzdvP2kYJ
# GvyNqgVyDevXchPtH6+V9L1Cn3lFf4vHOtR7y/ufTk3A3ouMLlIr2+EoZyydRYLs
# SKV+6Qh1dexXCccYz+eSzLHAZgPTDYLgDh9jYQQmjDuE6rbbV7AzxVBH1CtKgbl6
# RSk98hpciDqikG61OOs6koKO19KYWq4egLZpD5BGgVL4HIHs7az05DxWzaowU5pr
# Ijm2Ws7Fs+66d8p2rhGZAFpxrQfZw5PooYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCBnBZ3I4qyn+LW9CvfAsgnY/lTsz+jKIkKNi2GTNRs7UgIURLpnaElL8oCb
# 46anglda/2KMyBkYDzIwMjYwMjA2MTEzODQyWjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# ILCK2osnj1THx8THK8GuPIEIZba83U0sjQQ8Z4fOrqweMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAMWvh2jy5StoL
# MLj0d4xw9YIcppKVTjpHPMn08dm2Kw0V07fCeTA6ES66nmffQToH/ic+gMGnxJWw
# EDW21nqRcOQl1Pp8A49MfhJgM876yXYXu9BWSIECrVznH7uOG3GY2cnmbJOj8CQC
# gzDnHSc39OIzpvAsST5swxvo9+4t8fgWdumtOMqya6cfeYQIKcg39bn9yt1ac8h2
# tg5dvVPZmYIBeFt3zES14jKC+M77kPc72x45v8xMZ/2FVyGi9m2Calh9QNGqCXvT
# YjjjJLybgQk6eUs41GxYmK8vqPdZ9lOG+xMybXH+TIVMjGx1cq7IxhJNdUkaMjdg
# wlVKE90HVkURWZopY+TRzAFMO9gN7NVW+b61XTVsT4+NAgY6qYKvrjbySMFNlSrK
# gEnZff1VprN+NBLfLYDVU0SYbj0qUhGwlvzBwVm+vM4Xx5Vh9l9FcAZMKifIU/bG
# 8k6iFcO9knWUqhyg1wx4V40P+00p/vgc6OleEgfDWL1uaE9zyj6Q
# SIG # End signature block
