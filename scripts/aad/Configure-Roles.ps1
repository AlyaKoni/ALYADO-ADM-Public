﻿#Requires -Version 2.0

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
    28.09.2020 Konrad Brunner       Initial Version
    29.06.2022 Konrad Brunner       Splittet PIM and MSOL
    21.04.2023 Konrad Brunner       Switched to Graph, removed MSOL

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
# MIIvGwYJKoZIhvcNAQcCoIIvDDCCLwgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBIgeDqql42bF8u
# i7h2NXsW5/hYE1TDZvJTg6d2sq/qeaCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxghnmMIIZ4gIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIELUfT13
# udibCLxkriFd2dCPtzD81dO1iKkuvaqvkU3sMA0GCSqGSIb3DQEBAQUABIICAJx+
# I/u9HxrD+l31VKHtsX+OyGcoCiaZgtviWwHkxmHv1zEZwWo0mydPMzw1pMl8d1zJ
# un2NeoHdQ+Df+GYdJG119M1/v0IEZgEnC5eHmT2Y3L9IZvU3K88f5OC8NJqmhmUx
# y0aps1AjxSzzRKpF4774p/1gevLZDKz71MpEk3Imq3j/R9nyedZ9Vh7aGO4uVEhM
# f+NqxbXajTiMBmuetCmi1NTIRn8fgg0/hD4FTC204GiBbMgE/6Nn0yBw8Ci7YkVl
# zJV2Lc8/9/5sBTcW8r8aQ+kN5Sd7+1a91TL732DR5reGvi3q24kIPkZc4o8Lcymu
# MO+wRWBAgRw4/762LjeWbfi5D8YkN+XCWGsRQuChg/g2n19xRzXKJwjBg3OAzQ8N
# ACZ68BTUcyXTbWlObZrCRRNLoHPOQZoXuwgUYhaHZqIj5/H/nWQg4qHukH++c4vZ
# kNmfRsWjZKg082dVGEIu4llI4wElw/tPj3qHsdVqCGjC1GUKTmWxeWp1OGNzfSDX
# t2/G2JXOh6WpQS6j1qd+kHAeaFSnAnGoPUwReCEoJVCUBaiB1fffwikcg56ftkSy
# m+tvG43csAIuSyslSJRyOGgGoVnMnjeSVykn4ybyp70/cuVCybw9uL1YBo2l59+Z
# tFTrQXbAZFkbc9DbHaCdk+OPeszHe0n8PN0RmdXyoYIWzTCCFskGCisGAQQBgjcD
# AwExgha5MIIWtQYJKoZIhvcNAQcCoIIWpjCCFqICAQMxDTALBglghkgBZQMEAgEw
# gegGCyqGSIb3DQEJEAEEoIHYBIHVMIHSAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCBZvj2DA8eUwizg9tOqutHdGh0mAuf8w8rTIYGIMVOZlQIUSR44
# VdQbWGI1vyD4xolidJwxvl8YDzIwMjUwMjI4MTk1NjI3WjADAgEBoGGkXzBdMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwq
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2IC0gMjAyMzExoIISVDCC
# BmwwggRUoAMCAQICEAGb6t7ITWuP92w6ny4BJBYwDQYJKoZIhvcNAQELBQAwWzEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMT
# KEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjMx
# MTA3MTcxMzQwWhcNMzQxMjA5MTcxMzQwWjBdMQswCQYDVQQGEwJCRTEZMBcGA1UE
# CgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwqR2xvYmFsc2lnbiBUU0EgZm9y
# IENvZGVTaWduMSAtIFI2IC0gMjAyMzExMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A
# MIIBigKCAYEA6oQ3UGg8lYW1SFRxl/OEcsmdgNMI3Fm7v8tNkGlHieUs2PGoan5g
# N0lzm7iYsxTg74yTcCC19SvXZgV1P3qEUKlSD+DW52/UHDUu4C8pJKOOdyUn4Ljz
# fWR1DJpC5cad4tiHc4vvoI2XfhagxLJGz2DGzw+BUIDdT+nkRqI0pz4Yx2u0tvu+
# 2qlWfn+cXTY9YzQhS8jSoxMaPi9RaHX5f/xwhBFlMxKzRmUohKAzwJKd7bgfiWPQ
# HnssW7AE9L1yY86wMSEBAmpysiIs7+sqOxDV8Zr0JqIs/FMBBHkjaVHTXb5zhMub
# g4htINIgzoGraiJLeZBC5oJCrwPr1NDag3rDLUjxzUWRtxFB3RfvQPwSorLAWapU
# l05tw3rdhobUOzdHOOgDPDG/TDN7Q+zw0P9lpp+YPdLGulkibBBYEcUEzOiimLAd
# M9DzlR347XG0C0HVZHmivGAuw3rJ3nA3EhY+Ao9dOBGwBIlni6UtINu41vWc9Q+8
# iL8nLMP5IKLBAgMBAAGjggGoMIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFPlOq764+Fv/wscD9EHunPjWdH0/MFYG
# A1UdIARPME0wCAYGZ4EMAQQCMEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8E
# AjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3Au
# Z2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdo
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0
# ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6
# MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNo
# YTM4NGc0LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAlfRnz5OaQ5KDF3bWIFW8if/k
# X7LlFRq3lxFALgBBvsU/JKAbRwczBEy0tGL/xu7TDMI0oJRcN5jrRPhf+CcKAr4e
# 0SQdI8svHKsnerOpxS8M5OWQ8BUkHqMVGfjvg+hPu2ieI299PQ1xcGEyfEZu8o/R
# nOhDTfqD4f/E4D7+3lffBmvzagaBaKsMfCr3j0L/wHNp2xynFk8mGVhz7ZRe5Bqi
# EIIHMjvKnr/dOXXUvItUP35QlTSfkjkkUxiDUNRbL2a0e/5bKesexQX9oz37obDz
# K3kPsUusw6PZo9wsnCsjlvZ6KrutxVe2hLZjs2CYEezG1mZvIoMcilgD9I/snE7Q
# 3+7OYSHTtZVUSTshUT2hI4WSwlvyepSEmAqPJFYiigT6tJqJSDX4b+uBhhFTwJN7
# OrTUNMxi1jVhjqZQ+4h0HtcxNSEeEb+ro2RTjlTic2ak+2Zj4TfJxGv7KzOLEcN0
# kIGDyE+Gyt1Kl9t+kFAloWHshps2UgfLPmJV7DOm5bga+t0kLgz5MokxajWV/vbR
# /xeKriMJKyGuYu737jfnsMmzFe12mrf95/7haN5EwQp04ZXIV/sU6x5a35Z1xWUZ
# 9/TVjSGvY7br9OIXRp+31wduap0r/unScU7Svk9i00nWYF9A43aZIETYSlyzXRrZ
# 4qq/TVkAF55gZzpHEqAwggZZMIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqG
# SIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMw
# EQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYy
# MDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDwAuIwI/rgG+GadLOvdYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64H
# iifuV6PENe2zNMeswwzrgGZt0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//
# NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe
# 9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirU
# IceU/kKWO/ELsX9/RpgOhz16ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0Kvq
# WsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50
# xHAotIB7vSqbu4ThDqxvDbm19m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU
# 2EESwVX9bpHFu7FMCEue1EIGbxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE
# 6giunUlnEYuC5a1ahqdm/TMDAd6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3s
# qSbldwKsDlcMCdFhniaI/MiyTdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac
# 0zd0hNkdZqs0c48efXxeltY9GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCC
# ASUwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3Ay
# Lmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8v
# Y3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0g
# ADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBv
# c2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZM
# v9sbB3DG+wsJrQA6YDMfOcYWaxlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7A
# I4zGhf5LFST5GETsH8KkrNCyz+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG
# 0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0
# +X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3Wd
# rG9KyC5qucqIwxIwTrIIc59eodaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXa
# jR63Wy+ILj198fKRMAWcznt8oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpI
# iScseeI85Zse46qEgok+wEr1If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ
# 7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx
# 773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZq
# HcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV
# 5yBZtnjGpGqqIpswggWDMIIDa6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG
# 9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEG
# A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAw
# MDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9v
# dCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxT
# aWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns8
# 9w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0b
# WsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZ
# gQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ
# 3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2M
# sonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI5
# 5KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPF
# OJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4Py
# XhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYF
# AJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWV
# ZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlw
# g3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4IC
# AQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/A
# VJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6x
# CCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc
# 053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6q
# TFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvd
# OxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJd
# w+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ
# 4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4Z
# sRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3
# nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZ
# xRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8w
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb
# 6t7ITWuP92w6ny4BJBYwCwYJYIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZI
# hvcNAQELBQAwLwYJKoZIhvcNAQkEMSIEICv3V1B/fjjm/XzVbaJzc0PoxJpuwp6n
# dZvgyIos4SDBMIGwBgsqhkiG9w0BCRACLzGBoDCBnTCBmjCBlwQgOoh6lRteuSpe
# 4U9su3aCN6VF0BBb8EURveJfgqkW0egwczBfpF0wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwDQYJ
# KoZIhvcNAQELBQAEggGACkYEupWqbLKsi9EjoSV7e0G9g7JZhPUJqaRh70AiY3sX
# 5BuXwZvJeMdnpQaImFrMSX0EIiSZVx2vRdfbdhwKU4FGFARZIp1hBYLZcRy8MyY0
# Z3MDjw0ME7hQZ/8ECDrbaUUMjtNSMFGiWEE8IvLVH7s45XdAI0P+0kLuUyr3U115
# 6mK4n8vwPkAyesWDgOBZ5ZMlgQ5QTgWJyIqiRULV6mq3xwrrEseZ4LLusrxl8At9
# GQrk1d98j5b5tX3pEoWuhfVcElJMzBtM/aLV57ImVOpJYTHZzXStOoiYzD9n37F/
# Pn+GIqc4Er7n7Aa3Gz7VeteaRQaZbOd/9iCbayUvzNjkjS3oTXlaw7zM3vxAuFmb
# ClhYOBhsesfj5ueU2gl9/ZE4Rkx7YpYZ/YqsuTiM0dW1VFx8+czg0BvcALCAghi7
# rswjxiwXr3rOVkEJGzQtdIuAT9xLOJNj+jdKKYCHNVyb4lcHJYL0OM4HR+gWE+Kd
# Cdwki3WgDsd0vMSBGWFp
# SIG # End signature block
