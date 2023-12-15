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
Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement.Enrolment"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Applications"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.Governance"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

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
foreach($key in $allRoles.Keys) { Write-Host "  $key" }

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
    if (-Not $allRoles.ContainsKey($roleName))
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
foreach($roleName in $allRoles.Keys)
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
foreach($roleName in $allRoles.Keys)
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
foreach($roleName in $allRoles.Keys)
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
