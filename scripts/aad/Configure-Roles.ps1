#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2022

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
    28.09.2020 Konrad Brunner       Initial Version
    29.06.2022 Konrad Brunner       Splittet PIM and MSOL

#>

[CmdletBinding()]
Param(
    [string]$inputFile = $null, #Defaults to "$AlyaData\aad\Rollen.xlsx"
    [bool]$configurePIM = $true,
    [bool]$updateRoleSettings = $false
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
Uninstall-ModuleIfInstalled "AzureAD"
Install-ModuleIfNotInstalled "ImportExcel"
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "AzureADPreview"
Install-ModuleIfNotInstalled "MSOnline"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
Connect-AzureAD
#Connect-AzureAD #TODO: Only works this way. Permission by token does not work
Connect-MsolService
#LoginTo-MSOL #TODO: Only works this way. Permission by token does not work

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
Write-Host "Configured roles:"
$lastRole = $null
$allRoles = @{}
$eligibleRoles = @{}
$permanentMSOLRoles = @{}
$permanentPIMRoles = @{}
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
        try { $principal = Get-AzureADUser -objectId $roleDef.Eligible -ErrorAction SilentlyContinue } catch {}
        if (-Not $principal)
        {
            $principal = Get-AzureADGroup -SearchString $roleDef.Eligible -ErrorAction SilentlyContinue
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

    if (-Not [string]::IsNullOrEmpty($roleDef.PermanentPIM))
    {
        if ($roleDef.PermanentPIM -like "##*") {
            $allRoles.$roleName = $true
            continue
        }
        try { $principal = Get-AzureADUser -objectId $roleDef.PermanentPIM -ErrorAction SilentlyContinue } catch {}
        if (-Not $principal)
        {
            $principal = Get-AzureADGroup -SearchString $roleDef.PermanentPIM -ErrorAction SilentlyContinue
        }
        if (-Not $principal)
        {
            throw "Not able to find user or group $($roleDef.PermanentPIM)"
        }
        if ($permanentPIMRoles.ContainsKey($roleName))
        {
            $permanentPIMRoles.$roleName += $principal
        }
        else
        {
            $permanentPIMRoles.$roleName = @($principal)
        }
    }

    if (-Not [string]::IsNullOrEmpty($roleDef.PermanentMSOL))
    {
        if ($roleDef.PermanentMSOL -like "##*") {
            $allRoles.$roleName = $true
            continue
        }
        try { $principal = Get-AzureADUser -objectId $roleDef.PermanentMSOL -ErrorAction SilentlyContinue } catch {}
        if (-Not $principal)
        {
            $principal = Get-AzureADGroup -SearchString $roleDef.PermanentMSOL -ErrorAction SilentlyContinue
        }
        if (-Not $principal)
        {
            throw "Not able to find user or group $($roleDef.PermanentMSOL)"
        }
        if ($permanentMSOLRoles.ContainsKey($roleName))
        {
            $permanentMSOLRoles.$roleName += $principal
        }
        else
        {
            $permanentMSOLRoles.$roleName = @($principal)
        }
    }
}
foreach($key in $allRoles.Keys) { Write-Host "  $key" }

# Checking built in roles
Write-Host "Checking built in roles:" -ForegroundColor $CommandInfo
$allBuiltInPIMRoles = Get-AzureADMSRoleDefinition
$allBuiltinRoles = Get-MsolRole
$missFound = $false
foreach($role in $allBuiltinRoles)
{
    $roleName = $role.Name
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
foreach($role in $allBuiltInPIMRoles)
{
    if (-Not $allRoles.ContainsKey($role.DisplayName))
    {
        Write-Warning "The role '$($role.DisplayName)' is not present in the excel sheet. Please update it!"
        $missFound = $true
    }
}
if (-Not $missFound)
{
    Write-Host "No missing role found in the excel sheet"
}
$missFound = $false
foreach($role in $allRoles.Keys)
{
    if (-Not ($allBuiltInPIMRoles | where { $_.DisplayName -eq $role}))
    {
        Write-Warning "The role '$($role)' was not found as built in role. Please check it!"
        $missFound = $true
    }
}
if (-Not $missFound)
{
    Write-Host "No wrong role found in the excel sheet"
}

# Checking role settings
if ($updateRoleSettings)
{
    Write-Host "Checking role settings" -ForegroundColor $CommandInfo
    $allSettings = Get-AzureADMSPrivilegedRoleSetting -ProviderId "aadRoles" -Filter "ResourceId eq '$($AlyaTenantId)'"
    foreach($roleName in $allRoles.Keys)
    {
        if ($allRoles[$roleName])
        {
            #Don't touch
        }
        else
        {
            Write-Host "Role '$($roleName)'"
            $role = Get-AzureADMSRoleDefinition -Filter "DisplayName eq 'Global Administrator'"
            $role = Get-AzureADMSRoleDefinition -Filter "DisplayName eq '$roleName'"
            $roleSetting = $allSettings | where { $_.RoleDefinitionId -eq $role.Id}
            if ($roleSetting)
            {
                $settingUserMemberExpirationRule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedRuleSetting
                $settingUserMemberExpirationRule.RuleIdentifier = "ExpirationRule"
                $settingUserMemberExpirationRule.Setting = "{`"permanentAssignment`":true,`"maximumGrantPeriodInMinutes`":540}"
                $settingUserMemberJustificationRule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedRuleSetting
                $settingUserMemberJustificationRule.RuleIdentifier = "JustificationRule"
                $settingUserMemberJustificationRule.Setting = "{`"required`":true}"
                $settingUserMemberMfaRule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedRuleSetting
                $settingUserMemberMfaRule.RuleIdentifier = "MfaRule"
                $settingUserMemberMfaRule.Setting = "{`"mfaRequired`":true}"
                $userMemberSettings = @($settingUserMemberExpirationRule, $settingUserMemberJustificationRule, $settingUserMemberMfaRule)

                $settingAdminMemberExpirationRule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedRuleSetting
                $settingAdminMemberExpirationRule.RuleIdentifier = "ExpirationRule"
                if ($roleName -eq "Global Administrator")
                {
                    $settingAdminMemberExpirationRule.Setting = "{`"permanentAssignment`":false,`"maximumGrantPeriodInMinutes`":21600}"
                }
                else
                {
                    $settingAdminMemberExpirationRule.Setting = "{`"maximumGrantPeriod`":`"180.00:00:00`",`"maximumGrantPeriodInMinutes`":259200,`"permanentAssignment`":true}"
                }
                $settingAdminMemberJustificationRule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedRuleSetting
                $settingAdminMemberJustificationRule.RuleIdentifier = "JustificationRule"
                $settingAdminMemberJustificationRule.Setting = "{`"required`":true}"
                $settingAdminMemberMfaRule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedRuleSetting
                $settingAdminMemberMfaRule.RuleIdentifier = "MfaRule"
                $settingAdminMemberMfaRule.Setting = "{`"mfaRequired`":true}"
                $adminMemberSettings = @($settingAdminMemberExpirationRule, $settingAdminMemberJustificationRule, $settingAdminMemberMfaRule)
            
                $settingAdminEligibleMfaRule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedRuleSetting
                $settingAdminEligibleMfaRule.RuleIdentifier = "MfaRule"
                $settingAdminEligibleMfaRule.Setting = "{`"mfaRequired`":true}"
                $adminEligibleSettings = @($settingAdminEligibleMfaRule)

                Set-AzureADMSPrivilegedRoleSetting -ProviderId "aadRoles" -ResourceId $AlyaTenantId `
                    -Id $roleSetting.Id `
                    -RoleDefinitionId $role.Id `
                    -UserMemberSettings $userMemberSettings `
                    -AdminMemberSettings $adminMemberSettings `
                    -AdminEligibleSettings $adminEligibleSettings
            
            }
            else
            {
                Write-Warning "Role '$($roleName)' does not has a role setting"
            }
        }
    }
}

# Adding new role members
foreach($roleName in $allRoles.Keys)
{
    Write-Host "Role '$($roleName)'" -ForegroundColor $CommandInfo
    if ($allRoles[$roleName])
    {
        #Don't touch
    }
    else
    {
        # Configuring permanent roles
        Write-Host "Configuring permanent MSOL role"
        $newUsers = $permanentMSOLRoles[$roleName]

        $msolRoleName = $roleName
        if ($msolRoleName -eq "Global Administrator") { $msolRoleName = "Company Administrator" }
        $role = Get-MsolRole -RoleName $msolRoleName
        $actMembs = Get-MsolRoleMember -RoleObjectId $role.ObjectId

        #Adding new members
        $newUsers | foreach {
            $newMemb = $_
            if ($newMemb)
            {
                $found = $false
                $actMembs | foreach {
                    $actMemb = $_
                    if ($newMemb -eq $actMemb.EmailAddress -or $newMemb -eq $actMemb.ObjectId)
                    {
                        $found = $true
                    }
                }
                if (-Not $found)
                {
                    Write-Host "    adding user $($newMemb)" -ForegroundColor $CommandWarning
                    Add-MsolRoleMember -RoleObjectId $role.ObjectId -RoleMemberEmailAddress $newMemb
                }
            }
        }

        Write-Host "Configuring permanent PIM role"
        $newUsers = $permanentPIMRoles[$roleName]

        $role = Get-AzureADMSRoleDefinition -Filter "DisplayName eq '$roleName'"
        $actMembs = Get-AzureADMSRoleAssignment -Filter "RoleDefinitionId eq '$($role.Id)'"

        #Adding new members
        $newUsers | foreach {
            $newMemb = $_
            if ($newMemb)
            {
                $found = $false
                $actMembs | foreach {
                    $actMemb = $_
                    if ($newMemb.ObjectId -eq $actMemb.PrincipalId)
                    {
                        $found = $true
                    }
                }
                if (-Not $found)
                {
                    Write-Host "    adding user $($newMemb.UserPrincipalName)" -ForegroundColor $CommandWarning
                    New-AzureADMSRoleAssignment -RoleDefinitionId $role.Id -PrincipalId $newMemb.ObjectId -DirectoryScopeId '/'
                }
            }
        }

        if ($configurePIM)
        {
            # Configuring eligible role settings
            Write-Host "Configuring eligible role settings"

            #checking PIM license
            try
            {
                $role = Get-AzureADMSPrivilegedRoleDefinition -ProviderId "aadRoles" -ResourceId $AlyaTenantId -Filter "DisplayName eq '$($roleName)'"
            }
            catch
            {
                if ($_.Exception.ToString() -like "*AadPremiumLicenseRequired*")
                {
                    Write-Host "No PIM license available! Can't configure PIM roles."
                    $configurePIM = $false
                }
                else
                {
                    throw $_.Exception
                }
            }

            if ($configurePIM)
            {
                $newUsers = $eligibleRoles[$roleName]

                #$settings = Get-AzureADMSPrivilegedRoleSetting -ProviderId "aadRoles" -Filter "ResourceId eq '$AlyaTenantId' and RoleDefinitionId eq '$($role.Id)'"
                Write-Host "  Please update notification settings for role '$($roleName)'"
                Write-Host "    Additional recipients '$($AlyaSecurityEmail)'"
                Write-Host "    MS does not allow this per PowerShell :-("

                # Configuring eligible roles
                Write-Host "Configuring eligible role"
                $actMembs = Get-AzureADMSPrivilegedRoleAssignment -ProviderId "aadRoles" -ResourceId $AlyaTenantId -Filter "RoleDefinitionId eq '$($role.Id)' and AssignmentState eq 'Eligible'"

                #Removing inactivated members
                $actMembs | foreach {
                    $actMemb = $_
                    if ($actMemb)
                    {
                        if ((-Not $newUsers) -or ($newUsers.ObjectId -notcontains $actMemb.SubjectId))
                        {
                            $principal = Get-AzureADUser -objectId $actMemb.SubjectId
                            Write-Host "    removing user $($principal.UserPrincipalName)" -ForegroundColor $CommandError
                            $title    = 'Role Assigments'
                            $question = 'Are you sure you want to remove the assignment?'
                            $choices  = '&Yes', '&No'
                            $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
                            if ($decision -eq 0) {
                                Write-Host "  Please remove assigment by hand"
                                Write-Host "    MS does not allow this per PowerShell :-("
                                #$req = Get-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId "aadRoles" -Filter "ResourceId eq '$AlyaTenantId' and RoleDefinitionId eq '$($role.Id)' and AssignmentState eq 'Eligible' and SubjectId eq '$($actMemb.SubjectId)'"
                                #Close-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId "aadRoles" -Id $req.Id
                                #Set-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId "AzureResources" -Id $req.ResourceId -Reason "{'RequestorReason':'Revoked by Alya role script','AdminReason':'Revoked by Alya role script'}" -Decision "AdminDenied"
                            }
                        }
                    }
                }

                #Adding new members
                $newUsers | foreach {
                    $newMemb = $_
                    if ($newMemb)
                    {
                        $found = $false
                        $actMembs | foreach {
                            $actMemb = $_
                            if ($newMemb.ObjectId -eq $actMemb.SubjectId)
                            {
                                $found = $true
                            }
                        }
                        if (-Not $found)
                        {
                            Write-Host "    adding user $($newMemb.UserPrincipalName)" -ForegroundColor $CommandWarning
                            $schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
                            $schedule.Type = "Once"
                            $schedule.StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                            $schedule.endDateTime = $null
                            Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId "aadRoles" -ResourceId $AlyaTenantId `
                                -RoleDefinitionId $role.Id -SubjectId $newMemb.ObjectId -Type "adminAdd" -AssignmentState "Eligible" `
                                -Schedule $schedule -Reason "Assigned by Alya role script"
                        }
                    }
                }

            }
        }

    }
}

# Removing role members
foreach($roleName in $allRoles.Keys)
{
    Write-Host "Role '$($roleName)'" -ForegroundColor $CommandInfo
    if ($allRoles[$roleName])
    {
        #Don't touch
    }
    else
    {
        # Configuring permanent roles
        Write-Host "Configuring permanent role"
        $newUsers = $permanentPIMRoles[$roleName]

        $role = Get-AzureADMSRoleDefinition -Filter "DisplayName eq '$roleName'"
        $actMembs = Get-AzureADMSRoleAssignment -Filter "RoleDefinitionId eq '$($role.Id)'"

        #Removing inactivated members
        $actMembs | foreach {
            $actMemb = $_
            if ($actMemb)
            {
                if ((-Not $newUsers) -or ($newUsers.ObjectId -notcontains $actMemb.PrincipalId))
                {
                    $principal = Get-AzureADUser -objectId $actMemb.PrincipalId
                    Write-Host "    Warning: this script does not check actual PIM assignments!" #TODO
                    Write-Host "    removing user $($principal.UserPrincipalName)" -ForegroundColor $CommandError

                    if ((Get-AzContext).Account.Id -eq $principal.UserPrincipalName)
                    {
                        Write-Host "    you can't remove yourself!!!" -ForegroundColor $CommandError
                    }
                    else
                    {
                        $title    = 'Role Assigments'
                        $question = 'Are you sure you want to remove the assignment?'
                        $choices  = '&Yes', '&No'
                        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
                        if ($decision -eq 0) {
                            Remove-AzureADMSRoleAssignment -Id $actMemb.Id
                        }
                    }
                }
            }
        }
    }
}

#Stopping Transscript
Stop-Transcript
