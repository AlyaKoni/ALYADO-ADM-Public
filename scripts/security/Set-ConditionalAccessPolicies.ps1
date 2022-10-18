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
    27.02.2020 Konrad Brunner       Initial Version
    30.06.2022 Konrad Brunner       Change from REST to AzureAdPreview

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Set-ConditionalAccessPolicies-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "AzureAdPreview"
    
# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-ConditionalAccessPolicies | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking no mfa group
Write-Host "Checking MFA exclude group" -ForegroundColor $CommandInfo
if (-Not $AlyaMfaDisabledGroupName)
{
    Write-Host "Please specify the AlyaMfaDisabledGroupName variable in data\ConfigureEnv.ps1" -ForegroundColor $CommandError
    exit 1
}
else
{
    $NoMfaGroupName = $AlyaMfaDisabledGroupName
}
$GrpRslt = Get-AzureADMSGroup -SearchString $NoMfaGroupName
$ExcludeGroupId = $GrpRslt.Id
if (-Not $ExcludeGroupId)
{
    Write-Host "No MFA group not found. Creating the No MFA group $NoMfaGroupName" -ForegroundColor $CommandError
    exit 2
}

# Getting role assignments
Write-Host "Getting role assignments" -ForegroundColor $CommandInfo
$roleDefs = @{
    "Global Administrator"=$null
    "Privileged Role Administrator"=$null
    "Global Reader"=$null
    "Service Support Administrator"=$null
    "Application Administrator"=$null
    "Azure AD Joined Device Local Administrator"=$null
    "Azure DevOps Administrator"=$null
    "Billing Administrator"=$null
    "Compliance Administrator"=$null
    "Conditional Access Administrator"=$null
    "Dynamics 365 Administrator"=$null
    "Exchange Administrator"=$null
    "Intune Administrator"=$null
    "Windows 365 Administrator"=$null
    "Edge Administrator"=$null
    "Kaizala Administrator"=$null
    "License Administrator"=$null
    "Groups Administrator"=$null
    "Office Apps Administrator"=$null
    "Power BI Administrator"=$null
    "Power Platform Administrator"=$null
    "Printer Administrator"=$null
    "Privileged Authentication Administrator"=$null
    "Search Administrator"=$null
    "Security Administrator"=$null
    "Skype for Business Administrator"=$null
    "SharePoint Administrator"=$null
    "Teams Administrator"=$null
    "User Administrator"=$null
    "Application Developer"=$null
    "Attack Payload Author"=$null
    "Attack Simulation Administrator"=$null
    "Authentication Policy Administrator"=$null
    "Authentication Administrator"=$null
    "Azure Information Protection Administrator"=$null
}
$roleDefKeys = ($roleDefs.Clone()).Keys
$IncludeRoleIds = @()
$ExcludeRoleIds = @()
foreach($roleName in $roleDefKeys)
{
    $role = Get-AzureADMSRoleDefinition -Filter "DisplayName eq '$roleName'"
    $roleDefs[$roleName] = Get-AzureADMSRoleAssignment -Filter "RoleDefinitionId eq '$($role.Id)'"
    $IncludeRoleIds += $role.Id
}
$ExcludeRoleIds = $IncludeRoleIds
$syncrole = Get-AzureADMSRoleDefinition -Filter "DisplayName eq 'Directory Synchronization Accounts'"
$ExcludeRoleIds += $syncrole.Id

# Getting actual access policies
Write-Host "Getting actual access policies" -ForegroundColor $CommandInfo
$ActPolicies = Get-AzureADMSConditionalAccessPolicy

# Checking all admins access policy
Write-Host "Checking all admins access policy" -ForegroundColor $CommandInfo
$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeRoles = $IncludeRoleIds
$conditions.Users.ExcludeGroups = @("$ExcludeGroupId")
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "mfa"
$policyObj = $ActPolicies | where { $_.displayName -eq "MFA: Required for all admins" }
if (-Not $policyObj)
{
    Write-Warning "Conditional access policy not found. Creating the policy 'MFA: Required for all admins'"
    $policyObj = New-AzureADMSConditionalAccessPolicy -DisplayName "MFA: Required for all admins" -State "Enabled" -Conditions $conditions -GrantControls $controls
}
else
{
    Write-Host "Updating policy $PolicyName"
    $policyObj = Set-AzureADMSConditionalAccessPolicy -PolicyId $policyObj.id -State "Enabled" -Conditions $conditions -GrantControls $controls
}

# Checking external groups to exclude
Write-Host "Checking external groups to exclude" -ForegroundColor $CommandInfo
$ExcludeGroupIds = @()
foreach($groupName in $AlyaMfaDisabledForGroups)
{
    $GrpRslt = Get-AzureADMSGroup -SearchString $NoMfaGroupName
    $ExcludeGroupIds += $GrpRslt.Id
}
$ExcludeGroupIds += $ExcludeGroupId #NOMFAGroup

# Checking all users access policy
Write-Host "Checking all users access policy" -ForegroundColor $CommandInfo
$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
if ([string]::IsNullOrEmpty($AlyaMfaEnabledGroupName))
{
    $conditions.Users.IncludeUsers = "All"
}
else
{
    $IncludeGroupIds = @()
    $GrpRslt = Get-AzureADMSGroup -SearchString $AlyaMfaEnabledGroupName
    $IncludeGroupIds += $GrpRslt.Id
    $conditions.Users.IncludeGroups = $IncludeGroupIds
}
$conditions.Users.ExcludeRoles = $ExcludeRoleIds
$conditions.Users.ExcludeGroups = $ExcludeGroupIds
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "mfa"
$policyObj = $ActPolicies | where { $_.displayName -eq "MFA: Required for all users" }
if (-Not $policyObj)
{
    Write-Warning "Conditional access policy not found. Creating the policy 'MFA: Required for all users'"
    $policyObj = New-AzureADMSConditionalAccessPolicy -DisplayName "MFA: Required for all users" -State "Enabled" -Conditions $conditions -GrantControls $controls
}
else
{
    Write-Host "Updating policy 'MFA: Required for all users'"
    $policyObj = Set-AzureADMSConditionalAccessPolicy -PolicyId $policyObj.id -State "Enabled" -Conditions $conditions -GrantControls $controls
}

# Checking all admins session policy
Write-Host "Checking all admins session policy" -ForegroundColor $CommandInfo
$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeRoles = $IncludeRoleIds
$conditions.Users.ExcludeGroups = @("$ExcludeGroupId")
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSessionControls
$sessioncontrols = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSignInFrequency
$sessioncontrols.IsEnabled = $true
$sessioncontrols.Type = "days"
$sessioncontrols.Value = 1
$persistent = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessPersistentBrowser
$persistent.IsEnabled = $true
$persistent.Mode = [Microsoft.Open.MSGraph.Model.ConditionalAccessPersistentBrowser+ModeEnum]::Always
$controls.PersistentBrowser = $persistent
$controls.SignInFrequency = $sessioncontrols
$policyObj = $ActPolicies | where { $_.displayName -eq "SESSION: For all admins" }
if (-Not $policyObj)
{
    Write-Warning "Conditional access policy not found. Creating the policy 'SESSION: For all admins'"
    $policyObj = New-AzureADMSConditionalAccessPolicy -DisplayName "SESSION: For all admins" -State "Enabled" -Conditions $conditions -SessionControls $controls
}
else
{
    Write-Host "Updating policy 'SESSION: For all admins'"
    $policyObj = Set-AzureADMSConditionalAccessPolicy -PolicyId $policyObj.id -State "Enabled" -Conditions $conditions -SessionControls $controls
}

# Checking all users session policy
Write-Host "Checking all users session policy" -ForegroundColor $CommandInfo
$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeRoles = $ExcludeRoleIds
$conditions.Users.ExcludeGroups = $ExcludeGroupIds
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSessionControls
$sessioncontrols = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSignInFrequency
$sessioncontrols.IsEnabled = $true
$sessioncontrols.Type = "days"
$sessioncontrols.Value = 30
$persistent = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessPersistentBrowser
$persistent.IsEnabled = $true
$persistent.Mode = [Microsoft.Open.MSGraph.Model.ConditionalAccessPersistentBrowser+ModeEnum]::Always
$controls.PersistentBrowser = $persistent
$controls.SignInFrequency = $sessioncontrols
$policyObj = $ActPolicies | where { $_.displayName -eq "SESSION: For all users" }
if (-Not $policyObj)
{
    Write-Warning "Conditional access policy not found. Creating the policy 'SESSION: For all users'"
    $policyObj = New-AzureADMSConditionalAccessPolicy -DisplayName "SESSION: For all users" -State "Enabled" -Conditions $conditions -SessionControls $controls
}
else
{
    Write-Host "Updating policy 'SESSION: For all users'"
    $policyObj = Set-AzureADMSConditionalAccessPolicy -PolicyId $policyObj.id -State "Enabled" -Conditions $conditions -SessionControls $controls
}

# Disabling security defaults
Write-Host "Disabling security defaults" -ForegroundColor $CommandInfo
Write-Host "You have now to disable the security defaults. Pleas browse to"
Write-Host "  https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties"
Write-Host "hit 'Manage Security defaults' at the bottom of the page and disable security defaults!"
Write-Host "Please select 'My organization is using Conditional Access'."
start https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties
pause

#Stopping Transscript
Stop-Transcript
