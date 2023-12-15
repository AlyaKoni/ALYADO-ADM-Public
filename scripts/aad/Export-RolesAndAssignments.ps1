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
    02.02.2021 Konrad Brunner       Initial Version
    27.11.2023 Konrad Brunner       Switch to Graph

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Export-RolesAndAssignments-$($AlyaTimeString).log" | Out-Null

# Constants
if (-Not (Test-Path "$AlyaData\aad"))
{
    New-Item -Path "$AlyaData\aad" -ItemType Directory -Force
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Export-RolesAndAssignments | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Getting defined AD roles
Write-Host "Getting defined AD roles" -ForegroundColor $CommandInfo
$roleMappings = @()
$adRoleDefs = Get-MgBetaDirectoryRoleTemplate -All
$adRoleDefs | Format-Table DisplayName, Description
$defRoles = Get-MgBetaDirectoryRole -All | Sort-Object -Property DisplayName
foreach($roleDef in $adRoleDefs)
{
    $role = $defRoles | Where-Object { $_.DisplayName -eq $roleDef.DisplayName }
    if ($role)
    {
        Write-Host "Role: $($role.DisplayName)"
        $members = Get-MgBetaDirectoryRoleMember -DirectoryRoleId $role.Id
        foreach($member in $members)
        {
            Write-Host "  Member: $($member.AdditionalProperties.userPrincipalName)"
            $extProp = $member.ExtensionProperty
            $objUser = New-Object psObject
            $objUser | Add-Member RoleName $role.DisplayName
            $objUser | Add-Member UserName $member.AdditionalProperties.displayName
            if (-Not [string]::IsNullOrEmpty($member.AdditionalProperties.userPrincipalName)) {
                $objUser | Add-Member UserPrincipalName $member.AdditionalProperties.userPrincipalName
                $objUser | Add-Member UserType $member.AdditionalProperties.userType
            } else {
                $objUser | Add-Member UserPrincipalName $member.AdditionalProperties.appId
                $objUser | Add-Member UserType $member.AdditionalProperties.servicePrincipalType
            }
            $objUser | Add-Member EMail $member.AdditionalProperties.mail
            $objUser | Add-Member AccountEnabled $member.AdditionalProperties.accountEnabled
            $objUser | Add-Member GivenName $member.AdditionalProperties.givenName
            $objUser | Add-Member Surname $member.AdditionalProperties.surname
            $objUser | Add-Member UsageLocation $member.AdditionalProperties.usageLocation
            $objUser | Add-Member PreferredLanguage $member.AdditionalProperties.preferredLanguage
            $objUser | Add-Member CreationDate $extProp.AdditionalProperties.createdDateTime
            $objUser | Add-Member SecurityIdentifier  $extProp.AdditionalProperties.securityIdentifier
            $roleMappings += $objUser
            if ($role.DisplayName -eq "Directory Readers")
            {
                return
            }
        }
    }
}
$roleMappings | Export-CSV -Path "$AlyaData\aad\RoleMappings.csv" -NoTypeInformation -Confirm:$false -Force

# Getting all Subscriptions
Write-Host "`n`nGetting all Subscriptions" -ForegroundColor $CommandInfo
$subs = Get-AzSubscription -TenantId $AlyaTenantId
$subs | Format-Table Name, Id

# Getting defined RBAC roles
Write-Host "Getting defined RBAC roles" -ForegroundColor $CommandInfo
$iamRoleDefs = Get-AzRoleDefinition | Sort-Object -Property Name
foreach($sub in $subs)
{
    $rds = Get-AzRoleDefinition -Scope "/subscriptions/$($sub.Id)" -Custom -ErrorAction SilentlyContinue
    foreach($rd in $rds)
    {
        $exRd = $iamRoleDefs | Where-Object { $_.Id -eq $rd.Id}
        if (-Not $exRd)
        {
            $iamRoleDefs += $rd
        }
    }
}
$iamRoleDefs | Format-Table IsCustom, Name, Description

# Reporting custom roles
Write-Host "Reporting custom roles" -ForegroundColor $CommandInfo
$iamRoleDefsCusts = $iamRoleDefs | Where-Object { $_.IsCustom -eq $true }
foreach($iamRoleDefsCust in $iamRoleDefsCusts)
{
    Write-Host "Custom role $($iamRoleDefsCust.Name):" -ForegroundColor $CommandSuccess
    Write-Host "Actions" -ForegroundColor $MenuColor
    $iamRoleDefsCust.Actions
    Write-Host "DataActions" -ForegroundColor $MenuColor
    $iamRoleDefsCust.DataActions
    Write-Host "NotActions" -ForegroundColor $MenuColor
    $iamRoleDefsCust.NotActions
    Write-Host "NotDataActions" -ForegroundColor $MenuColor
    $iamRoleDefsCust.NotDataActions
}

# Getting all management groups
Write-Host "Getting all management groups" -ForegroundColor $CommandInfo
$roleAssignments = @()
$Global:manGrps = @()
$manGrpsExp = Get-AzManagementGroup -Expand -Recurse -GroupName $AlyaTenantId -ErrorAction SilentlyContinue
function TraverseManGrps($grp)
{
    $Global:manGrps += $grp
    foreach($expGrp in $grp.Children)
    {
        if ($expGrp.Type -eq "/providers/Microsoft.Management/managementGroups")
        {
            TraverseManGrps -grp $expGrp
        }
    }
}
if ($manGrpsExp)
{
    TraverseManGrps -grp $manGrpsExp
}
$Global:manGrps | Format-Table Id, Name, Description

# Getting all role assigments from all subscriptions
Write-Host "Getting all role assigments from all subscriptions" -ForegroundColor $CommandInfo
foreach($sub in $subs)
{
    Write-Host "Subscription $($sub.Name)" -ForegroundColor $CommandInfo
    Select-AzSubscription -SubscriptionObject $sub
    $assignments = Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)"
    foreach($assignment in $assignments)
    {
        $assignment
        $subName = ""
        $mgName = ""
        $rcrsGrpName = ""
        $rcrsName = ""
        if ($assignment.Scope -eq "/")
        {
            $mgName = "Root"
        }
        if ($assignment.Scope.StartsWith("/providers/Microsoft.Management/managementGroups/","CurrentCultureIgnoreCase"))
        {
            $mgName = $assignment.Scope.Substring("/providers/Microsoft.Management/managementGroups/".Length).Trim("/")
            if ($Global:manGrps.Count -gt 0)
            {
                $mgName = ($Global:manGrps | Where-Object { $_.Name -eq $mgName}).DisplayName
            }
        }
        if ($assignment.Scope.StartsWith("/subscriptions/"+$sub.Id,"CurrentCultureIgnoreCase"))
        {
            $res = $assignment.Scope.Substring(("/subscriptions/"+$sub.Id).Length).Trim("/")
            if ([string]::IsNullOrEmpty($res))
            {
                $subName = $sub.Name
            }
            else
            {
                if ($res.Split("/",[System.StringSplitOptions]::RemoveEmptyEntries).Count -gt 2)
                {
                    $rcrsName = $res
                }
                else
                {
                    $rcrsGrpName = $res.Split("/",[System.StringSplitOptions]::RemoveEmptyEntries)[1]
                }
            }
        }

        $objUser = New-Object psObject
        $objUser | Add-Member ManagementGroup $mgName
        $objUser | Add-Member Subscription $subName
        $objUser | Add-Member RessourceGroup $rcrsGrpName
        $objUser | Add-Member Ressource $rcrsName
        $objUser | Add-Member RoleName $assignment.RoleDefinitionName
        $objUser | Add-Member RoleId $assignment.RoleDefinitionId
        $objUser | Add-Member ObjectType $assignment.ObjectType
        $objUser | Add-Member ObjectId $assignment.ObjectId
        $objUser | Add-Member UserName $assignment.DisplayName
        $objUser | Add-Member EMail $assignment.SignInName
        $roleAssignments += $objUser
    }
}
$roleAssignments | Export-CSV -Path "$AlyaData\aad\RoleAssignments.csv" -NoTypeInformation -Confirm:$false -Force

#Stopping Transscript
Stop-Transcript
