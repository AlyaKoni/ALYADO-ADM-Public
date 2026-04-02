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
    12.02.2026 Konrad Brunner       Initial Version

#>

<#
.SYNOPSIS
Migrates all Azure Key Vaults in specified or all subscriptions to RBAC authorization.

.DESCRIPTION
This script checks one or multiple Azure subscriptions for existing Key Vaults and migrates each vault from access policies to RBAC authorization if not already enabled. It maps existing access policies to suitable built-in Azure roles and assigns them at the Key Vault scope. The script supports optional processing of a single Key Vault by name and can target a specific subscription if desired. It automatically handles Azure module installation and authentication, and logs its operations.

.PARAMETER processOnlyKeyVaultsWithName
Specifies the name of a single Key Vault to be migrated. If not provided, all Key Vaults in the selected subscriptions are processed.

.PARAMETER subscriptionName
Specifies the name of a single subscription to process. If not provided, all subscriptions defined in the configuration are processed.

.PARAMETER dryRun
If set to $true, no changes are made; the script only reports what would be done.

.PARAMETER handleStoragePermissions
If set to $true, storage permissions in Key Vault access policies are also migrated.

.INPUTS
None. The script does not accept pipeline input.

.OUTPUTS
None. The script writes status messages and logs actions to a transcript file.

.EXAMPLE
PS> .\Migrate-AllKeyVaultsToRBAC.ps1 -subscriptionName "Production" -processOnlyKeyVaultsWithName "mykeyvault001" -dryRun $false

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [string]$processOnlyKeyVaultsWithName = $null,
    [string]$subscriptionName = $null,
    [bool]$dryRun = $true,
    [bool]$handleStoragePermissions = $false
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Migrate-AllKeyVaultsToRBAC-$($AlyaTimeString).log" | Out-Null

# Members
$permissionMap = @(
    @{Group="Key";Access="GET";Permissions=@("Microsoft.KeyVault/vaults/keys/read")},
    @{Group="Key";Access="LIST";Permissions=@("Microsoft.KeyVault/vaults/keys/read")},
    @{Group="Key";Access="UPDATE";Permissions=@("Microsoft.KeyVault/vaults/keys/update/action")},
    @{Group="Key";Access="CREATE";Permissions=@("Microsoft.KeyVault/vaults/keys/create/action")},
    @{Group="Key";Access="IMPORT";Permissions=@("Microsoft.KeyVault/vaults/keys/import/action")},
    @{Group="Key";Access="DELETE";Permissions=@("Microsoft.KeyVault/vaults/keys/delete")},
    @{Group="Key";Access="RECOVER";Permissions=@("Microsoft.KeyVault/vaults/keys/recover/action")},
    @{Group="Key";Access="BACKUP";Permissions=@("Microsoft.KeyVault/vaults/keys/backup/action")},
    @{Group="Key";Access="RESTORE";Permissions=@("Microsoft.KeyVault/vaults/keys/restore/action")},
    @{Group="Key";Access="DECRYPT";Permissions=@("Microsoft.KeyVault/vaults/keys/decrypt/action")},
    @{Group="Key";Access="ENCRYPT";Permissions=@("Microsoft.KeyVault/vaults/keys/encrypt/action")},
    @{Group="Key";Access="UNWRAPKEY";Permissions=@("Microsoft.KeyVault/vaults/keys/unwrap/action")},
    @{Group="Key";Access="WRAPKEY";Permissions=@("Microsoft.KeyVault/vaults/keys/wrap/action")},
    @{Group="Key";Access="VERIFY";Permissions=@("Microsoft.KeyVault/vaults/keys/verify/action")},
    @{Group="Key";Access="SIGN";Permissions=@("Microsoft.KeyVault/vaults/keys/sign/action")},
    @{Group="Key";Access="PURGE";Permissions=@("Microsoft.KeyVault/vaults/keys/purge/action")},
    @{Group="Key";Access="RELEASE";Permissions=@("Microsoft.KeyVault/vaults/keys/release/action")},
    @{Group="Key";Access="ROTATE";Permissions=@("Microsoft.KeyVault/vaults/keys/rotate/action")},
    @{Group="Key";Access="GETROTATIONPOLICY";Permissions=@("Microsoft.KeyVault/vaults/keyrotationpolicies/read")},
    @{Group="Key";Access="SETROTATIONPOLICY";Permissions=@("Microsoft.KeyVault/vaults/keyrotationpolicies/write")},
    @{Group="Key";Access="ALL";Permissions=@("Microsoft.KeyVault/vaults/keys/read","Microsoft.KeyVault/vaults/keys/read","Microsoft.KeyVault/vaults/keys/update/action","Microsoft.KeyVault/vaults/keys/create/action","Microsoft.KeyVault/vaults/keys/import/action","Microsoft.KeyVault/vaults/keys/delete","Microsoft.KeyVault/vaults/keys/recover/action","Microsoft.KeyVault/vaults/keys/backup/action","Microsoft.KeyVault/vaults/keys/restore/action","Microsoft.KeyVault/vaults/keys/decrypt/action","Microsoft.KeyVault/vaults/keys/encrypt/action","Microsoft.KeyVault/vaults/keys/unwrap/action","Microsoft.KeyVault/vaults/keys/wrap/action","Microsoft.KeyVault/vaults/keys/verify/action","Microsoft.KeyVault/vaults/keys/sign/action","Microsoft.KeyVault/vaults/keys/purge/action","Microsoft.KeyVault/vaults/keys/release/action","Microsoft.KeyVault/vaults/keys/rotate/action","Microsoft.KeyVault/vaults/keyrotationpolicies/read","Microsoft.KeyVault/vaults/keyrotationpolicies/write")},
    @{Group="Certificate";Access="GET";Permissions=@("Microsoft.KeyVault/vaults/certificates/read")},
    @{Group="Certificate";Access="LIST";Permissions=@("Microsoft.KeyVault/vaults/certificates/read")},
    @{Group="Certificate";Access="UPDATE";Permissions=@("Microsoft.KeyVault/vaults/certificates/update/action")},
    @{Group="Certificate";Access="CREATE";Permissions=@("Microsoft.KeyVault/vaults/certificates/create/action")},
    @{Group="Certificate";Access="IMPORT";Permissions=@("Microsoft.KeyVault/vaults/certificates/import/action")},
    @{Group="Certificate";Access="DELETE";Permissions=@("Microsoft.KeyVault/vaults/certificates/delete")},
    @{Group="Certificate";Access="RECOVER";Permissions=@("Microsoft.KeyVault/vaults/certificates/recover/action")},
    @{Group="Certificate";Access="BACKUP";Permissions=@("Microsoft.KeyVault/vaults/certificates/backup/action")},
    @{Group="Certificate";Access="RESTORE";Permissions=@("Microsoft.KeyVault/vaults/certificates/restore/action")},
    @{Group="Certificate";Access="MANAGECONTACTS";Permissions=@("Microsoft.KeyVault/vaults/certificatecontacts/write")},
    @{Group="Certificate";Access="MANAGEISSUERS";Permissions=@("Microsoft.KeyVault/vaults/certificatecas/write")},
    @{Group="Certificate";Access="GETISSUERS";Permissions=@("Microsoft.KeyVault/vaults/certificatecas/read")},
    @{Group="Certificate";Access="LISTISSUERS";Permissions=@("Microsoft.KeyVault/vaults/certificatecas/read")},
    @{Group="Certificate";Access="SETISSUERS";Permissions=@("Microsoft.KeyVault/vaults/certificatecas/write")},
    @{Group="Certificate";Access="DELETEISSUERS";Permissions=@("Microsoft.KeyVault/vaults/certificatecas/delete")},
    @{Group="Certificate";Access="PURGE";Permissions=@("Microsoft.KeyVault/vaults/certificates/purge/action")},
    @{Group="Certificate";Access="ALL";Permissions=@("Microsoft.KeyVault/vaults/certificates/read","Microsoft.KeyVault/vaults/certificates/read","Microsoft.KeyVault/vaults/certificates/update/action","Microsoft.KeyVault/vaults/certificates/create/action","Microsoft.KeyVault/vaults/certificates/import/action","Microsoft.KeyVault/vaults/certificates/delete","Microsoft.KeyVault/vaults/certificates/recover/action","Microsoft.KeyVault/vaults/certificates/backup/action","Microsoft.KeyVault/vaults/certificates/restore/action","Microsoft.KeyVault/vaults/certificatecontacts/write","Microsoft.KeyVault/vaults/certificatecas/write","Microsoft.KeyVault/vaults/certificatecas/read","Microsoft.KeyVault/vaults/certificatecas/read","Microsoft.KeyVault/vaults/certificatecas/write","Microsoft.KeyVault/vaults/certificatecas/delete","Microsoft.KeyVault/vaults/certificates/purge/action")},
    @{Group="Secret";Access="GET";Permissions=@("Microsoft.KeyVault/vaults/secrets/getSecret/action")},
    @{Group="Secret";Access="LIST";Permissions=@("Microsoft.KeyVault/vaults/secrets/readMetadata/action")},
    @{Group="Secret";Access="SET";Permissions=@("Microsoft.KeyVault/vaults/secrets/setSecret/action","Microsoft.KeyVault/vaults/secrets/update/action")},
    @{Group="Secret";Access="DELETE";Permissions=@("Microsoft.KeyVault/vaults/secrets/delete")},
    @{Group="Secret";Access="RECOVER";Permissions=@("Microsoft.KeyVault/vaults/secrets/recover/action")},
    @{Group="Secret";Access="BACKUP";Permissions=@("Microsoft.KeyVault/vaults/secrets/backup/action")},
    @{Group="Secret";Access="RESTORE";Permissions=@("Microsoft.KeyVault/vaults/secrets/restore/action")},
    @{Group="Secret";Access="PURGE";Permissions=@("Microsoft.KeyVault/vaults/secrets/purge/action")},
    @{Group="Secret";Access="ALL";Permissions=@("Microsoft.KeyVault/vaults/secrets/getSecret/action","Microsoft.KeyVault/vaults/secrets/readMetadata/action","Microsoft.KeyVault/vaults/secrets/setSecret/action","Microsoft.KeyVault/vaults/secrets/update/action","Microsoft.KeyVault/vaults/secrets/delete","Microsoft.KeyVault/vaults/secrets/recover/action","Microsoft.KeyVault/vaults/secrets/backup/action","Microsoft.KeyVault/vaults/secrets/restore/action","Microsoft.KeyVault/vaults/secrets/purge/action")},
    @{Group="Storage";Access="GET";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/read")},
    @{Group="Storage";Access="LIST";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/read")},
    @{Group="Storage";Access="DELETE";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/delete")},
    @{Group="Storage";Access="SET";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/set/action")},
    @{Group="Storage";Access="UPDATE";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/set/action")},
    @{Group="Storage";Access="REGENERATEKEY";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/regeneratekey/action")},
    @{Group="Storage";Access="GETSAS";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/sas/read")},
    @{Group="Storage";Access="LISTSAS";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/sas/read")},
    @{Group="Storage";Access="DELETESAS";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/sas/delete")},
    @{Group="Storage";Access="SETSAS";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/sas/set/action")},
    @{Group="Storage";Access="RECOVER";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/recover/action")},
    @{Group="Storage";Access="BACKUP";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/backup/action")},
    @{Group="Storage";Access="RESTORE";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/restore/action")},
    @{Group="Storage";Access="PURGE";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/purge/action")},
    @{Group="Storage";Access="ALL";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/read","Microsoft.KeyVault/vaults/storageaccounts/read","Microsoft.KeyVault/vaults/storageaccounts/delete","Microsoft.KeyVault/vaults/storageaccounts/set/action","Microsoft.KeyVault/vaults/storageaccounts/set/action","Microsoft.KeyVault/vaults/storageaccounts/regeneratekey/action","Microsoft.KeyVault/vaults/storageaccounts/sas/read","Microsoft.KeyVault/vaults/storageaccounts/sas/read","Microsoft.KeyVault/vaults/storageaccounts/sas/delete","Microsoft.KeyVault/vaults/storageaccounts/sas/set/action","Microsoft.KeyVault/vaults/storageaccounts/recover/action","Microsoft.KeyVault/vaults/storageaccounts/backup/action","Microsoft.KeyVault/vaults/storageaccounts/restore/action","Microsoft.KeyVault/vaults/storageaccounts/purge/action")}
)

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.KeyVault"

# Logins
LoginTo-Az -SubscriptionName ([string]::IsNullOrEmpty($subscriptionName) ? $AlyaSubscriptionName : $subscriptionName)

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Monitor | Migrate-AllKeyVaultsToRBAC | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Getting all key vault roles
Write-Host "Getting all key vault roles" -ForegroundColor $CommandInfo
$allRoles = Get-AzRoleDefinition
$roles = $allRoles | Where-Object { $_.Name -like "Key Vault*" } | Sort-Object { 
    $s = 0
    if ($_.Name.Contains("User")) { $s += 1 }
    if ($_.Name.Contains("Officer")) { $s += 3 }
    if ($_.Name.Contains("Operator")) { $s += 5 }
    if ($_.Name.Contains("Contributor")) { $s += 7 }
    if ($_.Name.Contains("Reader")) { $s += 9 }
    if ($_.Name.Contains("Administrator")) { $s += 11 }
    if ($_.Name.Contains("Crypto")) { $s += 1 }
    if ($_.Name.Contains("Data")) { $s -= 1 }
    $s
}
$roles.Name

# Functions
function Is-RoleContainedInRole($checkRole, $containedInRole)
{
    #Write-Host "          Checking if role $($checkRole.Name) is contained in role $($containedInRole.Name)"
    # foreach($action in $checkRole.Actions) {
    #     $fnd = $false
    #     foreach($cAction in $containedInRole.Actions) {
    #         if ($action -like "$cAction")
    #         {
    #             $fnd = $true
    #             break
    #         }
    #     }
    #     foreach($cAction in $containedInRole.DataActions) {
    #         if ($action -like "$cAction")
    #         {
    #             $fnd = $true
    #             break
    #         }
    #     }
    #     if (-Not $fnd) {
    #         return $false
    #     }
    # }
    foreach($action in $checkRole.DataActions) {
        $fnd = $false
        foreach($cAction in $containedInRole.DataActions) {
            if ($action -like "$cAction")
            {
                $fnd = $true
                break
            }
        }
        # foreach($cAction in $containedInRole.Actions) {
        #     if ($action -like "$cAction")
        #     {
        #         $fnd = $true
        #         break
        #     }
        # }
        if (-Not $fnd) {
            return $false
        }
    }
    # foreach($action in $checkRole.NotActions) {
    #     foreach($cAction in $containedInRole.NotActions) {
    #         if ($action -like "$cAction")
    #         {
    #             $fnd = $true
    #             break
    #         }
    #     }
    #     if (-Not $fnd) {
    #         return $false
    #     }
    # }
    foreach($action in $checkRole.NotDataActions) {
        foreach($cAction in $containedInRole.NotDataActions) {
            if ($action -like "$cAction")
            {
                $fnd = $true
                break
            }
        }
        if (-Not $fnd) {
            return $false
        }
    }
    return $true
}

function Find-RoleByPermissions($allKvRoles, $allPerms)
{
    $rert = $null
    foreach($role in $allKvRoles)
    {
        $allFnd = $true
        foreach($perm in $allPerms) {
            $cont = $false
            # foreach($action in $role.Actions) {
            #     if ($perm -like "$action")
            #     {
            #         $cont = $true
            #         break
            #     }
            # }
            foreach($action in $role.DataActions) {
                if ($perm -like "$action")
                {
                    $cont = $true
                    break
                }
            }
            # foreach($action in $role.NotActions) {
            #     if ($perm -like "$action")
            #     {
            #         $cont = $false
            #         break
            #     }
            # }
            foreach($action in $role.NotDataActions) {
                if ($perm -like "$action")
                {
                    $cont = $false
                    break
                }
            }
            if (-Not $cont) {
                $allFnd = $false
                break
            }
        }
        if ($allFnd) {
            $rert = $role
            break
        }
    }
    return $rert
}

# Checking subscriptions
foreach ($AlyaSubscriptionName in (([string]::IsNullOrEmpty($subscriptionName) ? $AlyaAllSubscriptions : @($subscriptionName)) | Select-Object -Unique))
{
    Write-Host "Checking subscription $AlyaSubscriptionName" -ForegroundColor $MenuColor
  
    # Switching to subscription
    $sub = Get-AzSubscription -SubscriptionName $AlyaSubscriptionName
    $null = Set-AzContext -Subscription $sub.Id
    $Context = Get-AzContext

    $KeyVaults = Get-AzKeyVault
    foreach ($KeyVault in $KeyVaults)
    {
        $KeyVaultName = $KeyVault.VaultName
        if (-Not [string]::IsNullOrEmpty($processOnlyKeyVaultWithName) -and $processOnlyKeyVaultWithName -ne $KeyVaultName)
        {
            continue
        }

        Write-Host "Checking key vault $KeyVaultName" -ForegroundColor $CommandInfo
        if ($KeyVault.EnableRbacAuthorization)
        {
            Write-Host "  Already using RBAC authorization, skipping."
        }
        else
        {
            # Checking own key vault access
            Write-Host "Checking own key vault access" -ForegroundColor $CommandInfo
            $user = Get-AzAdUser -UserPrincipalName $Context.Account.Id
            $RoleAssignments = Get-AzRoleAssignment -ObjectId $user.Id -ResourceGroupName $KeyVault.ResourceGroupName -ResourceName $KeyVault.VaultName -ResourceType "Microsoft.KeyVault/vaults"
            $fndAss = $false
            $fndKv = $false
            foreach($RoleAssignment in $RoleAssignments)
            {
                $role = $allRoles | Where-Object { $_.Id -eq $RoleAssignment.RoleDefinitionId }
                foreach($perm in $role.Actions) {
                    if ("Microsoft.Authorization/roleAssignments/write" -like $perm) {
                        $fndAss = $true
                        break
                    }
                    if ("Microsoft.KeyVault/vaults/write" -like $perm) {
                        $fndKv = $true
                        break
                    }
                }
            }   
            if (-Not $fndAss -or -Not $fndKv) {
                Write-Warning "  No permissions to set role assignments or update key vaults, skipping migration of this key vault!"
            }

            Write-Host "  Migrating to RBAC authorization..."
            $KeyVault = Get-AzKeyVault -ResourceGroupName $KeyVault.ResourceGroupName -VaultName $KeyVaultName
            Write-Host "    Checking migration"
            foreach($AccessPolicy in $KeyVault.AccessPolicies)
            {
                #$AccessPolicy = $KeyVault.AccessPolicies[0]
                $prcplId = $AccessPolicy.ObjectId
                if ($null -ne $AccessPolicy.ApplicationId)
                {
                    if ($null -ne $prcplId)
                    {
                        throw "Not yet implemented handling of access policies with both object id and application id set! ObjectId: $($AccessPolicy.ObjectId) ApplicationId: $($AccessPolicy.ApplicationId)"
                    }
                    $prcplId = $AccessPolicy.ApplicationId
                }
                Write-Host "      Access policy for object id $($prcplId) with permissions to"
                Write-Host "          keys: $($AccessPolicy.PermissionsToKeys -join ",")"
                Write-Host "          secrets: $($AccessPolicy.PermissionsToSecrets -join ",")"
                Write-Host "          certificates: $($AccessPolicy.PermissionsToCertificates -join ",")"
                if ($handleStoragePermissions) {
                    Write-Host "          storage: $($AccessPolicy.PermissionsToStorage -join ",")"
                }
                $allPerms = @()
                $migRoles = @()
                if ($AccessPolicy.PermissionsToKeys.Count -gt 0)
                {
                    $perms = @()
                    foreach($acc in $AccessPolicy.PermissionsToKeys)
                    {
                        $permMap = $permissionMap | Where-Object { $_.Group -eq "Key" -and $_.Access -eq $acc.ToUpper() }
                        if (-Not $permMap) {
                            Write-Error "No permission mapping found for access '$acc' in group Key, skipping!" -ErrorAction Continue
                            exit
                        }
                        foreach($perm in $permMap.Permissions) {
                            if ($perms -notcontains $perm) {
                                $perms += $perm
                            }
                        }
                    }
                    $fndRole = Find-RoleByPermissions -allKvRoles $roles -allPerms $perms
                    if ($fndRole) {
                        Write-Host "        Keys: Possible migration to $($fndRole.Name)"
                        if ($migRoles -notcontains $fndRole) {
                            $migRoles += $fndRole
                        }
                    }
                    else {
                        foreach($perm in $perms) {
                            if ($allPerms -notcontains $perm) {
                                $allPerms += $perm
                            }
                        }
                    }
                }
                if ($AccessPolicy.PermissionsToSecrets.Count -gt 0)
                {
                    $perms = @()
                    foreach($acc in $AccessPolicy.PermissionsToSecrets)
                    {
                        $permMap = $permissionMap | Where-Object { $_.Group -eq "Secret" -and $_.Access -eq $acc.ToUpper() }
                        if (-Not $permMap) {
                            Write-Error "No permission mapping found for access '$acc' in group Secret, skipping!" -ErrorAction Continue
                            exit
                        }
                        foreach($perm in $permMap.Permissions) {
                            if ($perms -notcontains $perm) {
                                $perms += $perm
                            }
                        }
                    }
                    $fndRole = Find-RoleByPermissions -allKvRoles $roles -allPerms $perms
                    if ($fndRole) {
                        Write-Host "        Secrets: Possible migration to $($fndRole.Name)"
                        if ($migRoles -notcontains $fndRole) {
                            $migRoles += $fndRole
                        }
                    }
                    else {
                        foreach($perm in $perms) {
                            if ($allPerms -notcontains $perm) {
                                $allPerms += $perm
                            }
                        }
                    }
                }
                if ($AccessPolicy.PermissionsToCertificates.Count -gt 0)
                {
                    $perms = @()
                    foreach($acc in $AccessPolicy.PermissionsToCertificates)
                    {
                        $permMap = $permissionMap | Where-Object { $_.Group -eq "Certificate" -and $_.Access -eq $acc.ToUpper() }
                        if (-Not $permMap) {
                            Write-Error "No permission mapping found for access '$acc' in group Certificate, skipping!" -ErrorAction Continue
                            exit
                        }
                        if ($permMap.Access -eq "ALL")
                        {
                            $aa = $permMap.Permissions
                        }
                        foreach($perm in $permMap.Permissions) {
                            if ($perms -notcontains $perm) {
                                $perms += $perm
                            }
                        }
                    }
                    $fndRole = Find-RoleByPermissions -allKvRoles $roles -allPerms $perms
                    if ($fndRole) {
                        Write-Host "        Certificates: Possible migration to $($fndRole.Name)"
                        if ($migRoles -notcontains $fndRole) {
                            $migRoles += $fndRole
                        }
                    }
                    else {
                        foreach($perm in $perms) {
                            if ($allPerms -notcontains $perm) {
                                $allPerms += $perm
                            }
                        }
                    }
                }
                if ($handleStoragePermissions) {
                    if ($AccessPolicy.PermissionsToStorage.Count -gt 0)
                    {
                        $perms = @()
                        foreach($acc in $AccessPolicy.PermissionsToStorage)
                        {
                            $permMap = $permissionMap | Where-Object { $_.Group -eq "Storage" -and $_.Access -eq $acc.ToUpper() }
                            if (-Not $permMap) {
                                Write-Error "No permission mapping found for access '$acc' in group Storage, skipping!" -ErrorAction Continue
                                exit
                            }
                            foreach($perm in $permMap.Permissions) {
                                if ($perms -notcontains $perm) {
                                    $perms += $perm
                                }
                            }
                        }
                        $fndRole = Find-RoleByPermissions -allKvRoles $roles -allPerms $perms
                        if ($fndRole) {
                            Write-Host "        Storage: Possible migration to $($fndRole.Name)"
                            if ($migRoles -notcontains $fndRole) {
                                $migRoles += $fndRole
                            }
                        }
                        else {
                            foreach($perm in $perms) {
                                if ($allPerms -notcontains $perm) {
                                    $allPerms += $perm
                                }
                            }
                        }
                    }
                }
                if ($allPerms.Count -gt 0)
                {
                    $fndRole = Find-RoleByPermissions -allKvRoles $roles -allPerms $allPerms
                    if ($fndRole) {
                        Write-Host "        All: Possible migration to $($fndRole.Name)"
                        if ($migRoles -notcontains $fndRole) {
                            $migRoles += $fndRole
                        }
                        $allPerms = $null
                    }
                }
                foreach($checkRole in $migRoles) {
                    foreach($containedInRole in $migRoles) {
                        if ($checkRole.Name -ne $containedInRole.Name) {
                            if (Is-RoleContainedInRole -checkRole $checkRole -containedInRole $containedInRole) {
                                Write-Host "        Role $($checkRole.Name) is contained in role $($containedInRole.Name), removing it from list."
                                $migRoles = $migRoles | Where-Object { $_.Name -ne $checkRole.Name }
                                break
                            }
                        }
                    }
                }
                if ($migRoles.Count -eq 0) {
                    Write-Warning "        No suitable built-in role found for migration, skipping!"
                    continue
                }
                Write-Host "        Roles to assign: $($migRoles.Name -join ", ")"

                foreach($migRole in $migRoles) {
                    Write-Host "          Checking: $($migRole.Name)"
                    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName $migRole.Name -ObjectId $prcplId -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
                    if ($RoleAssignment)
                    {
                        Write-Host "            Role assignment already exists, skipping."
                        continue
                    }
                    Write-Host "            Role assignment not found, creating..." -ForegroundColor $CommandWarning
                    if (-Not $dryRun -and $fndAss -and $fndKv) {
                        $Retries = 0;
                        While ($null -eq $RoleAssignment -and $Retries -le 6)
                        {
                            $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName $migRole.Name -ObjectId $prcplId -scope $KeyVault.ResourceId -ErrorAction SilentlyContinue
                            Start-Sleep -s 10
                            $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName $migRole.Name -ObjectId $prcplId -scope $KeyVault.ResourceId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
                            $Retries++;
                        }
                        if ($Retries -gt 6)
                        {
                            throw "Was not able to set role assigment '$($migRole.Name)' for app $($AutomationAccount.Identity.PrincipalId) on scope $($KeyVault.ResourceId)"
                        }
                    }
                }

            }

            Write-Host "  Migration completed, enabling RBAC authorization on key vault."
            if (-Not $dryRun -and $fndAss -and $fndKv) {
                Update-AzKeyVault -ResourceGroupName $KeyVault.ResourceGroupName -Name $KeyVaultName -EnableRbacAuthorization $true
            }
        }
    }
}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIvCQYJKoZIhvcNAQcCoIIu+jCCLvYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDfiRlIVvWStkdF
# ST6tBLIymR9QlBFU5m/RyK7c+NReuaCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAsgIo8C
# tQFI608qlWX4i6QWGuUYtMVIWlmsh1QLa11oMA0GCSqGSIb3DQEBAQUABIICABDt
# fSXOtm0ljiuIxhhuKqNTy3BF6eCu0qm/7Jt4W78k+wg46CqolMHdDnLtz41tF9ol
# Ny/8lNEFZ2R6L+U3kuxMWUiZlMpErMt9NaSvJifvkUP4US44n0OGT2cHPtkVhGBZ
# W/imFImR76d9IIiYn48YwCVpLS7xxAJO0V2415gKIkNaTisclRijjHma+aVX54DN
# SlMBDlFWDslrvNb2/2GPwQmEGvI6muEp/KyJKT3JbEwtixXOjVJE+tAMVQEnpfow
# OY6Bv4CaoFPBXBUyiNvN5bPAPbSBUyfCCqArcKO5OB7jzSolSZTOb5D4t3xU5lB3
# Llq3wIenEXSmwGOiSznI961XCbkoNLlv8xlDhKR0aVMQLvc76H77W/Er5Bthi5KU
# V12PbN9c21truxH8InOtYQKQjLhQt9APFTlzwEdoc4okSA38ME6U/y73SfT0qlOg
# yBZVXKbFZZ2csWZVebEJw2l3/bCpZvfGzpjPiDGcpgfztx1hkBy+9Pq3W9jz2MEd
# vo9GpVavkTQHYoFuJ/HGDbco5lcAaeR7u6HcnFirn1KU8dOhtNVjYE1E5tOU9JM9
# stKITHauTMftw90WTvcOXqAE0YCBVplFPw5Vs3zE4XhSxTkEMefGP47DyJfQnTHK
# G+4+cmqmMa45Ct0rebE+TLXkNxXV1izR/TzX/FKwoYIWuzCCFrcGCisGAQQBgjcD
# AwExghanMIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEw
# gd8GCyqGSIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCB9jsy2GxtU7nFZzjPDjZWPObAfokoxFw9tByxnBW0RtwIURYbv
# N+PCAzkGrMRp4uiElNwvUlwYDzIwMjYwMjEyMjA1NjE2WjADAgEBoFikVjBUMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwh
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMC
# AQICEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNp
# Z24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5
# WhcNMzQxMjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFs
# U2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWdu
# MSAtIFI2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4
# PuCF6+aqCj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb
# 5gk0Xydy3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJSc
# RV1W6/6efi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy
# 5RJY+o1NWhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY
# 0Lie04DuKbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2Z
# wbI6yiFHaS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYh
# KUlrMH9+2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5s
# WtX1qvCzk6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGo
# MIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYD
# VR0OBBYEFIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQC
# MEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSB
# gzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2Ev
# Z3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2Jh
# bHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaA
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9j
# cmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG
# 9w0BAQwFAAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26
# IFq7fQMIrN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76Tkv
# L+v2f4mHolGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftP
# ttS+G/MhNUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIl
# S3Ki74CU15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt
# 8DT4RQj9LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5
# lgJkgXEc1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD
# 9hQchjiGkyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71
# yzGKWnbAWQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGL
# ZtJFJzGJD7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVA
# GXCqHsh62QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZ
# MIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAw
# MDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOv
# dYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt
# 0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHP
# vIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFU
# UweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16
# ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS
# 2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm1
# 9m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIG
# bxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMD
# Ad6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/Miy
# Tdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9
# GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGG
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDD
# vWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEB
# BDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jv
# b3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29t
# L3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0B
# AQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYW
# axlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCy
# z+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQ
# cXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0
# Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59e
# odaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8
# oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1
# If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbcl
# IA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2M
# tnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB
# +SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIID
# a6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQL
# ExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjET
# MBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAw
# MDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQK
# EwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4
# QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTe
# c5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWy
# ZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7tt
# U+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrK
# otudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKF
# t3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTfl
# puwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2Fm
# CWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5
# paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4O
# hxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwo
# TK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki
# 5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnm
# XNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJE
# lrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMp
# mY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6
# JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG
# 7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/
# gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324G
# abbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5
# MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO7
# 7oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4st
# Q1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjx
# guhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJ
# YIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZI
# hvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcN
# AQkEMSIEILmNw7C2ao+6B6b//lqspGBI48UdTEIYmJiwg23hmfA9MIGwBgsqhkiG
# 9w0BCRACLzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1or
# d69gXP0wczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hB
# Mzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAn51r
# zJu2jwGgZkv1jTKrfhK15bK+vboD93n40owIfV5Racf5mFBSStZuMpeHg0v0z7/S
# BhjW2fF90EBdAHLwsIk/H8GBFXbYHXDYi6QemHflC7ws+Wem6XR+4Wd6w0vqizUw
# vJ0fy2Sx5qmnSbWvfbwHuWJU3NCMrfnQ0Bv6tVvc/EBnrVJoObD+zil8GAEWVrNq
# lE4gaM9MhSH1rkS+V6My2tdM04nKk8B5FzU4QIL2uMsmrS6UnN72qrAL8SQLhx1K
# /Nud/WmWRAuQH0/5VegCgH1wKsyXUY/trbXMo81Imu/oJpNonO9OawDPCPsGdmUZ
# Dbr3zMcEHBSnjX83HUWqnkvlLmtc+H97w63dHCxzQ5cyXwZd3WnsKI85WwwULA4B
# rQFF+vQ6MJniOv+o8Qig0cRlPzzdVdku2iX2dKY41xF/JjV7hEQMwmCDwfdR10wi
# TyIlGwnhOwpgXz6DqJnFcV90aZUwYsJQ5YQWvhGtN4iAzlzGDk+MSBuvOARK
# SIG # End signature block
