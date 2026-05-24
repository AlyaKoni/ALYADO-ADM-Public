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
        Write-Host "Checking key vault $KeyVaultName" -ForegroundColor $CommandInfo
        $KeyVault = Get-AzKeyVault -VaultName $KeyVault.VaultName -ResourceGroupName $KeyVault.ResourceGroupName
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
                    }
                    if ("Microsoft.KeyVault/vaults/write" -like $perm) {
                        $fndKv = $true
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
                Update-AzKeyVault -ResourceGroupName $KeyVault.ResourceGroupName -Name $KeyVaultName -DisableRbacAuthorization $false $false
            }
        }
    }
}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIwlQYJKoZIhvcNAQcCoIIwhjCCMIICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAoelddWj0m4xb7
# TlN60/aK7G8tffuSxlwFiIxBsq4xSqCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# giEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOnYbrhH3I6Eva+k
# 9zFkk3oA8AKECefJAsbek+7Ll2pMMA0GCSqGSIb3DQEBAQUABIICACVqSAj60A5Q
# 3NBNnCj7qjtttz+rTLVXe4GJQobmvNAZJfz+UToInPc+ospbvc8l0YtT2uMKHHZU
# k9XonNabqQHFPhk4IU+9vpBWXNAc+RHH0FuVgfUAiPV1hjemQL3BNc91cSYrpkAM
# 4WIZriY74KwY25sLEjfvvjOPa+q9kaAl9ClD5pbu+6kp3lJR9GdoNniZZzwA0otD
# 9TU9zZqs5GoSawoOi/ew4eqiiEVg52RF53D0tJzHFqRJbwgOLwQgcNtuBSWpNr78
# kH3KIbhx0QMHBx6vVporW6UcwDwf7A1MQER+Uw5JRPVPg211kq+9guQKMA6iPB2A
# TQV5v2a81Bhg0uRuiTwZELZi6Jis7ZFmVLfzYdwmmV/pK7bF4DEDPrB0liQkQeBD
# SXpTLDf2R4pqF7mFR6SOVoZuos0HlHKgyy0O7MDibvf40tY3CmoGxzJf4NNrgDc5
# 4ZnEuBZ7sJlrs/SIKnHPmlahyzkkYz1LlW/8QMYGMy/Vmx6uZMGqxeMTWVQ6NYg2
# G1NBk1sz88RxAxmEI3I8emzyDDLJpzRnRViQhu5erzC03ljxwD9ZLhjFgRefgPV7
# ygl/a20nB3lV8X3rGVVMb3djDHCONFmhmtfUAHjeO4z2qDuMWA7WD9+mG33PIFpG
# tYHb8PLojv/v4fmzXV52oMn3sPiKMKgroYId7TCCHekGCisGAQQBgjcDAwExgh3Z
# MIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIwgeQGCyqG
# SIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCGSAFlAwQC
# AQUABCDldj/24kT3NzOiSl2P6szGkqqkAoILf6nudHyy9baEmAIUYG43n/0gOOQL
# D0Z2aDkz3rgmOTAYDzIwMjYwNTExMTAyNTAzWjADAgEBoF2kWzBZMQswCQYDVQQG
# EwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFs
# c2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCCBHKgAwIB
# AgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNp
# Z24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUxMDE1MDcy
# NTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xv
# YmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNBIGZvciBD
# b2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDR
# So2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6rVD8pgy1
# sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6qADUMn96m
# qHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6CjX0t3wJfh
# L0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHux0InYS7R
# r54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKOC7QkFbkl
# hPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ0SoibbUq
# xsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQbPGs02Ba
# 8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+TfueCIU0C
# AwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEF
# BQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8dPIxlNigG
# GTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYBBQUHAQEE
# gZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dz
# b2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0cDovL3Nl
# Y3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGltZXN0YW1w
# Y2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmdsb2JhbHNp
# Z24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYDVR0gBE8w
# TTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8v
# d3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBDAUAA4IC
# AQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOfBvhcvoFQ
# w4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SCNLHs6vCg
# 6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdByiHteLxgj
# ugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRWLzPVcUkR
# k9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZsH8EXwiT
# UTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdPL/F8VCMK
# j3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWIV3hgRl+V
# yKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/xCB0/lSK
# LnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJsnmVbS0x
# 50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5+6PokOkQ
# 8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSIoAMCAQIC
# EQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNVBAYTAkJF
# MRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWdu
# IFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00MTA3MTYw
# MDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNh
# MTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFtcGluZyBD
# QSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW+O19i+Ld
# AoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzoZ3nN0CMn
# cZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hfGMG4PJvY
# FvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSaZKraMxFt
# 676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJexYwEVU0
# GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVrYXEdhfVL
# wuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfFJC4P5FW1
# SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z8oTvSaSI
# REovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDzPk+UbLmg
# ZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlTZbVHdqNi
# u0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxUYgoVSxqb
# 4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1UdDwEB/wQE
# AwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/AgEAMB0G
# A1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRGshx34XsV
# 8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcwAYYraHR0
# cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBEBggrBgEF
# BQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvdGltZXN0
# YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAIMAYGBFUd
# IAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1n//quXGL
# VfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM+YjPEf8A
# tC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3yZ6Vcu6Ha
# 0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8njTvAwaT
# MGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534nUINB9whO
# RicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+sQdBidnP
# uLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTfd4yw4nQd
# k1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7NacoTVxZnKG
# kv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZxci6TX78
# smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDXQbEfa93l
# hikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6DC74n5+O5
# bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkqhkiG9w0B
# AQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UE
# ChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEyMDkwMDAw
# MDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBS
# b290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0M+wn3BI4
# IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0lHI7cQ0a
# 72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/WrNU0Pn1k7
# 9S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8NyiwAS+CA6
# YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOooMUz5IWqo
# zfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+PuNF2cvN8
# oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMsDpt3UCA0
# QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvbQhQFB6r7
# FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6SW/bPnf+
# uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jhan+HKd45
# m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32xRdvPBUQ
# sA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNVHQ8BAf8E
# BAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
# HQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwFo5MT4qLn
# 4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJodHRwOi8v
# b2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9odHRwOi8v
# c2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2BgNVHR8E
# LzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3Js
# MEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5n
# bG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAi0i6
# Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l74Z/4omN
# laV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VPZnpmqUdU
# M7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+CLDZZCv5
# 6vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPVSbj/S9Il
# T0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTVha1Fe7Wf
# uy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXeP6Z/xyjv
# oW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb5O1mjj2A
# naSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZmIVHCh5i
# 2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDaI4lgH4Nx
# krXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvxbwPBKVLi
# lL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgECAg5F5rsD
# gzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWdu
# IFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xv
# YmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMaw
# iGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjI
# ElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0y
# BqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3
# YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHN
# V5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTah
# b1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV
# 2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9
# ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmF
# zzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT
# 6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEw
# DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOT
# E+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1Og
# MA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jW
# ZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMT
# VlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgH
# M3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3b
# mZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9Bx
# gXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1e
# bcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRg
# emSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2Zla
# tJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQl
# p7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l3
# 1VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MF
# WsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2Jh
# bFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBSNDUgVGlt
# ZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCGSAFlAwQC
# AqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3DQEJNDEe
# MBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJBDEyBDBP
# cBRQV1SWzr/ILHRmcGgZP3ZypiXF8SzcfFeQdN/YAr7U/1FqJAfduPqlBPwyZsQw
# gbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS858bMJhdk
# iChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xv
# YmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5lIFI0NSBU
# aW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcN
# AQEMBQAEggGARigVqn42SODrjZ2S1E3BDkgz4QDSBs+VfnutznRhaQ1MID02stZS
# Zpi3PxPg1LX0dXRomek9hUroplVREEV8hUH+tUVjFKcuHZgX3IWDaYuNpYMDIkxN
# u+fml5Kq9J3YBb07rxh1IURJYDt88aEnB3SVhIlQBaoXQh49Kh6tkjr3mlfIxzHx
# vtxhjNFIrduk5cPF/63rjw4Vzdeps3+FbXVc0eXPGnrSsqctheXXzMfTfR7ZXIHp
# Tx7kMMpZAiUWgws4Vc/tJ6H3+wmX2O2+dJVDdZLUep5YppfG5NewPOjFqV8+jq6n
# mGJlZbjj0B8PPp/0C2e8u5Wf9iGYiHfVtGrW9miRdpbYC+Unx4zUhD+kHP4Y2z1E
# QxFhXAvCWkbu29XysmiNU+4uY0TYvy/MBIR+bv3nwJvJcKW66vnYRe/f8Mg/IcqV
# JgQCSh4/FC5x2XxkN93E84dMbAAAnYlc+KBBkbvyp+h1UUH17eDB9I1fqHTnVVYW
# Qn8q4AO5fZcD
# SIG # End signature block
