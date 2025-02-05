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
    26.09.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$processOnlyStorageAccountWithName = $null,
    [string]$subscriptionName = $null
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Set-RetentionOnAllStorageAccounts-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Storage"
Install-ModuleIfNotInstalled "Az.OperationalInsights"
Install-ModuleIfNotInstalled "Az.Monitor"

# Logins
LoginTo-Az -SubscriptionName ([string]::IsNullOrEmpty($subscriptionName) ? $AlyaSubscriptionName : $subscriptionName)

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Monitor | Set-RetentionOnAllStorageAccounts | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking subscriptions
foreach ($AlyaSubscriptionName in ($AlyaAllSubscriptions | Select-Object -Unique))
{
    Write-Host "Checking subscription $AlyaSubscriptionName" -ForegroundColor $MenuColor
  
    # Switching to subscription
    $sub = Get-AzSubscription -SubscriptionName $AlyaSubscriptionName
    $null = Set-AzContext -Subscription $sub.Id
    $Context = Get-AzContext

    $StrgAccounts = Get-AzStorageAccount
    foreach ($StrgAccount in $StrgAccounts)
    {
        $StorageAccountName = $StrgAccount.StorageAccountName
        if (-Not [string]::IsNullOrEmpty($processOnlyStorageAccountWithName) -and $processOnlyStorageAccountWithName -ne $StorageAccountName)
        {
            continue
        }
        Write-Host "Checking storage account $StorageAccountName" -ForegroundColor $CommandInfo

        $pol = Get-AzStorageAccountManagementPolicy `
            -ResourceGroupName $StrgAccount.ResourceGroupName `
            -StorageAccountName $StrgAccount.StorageAccountName `
            -ErrorAction SilentlyContinue
        if ($pol.Rules)
        {
            $rules = [System.Collections.ArrayList]@($pol.Rules)
        }
        else
        {
            $rules = [System.Collections.ArrayList]@()
        }
        $rule1 = $rules | Where-Object { $_.Name -eq "MediumLogRetentionBlockBlob" }
        $rule2 = $rules | Where-Object { $_.Name -eq "MediumLogRetentionAppendBlob" }
        $rule3 = $rules | Where-Object { $_.Name -eq "LongLogRetentionBlockBlob" }
        $rule4 = $rules | Where-Object { $_.Name -eq "LongLogRetentionAppendBlob" }

        if (-Not $rule1)
        {
            $action1 = Add-AzStorageAccountManagementPolicyAction -BaseBlobAction Delete `
                -daysAfterModificationGreaterThan 180
            $null = Add-AzStorageAccountManagementPolicyAction -InputObject $action1 `
                -BaseBlobAction TierToArchive `
                -daysAfterModificationGreaterThan 90
            $null = Add-AzStorageAccountManagementPolicyAction -InputObject $action1 `
                -BaseBlobAction TierToCool `
                -daysAfterModificationGreaterThan 30
            $null = Add-AzStorageAccountManagementPolicyAction -InputObject $action1 `
                -SnapshotAction Delete `
                -daysAfterCreationGreaterThan 60
            $null = Add-AzStorageAccountManagementPolicyAction -InputObject $action1 `
                -BlobVersionAction TierToArchive `
                -daysAfterCreationGreaterThan 60

            $filter1 = New-AzStorageAccountManagementPolicyFilter -PrefixMatch "insights-activity","insights-metrics","bootdiagnostics" `
                -BlobType blockBlob
            $rule1 = New-AzStorageAccountManagementPolicyRule -Name "MediumLogRetentionBlockBlob" `
                -Action $action1 `
                -Filter $filter1

            $null = $rules.Add($rule1)
        }

        if (-Not $rule2)
        {
            $action2 = Add-AzStorageAccountManagementPolicyAction -BaseBlobAction Delete `
                -daysAfterModificationGreaterThan 180
            $null = Add-AzStorageAccountManagementPolicyAction -InputObject $action2 `
                -SnapshotAction Delete `
                -daysAfterCreationGreaterThan 60
            $null = Add-AzStorageAccountManagementPolicyAction -InputObject $action2 `
                -BlobVersionAction Delete `
                -daysAfterCreationGreaterThan 60

            $filter2 = New-AzStorageAccountManagementPolicyFilter -PrefixMatch "insights-activity","insights-metrics","bootdiagnostics" `
                -BlobType appendBlob
            $rule2 = New-AzStorageAccountManagementPolicyRule -Name "MediumLogRetentionAppendBlob" `
                -Action $action2 `
                -Filter $filter2
                
                $null = $rules.Add($rule2)
        }

        if (-Not $rule3)
        {
            $action3 = Add-AzStorageAccountManagementPolicyAction -BaseBlobAction Delete `
                -daysAfterModificationGreaterThan 730
            $null = Add-AzStorageAccountManagementPolicyAction -InputObject $action3 `
                -BaseBlobAction TierToArchive `
                -daysAfterModificationGreaterThan 180
            $null = Add-AzStorageAccountManagementPolicyAction -InputObject $action3 `
                -BaseBlobAction TierToCool `
                -daysAfterModificationGreaterThan 90
            $null = Add-AzStorageAccountManagementPolicyAction -InputObject $action3 `
                -SnapshotAction Delete `
                -daysAfterCreationGreaterThan 60
            $null = Add-AzStorageAccountManagementPolicyAction -InputObject $action3 `
                -BlobVersionAction TierToArchive `
                -daysAfterCreationGreaterThan 60

            $filter3 = New-AzStorageAccountManagementPolicyFilter -PrefixMatch "insights-logs" `
                -BlobType blockBlob
            $rule3 = New-AzStorageAccountManagementPolicyRule -Name "LongLogRetentionBlockBlob" `
                -Action $action3 `
                -Filter $filter3

            $null = $rules.Add($rule3)
        }

        if (-Not $rule4)
        {
            $action4 = Add-AzStorageAccountManagementPolicyAction -BaseBlobAction Delete `
                -daysAfterModificationGreaterThan 730
            $null = Add-AzStorageAccountManagementPolicyAction -InputObject $action4 `
                -SnapshotAction Delete `
                -daysAfterCreationGreaterThan 60
            $null = Add-AzStorageAccountManagementPolicyAction -InputObject $action4 `
                -BlobVersionAction Delete `
                -daysAfterCreationGreaterThan 60

            $filter4 = New-AzStorageAccountManagementPolicyFilter -PrefixMatch "insights-logs" `
                -BlobType appendBlob
            $rule4 = New-AzStorageAccountManagementPolicyRule -Name "LongLogRetentionAppendBlob" `
                -Action $action4 `
                -Filter $filter4
                
                $null = $rules.Add($rule4)
        }

        $null = Set-AzStorageAccountManagementPolicy `
            -ResourceGroupName  $StrgAccount.ResourceGroupName `
            -StorageAccountName $StrgAccount.StorageAccountName `
            -Rule $rules

    }

}

#Stopping Transscript
Stop-Transcript
