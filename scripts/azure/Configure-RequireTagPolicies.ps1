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
    21.08.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$requiredTagName = "ownerMail",
    [string]$includeResourceGroupsWithPartialName = "",
    [string]$excludeResourceGroupsWithPartialName = ""
)

# Loading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Configure-RequireTagPolicies-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Constants
$userAssignedIdentityResourceGroupName = "$($AlyaNamingPrefixTest)resg$($AlyaResIdMainInfra)"
$userAssignedIdentityName = "$($AlyaNamingPrefixTest)uaid$($AlyaResIdMainInfra)"
$md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
$utf8 = New-Object -TypeName System.Text.UTF8Encoding

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Infrastructure | Configure-RequireTagPolicies | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context) {
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking user assigned managed identity
Write-Host "Checking user assigned managed identity" -ForegroundColor $CommandInfo
$policyIdentity = Get-AzUserAssignedIdentity -ResourceGroupName $userAssignedIdentityResourceGroupName -Name $userAssignedIdentityName -ErrorAction SilentlyContinue
if (-Not $policyIdentity)
{
    $policyIdentity = New-AzUserAssignedIdentity -ResourceGroupName $userAssignedIdentityResourceGroupName -Name $userAssignedIdentityName -Location $AlyaLocation
}

# Processing subscriptions
foreach($AlyaSubscription in $AlyaAllSubscriptions) {
    Write-Host "Processing subscription $AlyaSubscription" -ForegroundColor $MenuColor
    $Context = Set-AzContext -SubscriptionName $AlyaSubscription
    if (-Not $Context) {
        Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
        Exit 1
    }
    
    # Checking resource provider Microsoft.PolicyInsights
    Write-Host "Checking resource provider Microsoft.PolicyInsights" -ForegroundColor $CommandInfo
    $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.PolicyInsights" -Location $AlyaLocation
    if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
    {
        Write-Warning "Resource provider Microsoft.PolicyInsights not registered. Registering now resource provider Microsoft.PolicyInsights"
        Register-AzResourceProvider -ProviderNamespace "Microsoft.PolicyInsights" | Out-Null
        do
        {
            Start-Sleep -Seconds 5
            $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.PolicyInsights" -Location $AlyaLocation
        } while ($resProv[0].RegistrationState -ne "Registered")
    }

    # Checking policy definitions
    Write-Host "Checking policy definitions" -ForegroundColor $CommandInfo
    $policies = Get-AzPolicyDefinition -Builtin
    $reqTagOnRg = $policies | Where-Object { $_.DisplayName -eq "Require a tag on resource groups" }
    if (-Not $reqTagOnRg)
    {
        throw "Policy definition nout found: Require a tag on resource groups"
    }
    $reqTagInh = $policies | Where-Object { $_.DisplayName -eq "Inherit a tag from the resource group if missing" }
    if (-Not $reqTagInh)
    {
        throw "Policy definition nout found: Inherit a tag from the resource group if missing"
    }

    # Checking policy 'Require an $requiredTagName tag on resource groups'
    Write-Host "Checking policy 'Require an $requiredTagName tag on resource groups'" -ForegroundColor $CommandInfo
    $reqTagOnRg = Get-AzPolicyAssignment -PolicyDefinitionId $reqTagOnRg.Id | Where-Object { $_.DisplayName -eq "$($AlyaSubscription.ToUpper()): Require an $requiredTagName tag on resource groups" }
    if (-Not $reqTagOnRg)
    {
        $tagName = @{"tagName"="$requiredTagName"}
        $reqTagOnRg = New-AzPolicyAssignment -Location $AlyaLocation -Scope "/subscriptions/$($Context.Subscription.Id)" -Name "$($AlyaSubscription)polowneronrg" -DisplayName "$($AlyaSubscription.ToUpper()): Require an $requiredTagName tag on resource groups" -PolicyDefinition $reqTagOnRg -PolicyParameterObject $tagName
    }

    # Checking policies 'Inherit the $requiredTagName tag from resource group'
    Write-Host "Checking policies 'Inherit the $requiredTagName tag from resource group'" -ForegroundColor $CommandInfo
    $rgs = Get-AzResourceGroup
    foreach($inhTagRg in $rgs)
    {
        # $inhTag = Get-AzPolicyAssignment -PolicyDefinitionId $reqTagInh.Id | Where-Object { $_.DisplayName -eq "$($AlyaSubscription.ToUpper()): RG $($inhTagRg.ResourceGroupName): Inherit the $requiredTagName tag from resource group" }
        # if ($inhTag)
        # {
        #     Remove-AzPolicyAssignment -Id $inhTag.Id
        # }
        if ([string]::IsNullOrEmpty($includeResourceGroupsWithPartialName) -or $inhTagRg.ResourceGroupName -like $includeResourceGroupsWithPartialName)
        {
            if ([string]::IsNullOrEmpty($excludeResourceGroupsWithPartialName) -or $inhTagRg.ResourceGroupName -notlike $excludeResourceGroupsWithPartialName)
            {
                Write-Host "RG: $($inhTagRg.ResourceGroupName)"
                $inhTag = Get-AzPolicyAssignment -PolicyDefinitionId $reqTagInh.Id | Where-Object { $_.DisplayName -eq "$($AlyaSubscription.ToUpper()): RG $($inhTagRg.ResourceGroupName): Inherit the $requiredTagName tag from resource group" }
                if (-Not $inhTag)
                {
                    $tagName = @{"tagName"="$requiredTagName"}
                    $nameHash = ([System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($inhTagRg.ResourceGroupName)))).replace("-","").ToLower()
                    $inhTag = New-AzPolicyAssignment -Location $AlyaLocation -Scope $inhTagRg.ResourceId -Name "$($AlyaSubscription)polownerinh$($nameHash)" -DisplayName "$($AlyaSubscription.ToUpper()): RG $($inhTagRg.ResourceGroupName): Inherit the $requiredTagName tag from resource group" -PolicyDefinition $reqTagInh -PolicyParameterObject $tagName -IdentityType "UserAssigned" -IdentityId $policyIdentity.Id
                }

                $json = @"
{
  "properties": {
    "resourceSelectors": [
      {
        "name": "ResourcesNotSupportingTags",
        "selectors": [
          {
            "in": null,
            "kind": "resourceType",
            "notIn": [ "Microsoft.Maintenance/maintenanceConfigurations","Microsoft.Compute/virtualMachines/extensions","Microsoft.HybridCompute/machines/licenseProfiles", "Microsoft.HybridCompute/machines/extensions" ]
          }
        ]
      }
    ]
  }
}
"@
                $res = Invoke-AzRestMethod -Method "Patch" -Path "$($inhTag.Id)?api-version=2024-04-01" -Payload $json
                if ($res.StatusCode -ge 400)
                {
                    Write-Error "Error updating assignment:" -ErrorAction Continue
                    Write-Error "$($res.Content)" -ErrorAction Continue
                }
                
            }
        }
    }

    # Checking user assigned identity subscription access
    Write-Host "Checking user assigned identity subscription access" -ForegroundColor $CommandInfo
    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Contributor" -PrincipalId $policyIdentity.PrincipalId -Scope "/subscriptions/$($Context.Subscription.Id)" -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq "/subscriptions/$($Context.Subscription.Id)" }
    $Retries = 0;
    While ($null -eq $RoleAssignment -and $Retries -le 6)
    {
        $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Contributor" -PrincipalId $policyIdentity.PrincipalId -Scope "/subscriptions/$($Context.Subscription.Id)" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 10
        $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Contributor" -PrincipalId $policyIdentity.PrincipalId -Scope "/subscriptions/$($Context.Subscription.Id)" -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq "/subscriptions/$($Context.Subscription.Id)" }
        $Retries++;
    }
    if ($Retries -gt 6)
    {
        throw "Was not able to set role assigment Contributor for user assigned identity $($policyIdentity.PrincipalId) on scope /subscriptions/$($Context.Subscription.Id)"
    }

}

Write-Host "Waiting 5 minutes for policy refresh"
Start-Sleep -Seconds 300

# Processing states for subscriptions
foreach($AlyaSubscription in $AlyaAllSubscriptions) {
    Write-Host "Processing states for subscription $AlyaSubscription" -ForegroundColor $MenuColor
    $Context = Set-AzContext -SubscriptionName $AlyaSubscription
    if (-Not $Context) {
        Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
        Exit 1
    }

    # Checking policy definitions
    Write-Host "Checking policy definitions" -ForegroundColor $CommandInfo
    $policies = Get-AzPolicyDefinition -Builtin
    $reqTagInh = $policies | Where-Object { $_.DisplayName -eq "Inherit a tag from the resource group if missing" }
    if (-Not $reqTagInh)
    {
        throw "Policy definition nout found: Inherit a tag from the resource group if missing"
    }

    # Checking policies 'Inherit the $requiredTagName tag from resource group'
    Write-Host "Checking policy states for 'Inherit the $requiredTagName tag from resource group'" -ForegroundColor $CommandInfo
    $states = Get-AzPolicyState -All
    $rgs = Get-AzResourceGroup
    foreach($inhTagRg in $rgs)
    {
        if ([string]::IsNullOrEmpty($includeResourceGroupsWithPartialName) -or $inhTagRg.ResourceGroupName -like $includeResourceGroupsWithPartialName)
        {
            if ([string]::IsNullOrEmpty($excludeResourceGroupsWithPartialName) -or $inhTagRg.ResourceGroupName -notlike $excludeResourceGroupsWithPartialName)
            {
                Write-Host "RG: $($inhTagRg.ResourceGroupName)"
                $inhTag = Get-AzPolicyAssignment -PolicyDefinitionId $reqTagInh.Id | Where-Object { $_.DisplayName -eq "$($AlyaSubscription.ToUpper()): RG $($inhTagRg.ResourceGroupName): Inherit the $requiredTagName tag from resource group" }
                if (-Not $inhTag)
                {
                    throw "Policy not found"
                }
                $remediationName = "rem-$($inhTag.Name)-$([Guid]::NewGuid())"
                $sts = $states | Where-Object { $_.PolicyAssignmentName -eq $inhTag.Name -and $_.ComplianceState -eq "NonCompliant" -and $_.PolicyDefinitionAction -eq "modify" }
                if ($sts -and $sts.Count -gt 0)
                {
                    Write-Host "  remediation $remediationName"
                    $rem = Start-AzPolicyRemediation -Name $remediationName -PolicyAssignmentId $inhTag.Id -Scope $inhTagRg.ResourceId
                }
            }
        }
    }

}

#Stopping Transscript
Stop-Transcript
