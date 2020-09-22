#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

    This unpublished material is proprietary to Alya Consulting.
    All rights reserved. The methods and techniques described
    herein are considered trade secrets and/or confidential. 
    Reproduction or distribution, in whole or in part, is 
    forbidden except by express written permission of Alya Consulting.

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    12.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\prod\20_assignUsersToGroups-$($AlyaTimeString).log" | Out-Null

# Constants
$appGrps = @(@("Desktop Application Group","$($AlyaNamingPrefixProd)hpol001",@("DSG_O365_App_Desktop")),`            @("Standard Apps","$($AlyaNamingPrefixProd)hpol002",@("DSG_O365_App_Standard")),`            @("Visio App","$($AlyaNamingPrefixProd)hpol002",@("DSG_O365_App_Visio")),`            @("Project App","$($AlyaNamingPrefixProd)hpol002",@("DSG_O365_App_Project")),`            @("Adobe Apps","$($AlyaNamingPrefixProd)hpol002",@("DSG_O365_App_Adobe")))
$allAdmins = @("adm_alya_kobr@alyaconsulting.ch", "adm_alya_kobr@alyaconsulting.ch")
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 11_createOrUpdateAppGroups_lmagtinfhpol001 | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error -Message "Can't get Az context! Not logged in?"
    Exit 1
}

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$AzureAdApplication = Get-AzADApplication -DisplayName $AlyaWvdServicePrincipalNameProd -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    throw "Azure AD Application not found. Please create the Azure AD Application $AlyaWvdServicePrincipalNameProd"
}
$AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdServicePrincipalNameProd

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$AlyaWvdServicePrincipalAssetName = "$($AlyaWvdServicePrincipalNameProd)Key"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AlyaWvdServicePrincipalAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    throw "Key Vault secret not found. Please create the secret $AlyaWvdServicePrincipalAssetName"
}
$AlyaWvdServicePrincipalPassword = $AzureKeyVaultSecret.SecretValueText
$AlyaWvdServicePrincipalPasswordSave = ConvertTo-SecureString $AlyaWvdServicePrincipalPassword -AsPlainText -Force

# Login to WVD
if (-Not $Global:RdsContext)
{
	Write-Host "Logging in to wvd" -ForegroundColor $CommandInfo
	$rdsCreds = New-Object System.Management.Automation.PSCredential($AzureAdServicePrincipal.ApplicationId, $AlyaWvdServicePrincipalPasswordSave)
	$Global:RdsContext = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $rdsCreds -ServicePrincipal -AadTenantId $AlyaTenantId
	#LoginTo-Wvd -AppId $AzureAdServicePrincipal.ApplicationId -SecPwd $AlyaWvdServicePrincipalPasswordSave
}

# Main
Write-Host "Assigning users to groups" -ForegroundColor $CommandInfo
foreach($appGrp in $appGrps)
{
    $appGrpName = $appGrp[0]
    $hostpoolName = $appGrp[1]
    Write-Host "App group $($appGrpName) on hostpool $($hostpoolName)"
    $accessToGrp = $appGrp[2]
    $appGrp = Get-RdsAppGroup -TenantName $AlyaWvdTenantNameProd -hostpoolName $hostpoolName -Name $appGrpName -ErrorAction SilentlyContinue
    if (-Not $appGrp)
    {
        Write-Host " - Adding app group $($appGrpName)"
        $appGrp = New-RdsAppGroup -TenantName $AlyaWvdTenantNameProd -hostpoolName $hostpoolName -Name $appGrpName
    }
    $grpUsers = Get-RdsAppGroupUser $AlyaWvdTenantNameProd $hostpoolName $appGrpName
    $allMembs = @()
    foreach ($admin in $allAdmins)
    {
        if (-Not $allMembs.Contains($admin))
        {
            $allMembs += $admin
        }
        $grpUser = $grpUsers | where { $_.UserPrincipalName -eq $admin }
        if (-Not $grpUser)
        {
            Write-Host "   - Adding admin $($admin)"
            Add-RdsAppGroupUser $AlyaWvdTenantNameProd $hostpoolName $appGrpName -UserPrincipalName $admin
        }
    }
    foreach ($accessGrp in $accessToGrp)
    {
        Write-Host " - Access for members of $($accessGrp)"
        $grp = Get-AzureADGroup -SearchString $accessGrp | Select-Object -First 1
        $membs = Get-AzureADGroupMember -ObjectId $grp.ObjectId -All:$true
        foreach ($memb in $membs)
        {
            if (-Not $allMembs.Contains($memb.UserPrincipalName))
            {
                $allMembs += $memb.UserPrincipalName
            }
            $grpUser = $grpUsers | where { $_.UserPrincipalName -eq $memb.UserPrincipalName }
            if (-Not $grpUser)
            {
                Write-Host "   - Adding user $($memb.UserPrincipalName)"
                Add-RdsAppGroupUser $AlyaWvdTenantNameProd $hostpoolName $appGrpName -UserPrincipalName $memb.UserPrincipalName
            }
        }
    }
    foreach ($grpUser in $grpUsers)
    {
        $memb = $allMembs | where { $_ -eq $grpUser.UserPrincipalName }
        if (-Not $memb)
        {
            Write-Host " - Removing user $($grpUser.UserPrincipalName)"
            Remove-RdsAppGroupUser $AlyaWvdTenantNameProd $hostpoolName $appGrpName -UserPrincipalName $grpUser.UserPrincipalName
        }
    }
}

#Stopping Transscript
Stop-Transcript
