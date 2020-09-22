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
    10.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\test\02_createServicePrincipal-$($AlyaTimeString).log" | Out-Null

# Constants
$RoleName = "RDS Owner"
$RessourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
#LoginTo-Wvd
if (-Not $Global:RdsContext)
{
    Write-Host "Login to WVD" -ForegroundColor $CommandInfo
    $Global:RdsContext = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker
}

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 02_createServicePrincipal | AZURE" -ForegroundColor $CommandInfo
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
$AzureAdApplication = Get-AzADApplication -DisplayName $AlyaWvdServicePrincipalNameTest -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    Write-Warning -Message "Azure AD Application not found. Creating the Azure AD Application $AlyaWvdServicePrincipalNameTest"

    #Creating application and service principal
    $KeyId = [Guid]::NewGuid()
    $HomePageUrl = $AlyaWvdRDBroker
    $AzureAdApplication = New-AzADApplication -DisplayName $AlyaWvdServicePrincipalNameTest -HomePage $HomePageUrl -IdentifierUris ("http://" + $KeyId)
    $AzureAdServicePrincipal = New-AzADServicePrincipal -ApplicationId $AzureAdApplication.ApplicationId

    #Create credential 
    $startDate = Get-Date
    $endDate = $startDate.AddYears(99)
    $AlyaWvdServicePrincipalPassword = "$" + [Guid]::NewGuid().ToString() + "!"
    $AlyaWvdServicePrincipalPasswordSave = ConvertTo-SecureString $AlyaWvdServicePrincipalPassword -AsPlainText -Force
    $AlyaWvdServicePrincipalSecret = New-AzADAppCredential -ApplicationId $AzureAdApplication.ApplicationId -StartDate $startDate -EndDate $endDate -Password $AlyaWvdServicePrincipalPasswordSave
}
else
{
    $AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdServicePrincipalNameTest
}

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$AlyaWvdServicePrincipalAssetName = "$($AlyaWvdServicePrincipalNameTest)Key"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AlyaWvdServicePrincipalAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    Write-Warning -Message "Key Vault secret not found. Creating the secret $AlyaWvdServicePrincipalAssetName"
    if (-Not $AlyaWvdServicePrincipalPasswordSave)
    {
        $AlyaWvdServicePrincipalPasswordSave = Read-Host -Prompt "Please specify the $($AlyaWvdServicePrincipalAssetName) password" -AsSecureString
        $AlyaWvdServicePrincipalPassword = (New-Object PSCredential $AlyaWvdServicePrincipalAssetName,$AlyaWvdServicePrincipalPasswordSave).GetNetworkCredential().Password
    }
    $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AlyaWvdServicePrincipalAssetName -SecretValue $AlyaWvdServicePrincipalPasswordSave
}
else
{
    $AlyaWvdServicePrincipalPassword = $AzureKeyVaultSecret.SecretValueText
    $AlyaWvdServicePrincipalPasswordSave = ConvertTo-SecureString $AlyaWvdServicePrincipalPassword -AsPlainText -Force
}

# Checking rds role assignment
Write-Host "Checking rds role assignment" -ForegroundColor $CommandInfo
$RoleAss = Get-RdsRoleAssignment -TenantGroupName $AlyaWvdTenantGroupName -TenantName $AlyaWvdTenantNameTest -ServicePrincipalName $AzureAdServicePrincipal.ApplicationId
if (-Not $RoleAss)
{
    Write-Warning -Message "Role assignment not found. Creating the role assignment for $AlyaWvdServicePrincipalNameTest"
    $RoleAss = New-RdsRoleAssignment -RoleDefinitionName $RoleName -ApplicationId $AzureAdServicePrincipal.ApplicationId -TenantGroupName $AlyaWvdTenantGroupName -TenantName $AlyaWvdTenantNameTest
}

#Testing login
Write-Host "Waiting 30 seconds to prevent from errors ..."
Start-Sleep -Seconds 30
Write-Host "Testing login with service principal" -ForegroundColor $CommandInfo
$creds = New-Object System.Management.Automation.PSCredential($AzureAdServicePrincipal.ApplicationId, $AlyaWvdServicePrincipalPasswordSave)
Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $creds -ServicePrincipal -AadTenantId $AlyaTenantId -ErrorAction Stop

#Stopping Transscript
Stop-Transcript