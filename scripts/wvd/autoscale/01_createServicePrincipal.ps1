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
    21.04.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\autoscale\01_createServicePrincipal-$($AlyaTimeString).log" | Out-Null

# Constants
$RessourceGroupNames = @("$($AlyaNamingPrefix)resg051","$($AlyaNamingPrefixTest)resg051")
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 01_createServicePrincipal | AZURE" -ForegroundColor $CommandInfo
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
$AzureAdApplication = Get-AzADApplication -DisplayName $AlyaWvdAzureServicePrincipalName -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    Write-Warning -Message "Azure AD Application not found. Creating the Azure AD Application $AlyaWvdAzureServicePrincipalName"

    #Creating application and service principal
    $KeyId = [Guid]::NewGuid()
    $HomePageUrl = "https://portal.azure.com"
    $AzureAdApplication = New-AzADApplication -DisplayName $AlyaWvdAzureServicePrincipalName -HomePage $HomePageUrl -IdentifierUris ("http://" + $KeyId)
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
    $AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdAzureServicePrincipalName
}

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$AlyaWvdServicePrincipalAssetName = "$($AlyaWvdAzureServicePrincipalName)Key"
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


Write-Host "ApplicationId: $($AzureAdApplication.ApplicationId)"

#Stopping Transscript
Stop-Transcript