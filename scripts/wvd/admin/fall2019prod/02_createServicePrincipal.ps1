﻿#Requires -Version 2.0

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
    10.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\fall2019prod\02_createServicePrincipal-$($AlyaTimeString).log" | Out-Null

# Constants
$RoleName = "RDS Owner"
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.KeyVault"
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
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$AzureAdApplication = Get-AzADApplication -DisplayName $AlyaWvdServicePrincipalNameProd -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    Write-Warning "Azure AD Application not found. Creating the Azure AD Application $AlyaWvdServicePrincipalNameProd"

    #Creating application and service principal
    $KeyId = [Guid]::NewGuid()
    $HomePageUrl = $AlyaWvdRDBroker
    $AzureAdApplication = New-AzADApplication -DisplayName $AlyaWvdServicePrincipalNameProd -HomePage $HomePageUrl -IdentifierUris ("http://" + $KeyId)
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
    $AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdServicePrincipalNameProd
}

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$AlyaWvdServicePrincipalAssetName = "$($AlyaWvdServicePrincipalNameProd)Key"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AlyaWvdServicePrincipalAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    Write-Warning "Key Vault secret not found. Creating the secret $AlyaWvdServicePrincipalAssetName"
    if (-Not $AlyaWvdServicePrincipalPasswordSave)
    {
        $AlyaWvdServicePrincipalPasswordSave = Read-Host -Prompt "Please specify the $($AlyaWvdServicePrincipalAssetName) password" -AsSecureString
        $AlyaWvdServicePrincipalPassword = (New-Object PSCredential $AlyaWvdServicePrincipalAssetName,$AlyaWvdServicePrincipalPasswordSave).GetNetworkCredential().Password
    }
    $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AlyaWvdServicePrincipalAssetName -SecretValue $AlyaWvdServicePrincipalPasswordSave
}
else
{
    $AlyaWvdServicePrincipalPasswordSave = $AzureKeyVaultSecret.SecretValue
}
Clear-Variable -Name AlyaWvdServicePrincipalPassword -Force -ErrorAction SilentlyContinue
Clear-Variable -Name AzureKeyVaultSecret -Force -ErrorAction SilentlyContinue

# Checking rds role assignment
Write-Host "Checking rds role assignment" -ForegroundColor $CommandInfo
$RoleAss = Get-RdsRoleAssignment -TenantGroupName $AlyaWvdTenantGroupName -TenantName $AlyaWvdTenantNameProd -ServicePrincipalName $AzureAdServicePrincipal.AppId
if (-Not $RoleAss)
{
    Write-Warning "Role assignment not found. Creating the role assignment for $AlyaWvdServicePrincipalNameProd"
    $RoleAss = New-RdsRoleAssignment -RoleDefinitionName $RoleName -ApplicationId $AzureAdServicePrincipal.AppId -TenantGroupName $AlyaWvdTenantGroupName -TenantName $AlyaWvdTenantNameProd
}

#Testing login
Write-Host "Waiting 30 seconds to prevent from errors ..."
Start-Sleep -Seconds 30
Write-Host "Testing login with service principal" -ForegroundColor $CommandInfo
$creds = New-Object System.Management.Automation.PSCredential($AzureAdServicePrincipal.AppId, $AlyaWvdServicePrincipalPasswordSave)
Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $creds -ServicePrincipal -AadTenantId $AlyaTenantId -ErrorAction Stop

#Stopping Transscript
Stop-Transcript
