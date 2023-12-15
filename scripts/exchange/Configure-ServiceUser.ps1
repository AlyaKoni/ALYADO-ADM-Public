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
    05.12.2019 Konrad Brunner       Initial Version
    25.02.2020 Konrad Brunner       Changes for a project

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Configure-ServiceUser-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.KeyVault"
Install-ModuleIfNotInstalled "MSOnline"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MSOL

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Exchange | Configure-ServiceUser | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Checking Exchange service account" -ForegroundColor $CommandInfo
$CompName = Make-PascalCase($AlyaCompanyNameShort)
$ExchUserName = "$($CompName)ExchangeServiceUser@$($AlyaTenantName)"
$ExchUser = Get-MsolUser -UserPrincipalName $ExchUserName -ErrorAction SilentlyContinue
if (-Not $ExchUser)
{
    Write-Warning "Exchange service account not found. Creating the Exchange service account $ExchUserName"
    $ExchUserPasswordForRunAsAccount = "$" + [Guid]::NewGuid().ToString() + "!"
    $ExchUser = New-MsolUser -UserPrincipalName $ExchUserName -DisplayName "$($CompName) Exchange Service User" -FirstName "$($CompName) Exchange" -LastName "Service User" -UsageLocation "CH" -PasswordNeverExpires $true -Password $ExchUserPasswordForRunAsAccount -ForceChangePassword $False
}
Set-MsolUser -UserPrincipalName $ExchUserName -PasswordNeverExpires $true

Write-Host "Checking Exchange service account role membership" -ForegroundColor $CommandInfo
$ExchangeRole = Get-MsolRole | Where-Object { $_.Name -eq "Exchange Administrator" }
$RoleMember = Get-MsolRoleMember -RoleObjectId $ExchangeRole.ObjectId -All | Where-Object { $_.ObjectId -eq $ExchUser.ObjectId }
if (-Not $RoleMember)
{
    Write-Warning "Exchange service account role membership not found. Creating the Exchange service account role membership"
    $RoleMember = Add-MsolRoleMember -RoleObjectId $ExchangeRole.ObjectId -RoleMemberObjectId $ExchUser.ObjectId
}

Write-Host "Disable MFA for Exchange service account" -ForegroundColor $CommandInfo
if (-Not $AlyaMfaDisabledGroupName)
{
    $NoMfaGroupName = Read-Host -Prompt "Please specify NoMfaGroupName (Hit return for SGNOMFA)"
    if ([string]::IsNullOrEmpty($NoMfaGroupName))
    {
        $NoMfaGroupName = "SGNOMFA"
    }
}
else
{
    $NoMfaGroupName = $AlyaMfaDisabledGroupName
}
$NoMfaGroup = Get-MsolGroup -SearchString $NoMfaGroupName
if (-Not $NoMfaGroup)
{
    Write-Warning "No MFA group not found. Creating the No MFA group"
    $NoMfaGroup = New-MsolGroup -DisplayName $NoMfaGroupName -Description "MFA is disabled for members in this group"
}
$GroupMember = Get-MsolGroupMember -GroupObjectId $NoMfaGroup.ObjectId -All | Where-Object { $_.ObjectId -eq $ExchUser.ObjectId }
if (-Not $GroupMember)
{
    Write-Warning "Exchange service account group membership not found. Creating the NoMfa group membership"
    $GroupMember = Add-MsolGroupMember -GroupObjectId $NoMfaGroup.ObjectId -GroupMemberObjectId $ExchUser.ObjectId
}

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Azure | Configure-ServiceUser | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ResourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $ResourceGroupName -Location $AlyaLocation -Tag @{displayName="Main Infrastructure Services";ownerEmail=$Context.Account.Id}
}

# Checking key vault
Write-Host "Checking key vault" -ForegroundColor $CommandInfo
$KeyVault = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -ErrorAction SilentlyContinue
if (-Not $KeyVault)
{
    Write-Warning "Key Vault not found. Creating the Key Vault $KeyVaultName"
    $KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -Sku Standard -Tag @{displayName="Main Infrastructure Keyvault"}
    if (-Not $KeyVault)
    {
        Write-Error "Key Vault $KeyVaultName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Setting own key vault access
Write-Host "Setting own key vault access" -ForegroundColor $CommandInfo
$user = Get-AzAdUser -UserPrincipalName $Context.Account.Id
Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $user.Id -PermissionsToCertificates "All" -PermissionsToSecrets "All" -PermissionsToKeys "All" -PermissionsToStorage "All"

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$ExchangeCredentialAssetName = "$($CompName)ExchangeServiceUserCredential"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $ExchangeCredentialAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    Write-Warning "Key Vault secret not found. Creating the secret $ExchangeCredentialAssetName"
    if (-Not $ExchUserPasswordForRunAsAccount)
    {
        $ExchUserPasswordForRunAsAccountSave = Read-Host -Prompt "Please specify the $($CompName)ExchangeServiceUser password" -AsSecureString
        $ExchUserPasswordForRunAsAccount = (New-Object PSCredential "user",$ExchUserPasswordForRunAsAccountSave).GetNetworkCredential().Password
    }
    else
    {
        $ExchUserPasswordForRunAsAccountSave = ConvertTo-SecureString $ExchUserPasswordForRunAsAccount -AsPlainText -Force
    }
    $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $ExchangeCredentialAssetName -SecretValue $ExchUserPasswordForRunAsAccountSave
}
else
{
    $ExchUserPasswordForRunAsAccount = ($AzureKeyVaultSecret.SecretValue | Foreach-Object { [System.Net.NetworkCredential]::new("", $_).Password })
}

#Stopping Transscript
Stop-Transcript
