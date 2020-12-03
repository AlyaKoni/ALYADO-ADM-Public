#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2019, 2020

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
    Alya Basis Konfiguration ist Freie Software: Sie koennen es unter den
	Bedingungen der GNU General Public License, wie von der Free Software
	Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veroeffentlichten Version, weiter verteilen und/oder modifizieren.
    Alya Basis Konfiguration wird in der Hoffnung, dass es nuetzlich sein wird,
	aber OHNE JEDE GEWAEHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewaehrleistung der MARKTFAEHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
	https://www.gnu.org/licenses/gpl-3.0.txt

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    05.11.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Configure-ServiceUser-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "MSOnline"

# Logins
LoginTo-Msol
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Configure-ServiceUser | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Checking SharePoint service account" -ForegroundColor $CommandInfo
$CompName = Make-PascalCase($AlyaCompanyNameShort)
$SPUserName = "$($CompName)SharePointServiceUser@$($AlyaTenantName)"
$SPUser = Get-MsolUser -UserPrincipalName $SPUserName -ErrorAction SilentlyContinue
if (-Not $SPUser)
{
    Write-Warning "SharePoint service account not found. Creating the SharePoint service account $SPUserName"
    $SPUserPasswordForRunAsAccount = "$" + [Guid]::NewGuid().ToString() + "!"
    $SPUser = New-MsolUser -UserPrincipalName $SPUserName -DisplayName "$($CompName) SharePoint Service User" -FirstName "$($CompName) SharePoint" -LastName "Service User" -UsageLocation "CH" -PasswordNeverExpires $true -Password $SPUserPasswordForRunAsAccount -ForceChangePassword $False
}
Set-MsolUser -UserPrincipalName $SPUserName -PasswordNeverExpires $true

Write-Host "Checking SharePoint service account role membership" -ForegroundColor $CommandInfo
$SharePointRole = Get-MsolRole | where { $_.Name -like "SharePoint*" }
$RoleMember = Get-MsolRoleMember -RoleObjectId $SharePointRole.ObjectId -All | where { $_.ObjectId -eq $SPUser.ObjectId }
if (-Not $RoleMember)
{
    Write-Warning "SharePoint service account role membership not found. Creating the SharePoint service account role membership"
    $RoleMember = Add-MsolRoleMember -RoleObjectId $SharePointRole.ObjectId -RoleMemberObjectId $SPUser.ObjectId
}

Write-Host "Disable MFA for SharePoint service account" -ForegroundColor $CommandInfo
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
$GroupMember = Get-MsolGroupMember -GroupObjectId $NoMfaGroup.ObjectId -All | where { $_.ObjectId -eq $SPUser.ObjectId }
if (-Not $GroupMember)
{
    Write-Warning "SharePoint service account group membership not found. Creating the NoMfa group membership"
    $GroupMember = Add-MsolGroupMember -GroupObjectId $NoMfaGroup.ObjectId -GroupMemberObjectId $SPUser.ObjectId
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

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$SharePointCredentialAssetName = "$($CompName)SharePointServiceUserCredential"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SharePointCredentialAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    Write-Warning "Key Vault secret not found. Creating the secret $SharePointCredentialAssetName"
    if (-Not $SPUserPasswordForRunAsAccount)
    {
        $SPUserPasswordForRunAsAccountSave = Read-Host -Prompt "Please specify the $($CompName)SharePointServiceUser password" -AsSecureString
        $SPUserPasswordForRunAsAccount = (New-Object PSCredential "user",$SPUserPasswordForRunAsAccountSave).GetNetworkCredential().Password
    }
    else
    {
        $SPUserPasswordForRunAsAccountSave = ConvertTo-SecureString $SPUserPasswordForRunAsAccount -AsPlainText -Force
    }
    $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SharePointCredentialAssetName -SecretValue $SPUserPasswordForRunAsAccountSave
}
else
{
    $SPUserPasswordForRunAsAccount = ($AzureKeyVaultSecret.SecretValue | foreach { [System.Net.NetworkCredential]::new("", $_).Password })
}

#Stopping Transscript
Stop-Transcript