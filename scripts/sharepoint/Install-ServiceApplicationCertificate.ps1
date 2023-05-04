#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2019-2021

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
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Install-ServiceApplicationCertificate-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.KeyVault"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Install-ServiceApplicationCertificate | AZURE" -ForegroundColor $CommandInfo
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

# Checking azure key vault certificate
Write-Host "Checking azure key vault certificate" -ForegroundColor $CommandInfo
$AzureCertifcateAssetName = "SharePointRunAsCertificate"
$AzureCertificateName = $AzureCertifcateAssetName
$AzureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertificateName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultCertificate)
{
    Write-Warning "Key Vault certificate not found. Creating the certificate $AzureCertificateName"
    $NoOfMonthsUntilExpired = 120
    $AzureCertSubjectName = "CN=" + $AzureCertificateName
    $AzurePolicy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $AzureCertSubjectName  -IssuerName "Self" -ValidityInMonths $NoOfMonthsUntilExpired -ReuseKeyOnRenewal
    $AzureKeyVaultCertificateProgress = Add-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertificateName -CertificatePolicy $AzurePolicy
    While ($AzureKeyVaultCertificateProgress.Status -eq "inProgress")
    {
        Start-Sleep -s 10
        $AzureKeyVaultCertificateProgress = Get-AzKeyVaultCertificateOperation -VaultName $KeyVaultName -Name $AzureCertificateName
    }
    if ($AzureKeyVaultCertificateProgress.Status -ne "completed")
    {
        Write-Error "Key vault cert creation is not sucessfull and its status is: $(KeyVaultCertificateProgress.Status)" -ErrorAction Continue 
        Exit 2
    }
}

#Exporting certificate
Write-Host "Exporting certificate" -ForegroundColor $CommandInfo
$CompName = Make-PascalCase($AlyaCompanyNameShort)
$PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($CompName + $AzureCertificateName + ".pfx")
$PfxCertPlainPasswordForRunAsAccount = "`$" + [Guid]::NewGuid().ToString() + "!"
#Getting the certificate 
$CertificateRetrieved = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AzureCertificateName
$CertificateBytes = [System.Convert]::FromBase64String(($CertificateRetrieved.SecretValue | Foreach-Object { [System.Net.NetworkCredential]::new("", $_).Password }))
$CertCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
$CertCollection.Import($CertificateBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
#Export the .pfx file 
$ProtectedCertificateBytes = $CertCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $PfxCertPlainPasswordForRunAsAccount)
$CertPasswordForRunAsAccount = ConvertTo-SecureString $PfxCertPlainPasswordForRunAsAccount -AsPlainText -Force
Clear-Variable -Name "PfxCertPlainPasswordForRunAsAccount" -Force -ErrorAction SilentlyContinue
[System.IO.File]::WriteAllBytes($PfxCertPathForRunAsAccount, $ProtectedCertificateBytes)

try
{
    Import-PfxCertificate -CertStoreLocation "Cert:\LocalMachine\My" -FilePath $PfxCertPathForRunAsAccount -Password $CertPasswordForRunAsAccount -Exportable $true
    Write-Host "Certificate imported to Cert:\LocalMachine\My"
    Write-Host "Thumbprint: $($AzureKeyVaultCertificate.Thumbprint)"
}
finally
{
    Remove-Item -Path $PfxCertPathForRunAsAccount -Force | Out-Null
}

#Stopping Transscript
Stop-Transcript
