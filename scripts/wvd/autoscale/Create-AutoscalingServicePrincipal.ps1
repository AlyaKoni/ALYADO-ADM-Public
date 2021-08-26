#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2021

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
    21.04.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\autoscale\Create-AutoscalingServicePrincipal-$($AlyaTimeString).log" | Out-Null

# Constants
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
Write-Host "WVD Autoscaling | Create-AutoscalingServicePrincipal | AZURE" -ForegroundColor $CommandInfo
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
$AzureAdApplication = Get-AzADApplication -DisplayName $AlyaWvdAzureServicePrincipalName -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    Write-Warning "Azure AD Application not found. Creating the Azure AD Application $AlyaWvdAzureServicePrincipalName"

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
Clear-Variable -Name AlyaWvdServicePrincipalPassword -Force
Clear-Variable -Name AzureKeyVaultSecret -Force


Write-Host "ApplicationId: $($AzureAdApplication.ApplicationId)"

#Stopping Transscript
Stop-Transcript