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
    13.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$HostPoolName = "alyainfphpol002"
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\prod\33_removeAllSessions-$($AlyaTimeString).log" | Out-Null

# Constants
$ErrorActionPreference = "Stop"
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
Write-Host "WVD | 33_removeAllSessions | AZURE" -ForegroundColor $CommandInfo
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

#Main
Write-Host "Removing user sessions" -ForegroundColor $CommandInfo
$hpool = Get-RdsHostPool -TenantName $AlyaWvdTenantNameProd -Name $HostPoolName
if ($hpool)
{
    $sessions = Get-RdsUserSession -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName
    foreach($session in $sessions)
    {
        Write-Host "Found session: $($session.UserPrincipalName). Logging out."
        Invoke-RdsUserSessionLogoff -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -SessionHostName $session.SessionHostName -SessionId $session.SessionId -NoUserPrompt
    }
}
else
{
    Write-Error "Hostpool not found!"
}

#Stopping Transscript
Stop-Transcript