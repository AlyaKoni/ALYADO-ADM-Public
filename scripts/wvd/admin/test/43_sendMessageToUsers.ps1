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
    02.04.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$MessageBody = "Dies ist ein Test. Bitte schreibe ein E-Mail an konrad.brunner@alyaconsulting.ch, dass Du dieses Fesnter gesehen hast. Danke."
)
#$MessageBody = "Bitte vor dem nach Hause gehen alles speichern. Wir müssen heute Abend die Hosts neu starten. Nicht gespeicherte Arbeit geht verloren!"

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\test\43_sendMessageToUsers-$($AlyaTimeString).log" | Out-Null

# Constants
$ErrorActionPreference = "Stop"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$MessageTitle = "!WICHTIG! Windows Virtual Desktop !WICHTIG!"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# WVD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 43_sendMessageToUsers | WVD" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$AzureAdApplication = Get-AzADApplication -DisplayName $AlyaWvdServicePrincipalNameTest -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    throw "Azure AD Application not found. Please create the Azure AD Application $AlyaWvdServicePrincipalNameTest"
}
$AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdServicePrincipalNameTest

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$AlyaWvdServicePrincipalAssetName = "$($AlyaWvdServicePrincipalNameTest)Key"
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
Write-Host "Sending message" -ForegroundColor $CommandInfo
$tenants = Get-RdsTenant
foreach ($tenant in $tenants)
{
    Write-Host "* Tenant: $($tenant.TenantName)"

    $hpools = Get-RdsHostPool -TenantName $tenant.TenantName
    foreach ($hpool in $hpools)
    {
        Write-Host " + HostPool: $($hpool.HostPoolName)"
        $sessns = Get-RdsUserSession -TenantName $tenant.TenantName -HostPoolName $hpool.HostPoolName
        foreach ($sessn in $sessns)
        {
            #if ($sessn.UserPrincipalName -ne "adm_alya_kobr@alyaconsulting.ch") { continue  }
            Write-Host "   - Session: $($sessn.UserPrincipalName) on $($sessn.SessionHostName) $($sessn.SessionState)"
            Send-RdsUserSessionMessage -TenantName $tenant.TenantName -HostPoolName $hpool.HostPoolName -SessionHostName $sessn.SessionHostName -SessionId $sessn.SessionId -MessageTitle $MessageTitle -MessageBody $MessageBody
        }
    }
}

#Stopping Transscript
Stop-Transcript
