#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2022

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
    11.02.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\automation\Fix-AutomationCertificate-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Constants
$RunAsConnectionName = "AzureRunAsConnection"
$RunAsCertificateName = "AzureRunAsCertificate"
$ConnectionTypeName = "AzureServicePrincipal"
$AzureCertificateName = $AutomationAccountName + $RunAsCertificateName
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAutomation)"
$AutomationAccountName = "$($AlyaNamingPrefix)aacc$($AlyaResIdAutomationAccount)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Automation | Fix-AutomationCertificate | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Find the application
Write-Output ("Getting application $($ApplicationId)")
$Application = Get-AzADApplication -DisplayName $AutomationAccountName
if (-Not $Application) { throw "Application with name $($AutomationAccountName) not found" }

# Create RunAs certificate
Write-Output ("Creating new certificate")
$SelfSignedCertNoOfMonthsUntilExpired = 6
$SelfSignedCertPlainPassword = "-"+[Guid]::NewGuid().ToString()+"]"
$PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($AzureCertificateName + ".pfx")
$CertPassword = ConvertTo-SecureString $SelfSignedCertPlainPassword -AsPlainText -Force
Clear-Variable -Name "SelfSignedCertPlainPassword" -Force -ErrorAction SilentlyContinue
$Cert = New-SelfSignedCertificate -Subject "CN=$AzureCertificateName" -CertStoreLocation Cert:\CurrentUser\My `
					-KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
					-NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddMonths($SelfSignedCertNoOfMonthsUntilExpired) -HashAlgorithm SHA256
Export-PfxCertificate -Cert ("Cert:\CurrentUser\My\" + $Cert.Thumbprint) -FilePath $PfxCertPathForRunAsAccount -Password $CertPassword -Force | Write-Verbose
$CerKeyValue = [System.Convert]::ToBase64String($Cert.GetRawCertData())
$CerThumbprint = [System.Convert]::ToBase64String($Cert.GetCertHash())
$CerThumbprintString = $Cert.Thumbprint
$CerStartDate = $Cert.NotBefore
$CerEndDate = $Cert.NotAfter

# Update the certificate in the Automation account with the new one 
Write-Output ("Updating automation account certificate")
Set-AzAutomationCertificate -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $PfxCertPathForRunAsAccount -Name $RunAsCertificateName `
				-Password $CertPassword -Exportable:$true

# Update the RunAs connection with the new certificate information
Write-Output ("Updating automation account connection")
$TenantId = $Context.Tenant.Id
$SubscriptionId = $Context.Subscription.Id
$ConnectionFieldValues = @{"ApplicationId" = $Application.AppId ; "TenantId" = $TenantId; "CertificateThumbprint" = $CerThumbprintString; "SubscriptionId" = $SubscriptionId }
# Can't just update the thumbprint value due to bug https://github.com/Azure/azure-powershell/issues/5862 so deleting / creating connection 
Remove-AzAutomationConnection -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunAsConnectionName -Force
New-AzAutomationConnection -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunAsConnectionName `
				-ConnectionFieldValues $ConnectionFieldValues -ConnectionTypeName $ConnectionTypeName | Write-Verbose

# Add new certificate to application
Write-Output ("Adding new certificate to application")
$payload = @"
{
  "keyCredentials": [{
    "@odata.type": "microsoft.graph.keyCredential",
    "customKeyIdentifier": "$CerThumbprint",
    "key": "$CerKeyValue",
    "keyId": "$([System.Guid]::NewGuid().ToString())",
    "type": "AsymmetricX509Cert",
    "usage": "Verify",
    "startDateTime": "$($CerStartDate.ToString("o"))",
    "endDateTime": "$($CerEndDate.ToString("o"))"
  }]
}
"@
Invoke-AzRestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$($Application.Id)" -Method PATCH -Payload $payload

#Stopping Transscript
Stop-Transcript