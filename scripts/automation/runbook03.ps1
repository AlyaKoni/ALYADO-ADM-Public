#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019

    This file is part of the Alya Base Configuration.
    The Alya Base Configuration is free software: you can redistribute it
	and/or modify it under the terms of the GNU General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
	Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
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
    14.11.2019 Konrad Brunner       Initial Version

#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseApprovedVerbs", "")]
param(
    [Parameter(Mandatory = $true)]
    [string] $SubscriptionName,

    [Parameter(Mandatory = $true)]
    [string] $ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string] $AutomationAccountName,

    [Parameter(Mandatory=$false)]
    [string] $AzureEnvironment = 'AzureCloud'
)
$ErrorActionPreference = "Stop"

<#

    1. Add the RunAs service principal as an owner of the application created during Automation Account creation. You can get the application
    id from the RunAs page in the Automation account and run the following commands locally after installly the AzureAD module from the PowerShellGallery.
    Connect-AzureAD
    $Application = Get-AzureADApplication -Filter "AppId eq '123456789'"
    $ServicePrincipal = Get-AzureADServicePrincipal -Filter "AppId eq '123456789'"
    Add-AzureADApplicationOwner -ObjectId $Application.ObjectId -RefObjectId $ServicePrincipal.ObjectId
    2. Grant permissions to the Application to be able to update itself. Go to Azure AD in the portal and search for the RunAs application
    in the App Registrations page (select all apps). 
    3. Select the application and click Settings button -> Required Permissions -> Add button
    Add the "Manage apps that this app creates or owns" permission from Windows Azure Active Directory.
    4. Select Grant permissions (You may need to be an administrator in Azure AD to be able to perform this task).

#>

# Constants
$RunAsConnectionName = "AzureRunAsConnection"
$RunAsCertificateName = "AzureRunAsCertificate"
$ConnectionTypeName = "AzureServicePrincipal"

# Login-AzureAutomation
try {
    $RunAsConnection = Get-AutomationConnection -Name $RunAsConnectionName
    Write-Output "Logging in to AzureRm ($AzureEnvironment)..."
    Add-AzureRmAccount `
        -ServicePrincipal `
        -TenantId $RunAsConnection.TenantId `
        -ApplicationId $RunAsConnection.ApplicationId `
        -CertificateThumbprint $RunAsConnection.CertificateThumbprint `
        -Environment $AzureEnvironment
    Select-AzureRmSubscription -Subscription $SubscriptionName  | Write-Verbose
    $Context = Get-AzureRmContext
} catch {
    if (!$RunAsConnection) {
        Write-Output $RunAsConnectionName
        Write-Output $_.Exception | ConvertTo-Json
        Write-Output "Connection $RunAsConnectionName not found."
    }
    throw
}

# Check AzureAutomationCertificate
$RunAsCert = Get-AutomationCertificate -Name $RunAsCertificateName
if ($RunAsCert.NotAfter -gt (Get-Date).AddMonths(2))
{
    Write-Output ("Certificate will expire at " + $RunAsCert.NotAfter)
    Write-Output ("Nothing to do!")
    Exit(0)
}

# Check AzureAD module if it is not in the Automation account.
$ADModule = Get-AzureRMAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
                         -Name "AzureAD" -AzureRmContext $Context -ErrorAction SilentlyContinue
if ([string]::IsNullOrEmpty($ADModule))
{
    $ADModule = Get-AzureRMAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
                            -Name "AzureADPreview" -AzureRmContext $Context -ErrorAction SilentlyContinue
    if ([string]::IsNullOrEmpty($ADModule))
    {
        $ErrorMessage = "Missing AzureAd module."
        throw $ErrorMessage
    }
}

# Connect to Azure AD to manage the application
Write-Output "Logging in to AzureAd..."
Connect-AzureAD `
    -TenantId $RunAsConnection.TenantId `
    -ApplicationId $RunAsConnection.ApplicationId `
    -CertificateThumbprint $RunAsConnection.CertificateThumbprint

# Find the application
$Filter = "AppId eq '" + $RunasConnection.ApplicationId + "'"
$Application = Get-AzureADApplication -Filter $Filter 

# Create RunAs certificate
Write-Output ("Creating new certificate")
$SelfSignedCertNoOfMonthsUntilExpired = 12
$SelfSignedCertPlainPassword = (New-Guid).Guid
$CertificateName = $AutomationAccountName + $RunAsCertificateName
$PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".pfx")
$CerCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".cer")
$Cert = New-SelfSignedCertificate -DnsName $CertificateName -CertStoreLocation Cert:\LocalMachine\My `
                    -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
                    -NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddMonths($SelfSignedCertNoOfMonthsUntilExpired) -HashAlgorithm SHA256
$CertPassword = ConvertTo-SecureString $SelfSignedCertPlainPassword -AsPlainText -Force
Export-PfxCertificate -Cert ("Cert:\LocalMachine\My\" + $Cert.Thumbprint) -FilePath $PfxCertPathForRunAsAccount -Password $CertPassword -Force | Write-Verbose
Export-Certificate -Cert ("Cert:\LocalMachine\My\" + $Cert.Thumbprint) -FilePath $CerCertPathForRunAsAccount -Type CERT | Write-Verbose

# Add new certificate to application
New-AzureADApplicationKeyCredential -ObjectId $Application.ObjectId -CustomKeyIdentifier ([System.Convert]::ToBase64String($Cert.GetCertHash())) `
         -Type AsymmetricX509Cert -Usage Verify -Value ([System.Convert]::ToBase64String($Cert.GetRawCertData())) -StartDate $Cert.NotBefore -EndDate $Cert.NotAfter | Write-Verbose

# Update the certificate with the new one in the Automation account
Set-AzureRmAutomationCertificate -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $PfxCertPathForRunAsAccount -Name $RunAsCertificateName `
             -Password $CertPassword -Exportable:$true -AzureRmContext $Context | Write-Verbose

# Update the RunAs connection with the new certificate information
$ConnectionFieldValues = @{"ApplicationId" = $RunasConnection.ApplicationId ; "TenantId" = $RunAsConnection.TenantId; "CertificateThumbprint" = $Cert.Thumbprint; "SubscriptionId" = $RunAsConnection.SubscriptionId }

# Can't just update the thumbprint value due to bug https://github.com/Azure/azure-powershell/issues/5862 so deleting / creating connection 
Remove-AzureRmAutomationConnection -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunAsConnectionName -Force
New-AzureRMAutomationConnection -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunAsConnectionName `
              -ConnectionFieldValues $ConnectionFieldValues -ConnectionTypeName $ConnectionTypeName -AzureRmContext $Context | Write-Verbose

Write-Output ("RunAs certificate credentials have been updated")

