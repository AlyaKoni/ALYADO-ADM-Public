#Requires -Version 2.0

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
    14.11.2019 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    $UpdateRunbooks = $true
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\automation\Create-AutomationAccount-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAutomation)"
$AutomationAccountName = "$($AlyaNamingPrefix)aacc$($AlyaResIdAutomationAccount)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$KeyVaultResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$SubscriptionNames = @($AlyaSubscriptionName)
$SolutionScriptsRoot = "$($AlyaScripts)\automation"
$SolutionDataRoot = "$($AlyaData)\automation"
if (-Not (Test-Path $SolutionDataRoot))
{
    $tmp = New-Item -Path $SolutionDataRoot -ItemType Directory -Force
}
if ($AlyaSubscriptionNameTest -and $AlyaSubscriptionNameTest -ne $AlyaSubscriptionName)
{
    $SubscriptionNames += $AlyaSubscriptionNameTest
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.KeyVault"
Install-ModuleIfNotInstalled "Az.Automation"
Install-ModuleIfNotInstalled "AzureAdPreview"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Automation | Create-AutomationAccount | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking resource provider registration
Write-Host "Checking resource provider registration Microsoft.KeyVault" -ForegroundColor $CommandInfo
$resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.KeyVault" -Location $AlyaLocation
if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
{
    Write-Warning "Resource provider Microsoft.KeyVault not registered. Registering now resource provider Microsoft.KeyVault"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.KeyVault" | Out-Null
    do
    {
        Start-Sleep -Seconds 5
        $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.KeyVault" -Location $AlyaLocation
    } while ($resProv[0].RegistrationState -ne "Registered")
}

# Checking resource provider registration
Write-Host "Checking resource provider registration Microsoft.Automation" -ForegroundColor $CommandInfo
$resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Automation" -Location $AlyaLocation
if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
{
    Write-Warning "Resource provider Microsoft.Automation not registered. Registering now resource provider Microsoft.Automation"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Automation" | Out-Null
    do
    {
        Start-Sleep -Seconds 5
        $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Automation" -Location $AlyaLocation
    } while ($resProv[0].RegistrationState -ne "Registered")
}

# Checking resource provider registration
Write-Host "Checking resource provider registration Microsoft.Insights" -ForegroundColor $CommandInfo
$resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Insights" -Location $AlyaLocation
if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
{
    Write-Warning "Resource provider Microsoft.Insights not registered. Registering now resource provider Microsoft.Insights"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Insights" | Out-Null
    do
    {
        Start-Sleep -Seconds 5
        $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Insights" -Location $AlyaLocation
    } while ($resProv[0].RegistrationState -ne "Registered")
}

# Checking subscriptions
Write-Host "Checking subscriptions" -ForegroundColor $CommandInfo
$Subscriptions = ""
foreach ($SubscriptionName in $SubscriptionNames)
{
    $Subs = Get-AzSubscription -SubscriptionName $SubscriptionName
    $Subscriptions += $Subs.SubscriptionId + ","
}
$Subscriptions = $Subscriptions.TrimEnd(",")

# Checking ressource group
Write-Host "Checking ressource group for automation account" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ResourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $ResourceGroupName -Location $AlyaLocation -Tag @{displayName="Automation";ownerEmail=$Context.Account.Id}
}

# Checking KeyVault ressource group
Write-Host "Checking KeyVault ressource group for keyvault" -ForegroundColor $CommandInfo
$ResGrpKeyVault = Get-AzResourceGroup -Name $KeyVaultResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrpKeyVault)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $KeyVaultResourceGroupName"
    $ResGrpKeyVault = New-AzResourceGroup -Name $KeyVaultResourceGroupName -Location $AlyaLocation -Tag @{displayName="Main Infrastructure Services";ownerEmail=$Context.Account.Id}
}

# Checking key vault
Write-Host "Checking key vault" -ForegroundColor $CommandInfo
$KeyVault = Get-AzKeyVault -ResourceGroupName $KeyVaultResourceGroupName -VaultName $KeyVaultName -ErrorAction SilentlyContinue
if (-Not $KeyVault)
{
    Write-Warning "Key Vault not found. Creating the Key Vault $KeyVaultName"
    $KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $KeyVaultResourceGroupName -Location $AlyaLocation -Sku Standard -Tag @{displayName="Main Infrastructure Keyvault"}
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
$AzureCertifcateAssetName = "AzureRunAsCertificate"
$AzureCertificateName = $AutomationAccountName + $AzureCertifcateAssetName
$AzureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertificateName -ErrorAction SilentlyContinue
if ($AzureKeyVaultCertificate)
{
    if ($AzureKeyVaultCertificate.Expires -lt (Get-Date).AddHours(-1))
    {
        Write-Host "  Certificate in key vault has expired. Updating"
        $AzureKeyVaultCertificate = $null
    }
}
if (-Not $AzureKeyVaultCertificate)
{
    Write-Warning "Key Vault certificate not found. Creating the certificate $AzureCertificateName"
    $NoOfMonthsUntilExpired = 3
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

try
{

    #Exporting certificate
    Write-Host "Exporting certificate" -ForegroundColor $CommandInfo
    $PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($AzureCertificateName + ".pfx")
    $PfxCertPlainPasswordForRunAsAccount = [Guid]::NewGuid().ToString().Substring(0, 8) + "!"
    $CerCertPathForRunAsAccount = Join-Path $env:TEMP ($AzureCertificateName + ".cer")
    #Getting the certificate 
    $CertificateRetrieved = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AzureCertificateName
    $CertificateBytes = [System.Convert]::FromBase64String(($CertificateRetrieved.SecretValue | foreach { [System.Net.NetworkCredential]::new("", $_).Password }))
    $CertCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $CertCollection.Import($CertificateBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    #Export the .pfx file 
    $ProtectedCertificateBytes = $CertCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $PfxCertPlainPasswordForRunAsAccount)
    [System.IO.File]::WriteAllBytes($PfxCertPathForRunAsAccount, $ProtectedCertificateBytes)
    #Export the .cer file 
    #$CertificateRetrieved = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertificateName
    #$CertificateBytes = $CertificateRetrieved.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    #[System.IO.File]::WriteAllBytes($CerCertPathForRunAsAccount, $CertificateBytes)
    #Read the .pfx file 
    $PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)
    $KeyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())
    $CerThumbprint = [System.Convert]::ToBase64String($PfxCert.GetCertHash())
    $CerThumbprintString = $PfxCert.Thumbprint
    $startDate = $PfxCert.NotBefore
    $endDate = $PfxCert.NotAfter

    # Checking automation account
    Write-Host "Checking automation account" -ForegroundColor $CommandInfo
    $AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
    if (-Not $AutomationAccount)
    {
        Write-Warning "Automation Account not found. Creating the Automation Account $AutomationAccountName"
        $AutomationAccount = New-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -Location $AlyaLocation
    }

    # Checking application
    Write-Host "Checking application" -ForegroundColor $CommandInfo
    $AzureAdApplication = Get-AzADApplication -DisplayName $AutomationAccountName -ErrorAction SilentlyContinue
    if (-Not $AzureAdApplication)
    {
        Write-Warning "Azure AD Application not found. Creating the Azure AD Application $AutomationAccountName"

        #Creating application and service principal
        $KeyId = [Guid]::NewGuid()
        $HomePageUrl = "https://management.azure.com/subscriptions/$($Context.Subscription.Id)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.Automation/automationAccounts/$($AutomationAccountName)"
        $AzureAdApplication = New-AzADApplication -DisplayName $AutomationAccountName -HomePage $HomePageUrl -IdentifierUris ("http://$AlyaDomainName/$KeyId")
        $AzureAdServicePrincipal = New-AzADServicePrincipal -ApplicationId $AzureAdApplication.AppId

        #Create credential 
        $AzureAdApplicationCredential = New-AzADAppCredential -ApplicationId $AzureAdApplication.AppId -CustomKeyIdentifier $CerThumbprint -CertValue $KeyValue -StartDate $startDate -EndDate $endDate 

        #Application access rights
        $RoleAssignment = $null
        $Retries = 0;
        While ($RoleAssignment -eq $null -and $Retries -le 6)
        {
            $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $AzureAdApplication.AppId -scope ("/subscriptions/" + $Context.Subscription.Id) -ErrorAction SilentlyContinue
            Start-Sleep -s 10
            $RoleAssignment = Get-AzRoleAssignment -ServicePrincipalName $AzureAdApplication.AppId -ErrorAction SilentlyContinue
            $Retries++;
        }

        #Setting its own as owner (required for automated cert updates)
        $AdAzureAdApplication = Get-AzureADApplication -Filter "AppId eq '$($AzureAdApplication.AppId)'"
        $AdAzureAdServicePrincipal = Get-AzureADServicePrincipal -Filter "AppId eq '$($AzureAdApplication.AppId)'"
        Add-AzureADApplicationOwner -ObjectId $AdAzureAdApplication.ObjectId -RefObjectId $AdAzureAdServicePrincipal.ObjectId

        #Granting permissions
        $AppPermissionMsGraph = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "18a4783c-866b-4cc7-a460-3d5e5662c884","Role"
        $RequiredResourceAccessMsGraph = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
        $RequiredResourceAccessMsGraph.ResourceAppId = "00000003-0000-0000-c000-000000000000"
        $RequiredResourceAccessMsGraph.ResourceAccess = $AppPermissionMsGraph

        Set-AzureADApplication -ObjectId $AdAzureAdApplication.ObjectId -RequiredResourceAccess $RequiredResourceAccessMsGraph
        $tmp = Get-AzureADApplication -ObjectId $AdAzureAdApplication.ObjectId
        while ($tmp.RequiredResourceAccess.Count -lt 1)
        {
            Start-Sleep -Seconds 10
            $tmp = Get-AzureADApplication -ObjectId $AdAzureAdApplication.ObjectId
        }
        Start-Sleep -Seconds 60 # Looks like there is some time issue for admin consent #TODO 60 seconds enough

        <#To check existing permissions
        $tmp.RequiredResourceAccess
        ($tmp.RequiredResourceAccess | where { $_.ResourceAppId -eq '00000003-0000-0ff1-ce00-000000000000'}).ResourceAccess
        ($tmp.RequiredResourceAccess | where { $_.ResourceAppId -eq '00000003-0000-0000-c000-000000000000'}).ResourceAccess
        ($tmp.RequiredResourceAccess | where { $_.ResourceAppId -eq '00000002-0000-0000-c000-000000000000'}).ResourceAccess
        $tmp.RequiredResourceAccess.ResourceAppId
        $tmp.RequiredResourceAccess.ResourceAccess
        #>

        #Admin consent
        $apiToken = Get-AzAccessToken
        if (-Not $apiToken)
        {
            Write-Warning "Can't aquire an access token. Please give admin consent to application '$($AutomationAccountName)' in the portal!"
            pause
        }
        else
        {
            $header = @{'Authorization'='Bearer '+$apiToken;'X-Requested-With'='XMLHttpRequest';'x-ms-client-request-id'=[guid]::NewGuid();'x-ms-correlation-id'=[guid]::NewGuid();}
            $url = "https://main.iam.ad.ext.azure.com/api/RegisteredApplications/$($AzureAdApplication.AppId)/Consent?onBehalfOfAll=true"
            Invoke-RestMethod -Uri $url -Headers $header -Method POST -ErrorAction Stop
            #TODO consent was working?
            Write-Warning "Please check in portal if admin consent was working"
        }
    }
    else
    {
        $AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AutomationAccountName
    }

    # Checking application credential
    Write-Host "Checking application credential" -ForegroundColor $CommandInfo
    $AppCredential = Get-AzADAppCredential -ApplicationId $AzureAdApplication.AppId -ErrorAction SilentlyContinue
    if (-Not $AppCredential)
    {
        Write-Host "  Not found" -ForegroundColor $CommandWarning
        $AzureAdApplicationCredential = New-AzADAppCredential -ApplicationId $AzureAdApplication.AppId -CustomKeyIdentifier $CerThumbprint -CertValue $CerKeyValue -StartDate $CerStartDate -EndDate $CerEndDate 
    }
    else
    {
        if ([System.Convert]::ToBase64String($AppCredential.CustomKeyIdentifier) -ne $CerThumbprint)
        {
            Write-Host "  Updating"
            Remove-AzADAppCredential -ObjectId $AzureAdApplication.Id -KeyId $AppCredential.KeyId
            $AzureAdApplicationCredential = New-AzADAppCredential -ApplicationId $AzureAdApplication.AppId -CustomKeyIdentifier $CerThumbprint -CertValue $CerKeyValue -StartDate $CerStartDate -EndDate $CerEndDate 
        }
    }
    #Remove-AzAutomationCertificate -ResourceGroupName -ResourceGroupName $AlyaAutomationResourceGroupName -AutomationAccountName $AlyaAutomationAccountName -Name $AzureCertifcateAssetName -ErrorAction SilentlyContinue

    # Checking automation certificate asset
    Write-Host "Checking automation certificate asset" -ForegroundColor $CommandInfo
    $AutomationCertificate = Get-AzAutomationCertificate -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $AzureCertifcateAssetName -ErrorAction SilentlyContinue
    $CertPassword = ConvertTo-SecureString $PfxCertPlainPasswordForRunAsAccount -AsPlainText -Force
    if (-Not $AutomationCertificate)
    {
        Write-Warning "Automation Certificate not found. Creating the Automation Certificate $AzureCertifcateAssetName"
        New-AzAutomationCertificate -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $AzureCertifcateAssetName -Path $PfxCertPathForRunAsAccount -Password $CertPassword -Exportable:$true
    }
    else
    {
        if ($AutomationCertificate.Thumbprint -ne $CerThumbprintString)
        {
            Write-Host "  Updating"
	        Set-AzAutomationCertificate -ResourceGroupName $ResourceGroupName `
                -AutomationAccountName $AutomationAccountName -Name $AzureCertifcateAssetName `
                -Path $PfxCertPathForRunAsAccount -Password $CertPassword -Exportable:$true
        }
    }
    #Remove-AzAutomationCertificate -ResourceGroupName -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $AzureCertificateName -ErrorAction SilentlyContinue

}
finally
{
    #Removing exported certificate
    Remove-Item -Path $PfxCertPathForRunAsAccount -Force | Out-Null
    #Remove-Item -Path $CerCertPathForRunAsAccount -Force | Out-Null
}

<#
# Checking app management group access
Write-Host "Checking app management group access" -ForegroundColor $CommandInfo
$mgrp = $null
$mgrpRets = Get-AzManagementGroup
foreach($mgrpRet in $mgrpRets)
{
    if ($mgrpRet.DisplayName -eq $AlyaAutomationManagementGroupName)
    {
        $mgrp = $mgrpRet
        break
    }
    $mgrpSRets = Get-AzManagementGroup -GroupName $mgrpRet.DisplayName -Expand
    foreach($mgrpSRet in $mgrpSRets)
    {
        if ($mgrpSRet.DisplayName -eq $AlyaAutomationManagementGroupName)
        {
            $mgrp = $mgrpSRet
            break
        }
    }
    if ($mgrp)
    {
        break
    }
}
if (-Not $mgrp) { throw "Management group '$AlyaAutomationManagementGroupName' not found" }
$RoleAssignment = $null
$Retries = 0;
While ($RoleAssignment -eq $null -and $Retries -le 6)
{
    $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $AzureAdServicePrincipal.AppId -scope ("/providers/Microsoft.Management/managementGroups/" + $AlyaAutomationManagementGroupName) -ErrorAction SilentlyContinue
    Start-Sleep -s 10
    $RoleAssignment = Get-AzRoleAssignment -ServicePrincipalName $AzureAdServicePrincipal.AppId -ErrorAction SilentlyContinue
    $Retries++;
}
#>

# Checking app key vault access
Write-Host "Checking app key vault access" -ForegroundColor $CommandInfo
Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $AzureAdServicePrincipal.Id -PermissionsToCertificates "All" -PermissionsToSecrets "All" # -PermissionsToKeys <keys-permissions>

# Populate the ConnectionFieldValues
$ConnectionTypeName = "AzureServicePrincipal"
$ConnectionAssetName = "AzureRunAsConnection"
$ConnectionFieldValues = @{"ApplicationId" = $AzureAdApplication.AppId; "TenantId" = $Context.Tenant.Id; "CertificateThumbprint" = $CerThumbprintString; "SubscriptionId" = $Context.Subscription.Id} 

# Create an Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
Write-Host "Checking automation connection asset" -ForegroundColor $CommandInfo
$AutomationConnection = Get-AzAutomationConnection -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $ConnectionAssetName -ErrorAction SilentlyContinue
if (-Not $AutomationConnection)
{
    Write-Warning "Automation Connection not found. Creating the Automation Connection $ConnectionAssetName"
    New-AzAutomationConnection -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $ConnectionAssetName -ConnectionTypeName $ConnectionTypeName -ConnectionFieldValues $ConnectionFieldValues 
}
else
{
    if ($AutomationConnection.FieldDefinitionValues.SubscriptionId -ne $ConnectionFieldValues.SubscriptionId -or `
        $AutomationConnection.FieldDefinitionValues.ApplicationId -ne $ConnectionFieldValues.ApplicationId -or `
        $AutomationConnection.FieldDefinitionValues.CertificateThumbprint -ne $ConnectionFieldValues.CertificateThumbprint -or `
        $AutomationConnection.FieldDefinitionValues.TenantId -ne $ConnectionFieldValues.TenantId)
    {
        Write-Host "  Updating"
	    Remove-AzAutomationConnection -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $ConnectionAssetName -Force
        New-AzAutomationConnection -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $ConnectionAssetName -ConnectionTypeName $ConnectionTypeName -ConnectionFieldValues $ConnectionFieldValues 
    } 
}
#Remove-AzAutomationConnection -ResourceGroupName $ResourceGroupOMS -automationAccountName $AutomationAccountName -Name $connectionAssetName -Force -ErrorAction SilentlyContinue


# Checking if WVD secrets have to be created
if ($AlyaWvdTenantNameProd)
{
    $assets = @($AlyaWvdServicePrincipalNameProd)
    if ($AlyaWvdServicePrincipalNameTest -and $AlyaWvdServicePrincipalNameTest -ne "PleaseSpecify" -and -Not [string]::IsNullOrEmpty($AlyaWvdServicePrincipalNameTest))
    {
        $assets += $AlyaWvdServicePrincipalNameTest
    }
    foreach($asset in $assets)
    {
        # Checking azure key vault secret
        Write-Host "Checking azure key vault secret $asset" -ForegroundColor $CommandInfo
        $AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $asset -ErrorAction SilentlyContinue
        if (-Not $AzureKeyVaultSecret)
        {
            throw "Secret $asset not found in key vault $KeyVaultName. Please create it first!"
        }
        else
        {
            $appKeySec = $AzureKeyVaultSecret.SecretValue
        }
        Clear-Variable -Name appKey -Force -ErrorAction SilentlyContinue
        Clear-Variable -Name AzureKeyVaultSecret -Force -ErrorAction SilentlyContinue

        # Checking application
        Write-Host "Checking application $asset" -ForegroundColor $CommandInfo
        $AzureAdApplication = Get-AzADApplication -DisplayName $asset -ErrorAction SilentlyContinue
        if (-Not $AzureAdApplication)
        {
            throw "Azure AD Application not found. Please create the Azure AD Application $asset"
        }
        $AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $asset

        # Create an Automation credential asset named $asset for wvd
        Write-Host "Checking automation credential asset $asset" -ForegroundColor $CommandInfo
        $AutomationCredential = Get-AzAutomationCredential -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $asset -ErrorAction SilentlyContinue
        if (-Not $AutomationCredential)
        {
            Write-Warning "Automation credential not found. Creating the Automation credential $asset"
            $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AzureAdServicePrincipal.AppId, $appKeySec
            New-AzAutomationCredential -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $asset -Value $Credential
        }
        #Remove-AutomationCredential -ResourceGroupName $ResourceGroupOMS -automationAccountName $AutomationAccountName -Name $asset -Force -ErrorAction SilentlyContinue
    }
}

# Publish runbooks
if (-Not (Test-Path "$SolutionDataRoot\$($AlyaAutomationAccountName)"))
{
    New-Item -Path "$SolutionDataRoot\$($AlyaAutomationAccountName)" -ItemType Directory -Force
}
Write-Host "Checking automation runbook 01" -ForegroundColor $CommandInfo
$runbookPath = "$SolutionDataRoot\$($AlyaAutomationAccountName)\$($AutomationAccountName)rb01.ps1"
if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
{
    $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook01.ps1" -Raw -Encoding UTF8
    $rbContent | Set-Content -Path $runbookPath -Force -Encoding UTF8
}
$Runnbook = Get-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb01") -ErrorAction SilentlyContinue
if (-Not $Runnbook)
{
    Write-Warning "Automation Runbook 01 not found. Creating the Automation Runbook $($AutomationAccountName+"rb01")"
    if (-Not (Test-Path $runbookPath))
    {
        Write-Error "Can't find runbook $($runbookPath)" -ErrorAction Continue 
        Exit 2
    }
    $tmp = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb01") -Type PowerShell -Description "Updates the Azure modules in the automation account" -Tags @{displayName="Module Updater"} -Path $runbookPath -Force
    $tmp = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb01")
    $Schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName â€“Name "Monthly2AM" -ErrorAction SilentlyContinue
    if (-Not $Schedule)
    {
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName â€“Name "Monthly2AM" -StartTime ((Get-Date "02:00:00").AddDays(1)) -MonthInterval 1 -DaysOfMonth One -TimeZone ([System.TimeZoneInfo]::Local).Id
    }
    $JobParams = @{"ResourceGroupName"=$ResourceGroupName;"AutomationAccountName"=$AutomationAccountName;"AzureModuleClass"="Az";"AzureEnvironment"="AzureCloud"}
    $tmp = Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName ($AutomationAccountName+"rb01") -ScheduleName "Monthly2AM" -Parameters $JobParams
}
else
{
    if ($UpdateRunbooks)
    {
        Write-Host "Automation Runbook 01 found. Updating the Automation Runbook $($AutomationAccountName+"rb01")"
        $tmp = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb01") -Type PowerShell -Description "Updates the Azure modules in the automation account" -Tags @{displayName="Module Updater"} -Path $runbookPath -Force
        $tmp = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb01")
    }
}
Write-Host "Checking automation runbook 02" -ForegroundColor $CommandInfo
$runbookPath = "$SolutionDataRoot\$($AlyaAutomationAccountName)\$($AutomationAccountName)rb02.ps1"
if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
{
    $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook02.ps1" -Raw -Encoding UTF8
    $rbContent = $rbContent.Replace("##AlyaModules##", "@{Name=`"Az.Accounts`"; Version=`$null}, @{Name=`"Az.Automation`"; Version=`$null}, @{Name=`"Az.Storage`"; Version=`$null}, @{Name=`"Az.Compute`"; Version=`$null}, @{Name=`"Az.Resources`"; Version=`$null}")
    $rbContent | Set-Content -Path $runbookPath -Force -Encoding UTF8
}
$Runnbook = Get-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb02") -ErrorAction SilentlyContinue
if (-Not $Runnbook)
{
    Write-Warning "Automation Runbook 02 not found. Creating the Automation Runbook $($AutomationAccountName+"rb02")"
    if (-Not (Test-Path $runbookPath))
    {
        Write-Error "Can't find runbook $($runbookPath)" -ErrorAction Continue 
        Exit 3
    }
    $tmp = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb02") -Type PowerShell -Description "Installs required modules in the automation account" -Tags @{displayName="Module Installer"} -Path $runbookPath -Force
    $tmp = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb02")
    $Schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName â€“Name "Monthly3AM" -ErrorAction SilentlyContinue
    if (-Not $Schedule)
    {
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName â€“Name "Monthly3AM" -StartTime ((Get-Date "03:00:00").AddDays(1)) -MonthInterval 1 -DayOfWeek Friday -DayOfWeekOccurrence First -TimeZone ([System.TimeZoneInfo]::Local).Id
    }
    $JobParams = @{"ResourceGroupName"=$ResourceGroupName;"AutomationAccountName"=$AutomationAccountName;"AzureEnvironment"="AzureCloud"}
    $tmp = Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName ($AutomationAccountName+"rb02") -ScheduleName "Monthly3AM" -Parameters $JobParams
}
else
{
    if ($UpdateRunbooks)
    {
        Write-Host "Automation Runbook 02 found. Updating the Automation Runbook $($AutomationAccountName+"rb02")"
        $tmp = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb02") -Type PowerShell -Description "Installs required modules in the automation account" -Tags @{displayName="Module Installer"} -Path $runbookPath -Force
        $tmp = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb02")
    }
}
Write-Host "Checking automation runbook 03" -ForegroundColor $CommandInfo
$runbookPath = "$SolutionDataRoot\$($AlyaAutomationAccountName)\$($AutomationAccountName)rb03.ps1"
if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
{
    $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook03.ps1" -Raw -Encoding UTF8
    $rbContent | Set-Content -Path $runbookPath -Force -Encoding UTF8
}
$Runnbook = Get-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb03") -ErrorAction SilentlyContinue
if (-Not $Runnbook)
{
    Write-Warning "Automation Runbook 03 not found. Creating the Automation Runbook $($AutomationAccountName+"rb03")"
    if (-Not (Test-Path $runbookPath))
    {
        Write-Error "Can't find runbook $($runbookPath)" -ErrorAction Continue 
        Exit 4
    }
    $tmp = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb03") -Type PowerShell -Description "Updates the run as certificate" -Tags @{displayName="Certificate Updater"} -Path $runbookPath -Force
    $tmp = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb03")
    $Schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName â€“Name "Monthly4AM" -ErrorAction SilentlyContinue
    if (-Not $Schedule)
    {
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName â€“Name "Monthly4AM" -StartTime ((Get-Date "04:00:00").AddDays(1)) -MonthInterval 1 -DaysOfMonth One -TimeZone ([System.TimeZoneInfo]::Local).Id
    }
    $JobParams = @{"ResourceGroupName"=$ResourceGroupName;"AutomationAccountName"=$AutomationAccountName;"AzureEnvironment"="AzureCloud"}
    $tmp = Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName ($AutomationAccountName+"rb03") -ScheduleName "Monthly4AM" -Parameters $JobParams
}
else
{
    if ($UpdateRunbooks)
    {
        Write-Host "Automation Runbook 03 found. Updating the Automation Runbook $($AutomationAccountName+"rb03")"
        $tmp = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb03") -Type PowerShell -Description "Updates the run as certificate" -Tags @{displayName="Certificate Updater"} -Path $runbookPath -Force
        $tmp = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb03")
    }
}
Write-Host "Checking automation runbook 04" -ForegroundColor $CommandInfo
$runbookPath = "$SolutionDataRoot\$($AlyaAutomationAccountName)\$($AutomationAccountName)rb04.ps1"
if ($AlyaWvdTenantNameProd)
{
    if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
    {
        $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook04wvd.ps1" -Raw -Encoding UTF8
        $rbContent = $rbContent.Replace("##AlyaTenantId##", $AlyaTenantId)
        $rbContent = $rbContent.Replace("##AlyaLocalDomainName##", $AlyaLocalDomainName)
        $rbContent = $rbContent.Replace("##AlyaWvdRDBroker##", $AlyaWvdRDBroker)
        $rbContent = $rbContent.Replace("##AlyaWvdTenantNameProd##", $AlyaWvdTenantNameProd)
        $rbContent = $rbContent.Replace("##AlyaWvdTenantNameTest##", $AlyaWvdTenantNameTest)
        $rbContent = $rbContent.Replace("##AlyaWvdServicePrincipalNameProd##", $AlyaWvdServicePrincipalNameProd)
        $rbContent = $rbContent.Replace("##AlyaWvdServicePrincipalNameTest##", $AlyaWvdServicePrincipalNameTest)
        $rbContent = $rbContent.Replace("##AlyaWvdTenantGroupName##", $AlyaWvdTenantGroupName)
        $rbContent | Set-Content -Path $runbookPath -Force -Encoding UTF8
    }
}
else
{
    if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
    {
        $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook04.ps1" -Raw -Encoding UTF8
        $rbContent | Set-Content -Path $runbookPath -Force -Encoding UTF8
    }
}
$Runnbook = Get-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb04") -ErrorAction SilentlyContinue
if (-Not $Runnbook)
{
    Write-Warning "Automation Runbook 04 not found. Creating the Automation Runbook $($AutomationAccountName+"rb04")"
    if (-Not (Test-Path $runbookPath))
    {
        Write-Error "Can't find runbook $($runbookPath)" -ErrorAction Continue 
        Exit 5
    }
    $tmp = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb04") -Type PowerShell -Description "Starts and stops VMs based on specified times in Vm tags" -Tags @{displayName="Start/Stop VM"} -Path $runbookPath -Force
    $tmp = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb04")
    $Schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName â€“Name "Hourly" -ErrorAction SilentlyContinue
    if (-Not $Schedule)
    {
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName â€“Name "Hourly" -StartTime ((Get-Date "00:10:00").AddDays(1)) -HourInterval 1 -TimeZone ([System.TimeZoneInfo]::Local).Id
    }
    $JobParams = @{"Subscriptions"=$Subscriptions;"TimeZone"=$AlyaTimeZone;"AzureEnvironment"="AzureCloud"}
    $tmp = Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName ($AutomationAccountName+"rb04") -ScheduleName "Hourly" -Parameters $JobParams
}
else
{
    if ($UpdateRunbooks)
    {
        Write-Host "Automation Runbook 04 found. Updating the Automation Runbook $($AutomationAccountName+"rb04")"
        $tmp = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb04") -Type PowerShell -Description "Will be called, when a new item in sharepoint is created" -Tags @{displayName="New Item Received"} -Path $runbookPath -Force
        $tmp = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb04")
    }
}

<#
Write-Host "      Checking webhook rb05wh02"
$webHookName = "$($AlyaAutomationAccountName+"rb05")wh02"
$webhook = Get-AzAutomationWebhook -ResourceGroupName $AlyaAutomationResourceGroupName -AutomationAccountName $AlyaAutomationAccountName `
                -Name $webHookName -ErrorAction SilentlyContinue
if (-Not $webhook)
{
    Write-Host "        Creating webhook"
    $expiryTime = [DateTimeOffset]((Get-Date).AddYears(1).AddDays(-1))
    $WebhookParams = @{
        SubscriptionId = $Context.Subscription.Id
        ResourceGroupName = "xxx"
        VmName = "xxx"
        Action = "xxx"
        AzureEnvironment = "AzureCloud"
    }
    $webhook = New-AzAutomationWebhook -ResourceGroupName $AlyaAutomationResourceGroupName -AutomationAccountName $AlyaAutomationAccountName `
                -Name $webHookName -RunbookName ($AlyaAutomationAccountName+"rb05") `
                -IsEnabled $true -ExpiryTime $expiryTime -Parameters $WebhookParams -Force
    if ([string]::IsNullOrEmpty($webhook.WebhookURI))
    {
        Write-Error "Could not create webhook!" -ErrorAction Continue
    }
    else
    {
        # Checking azure key vault secret
        Write-Host "        Checking azure key vault secret"
        $AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $webHookName -ErrorAction SilentlyContinue
        $WebhookURISave = ConvertTo-SecureString $webhook.WebhookURI -AsPlainText -Force
        if (-Not $AzureKeyVaultSecret)
        {
            Write-Warning "        Key Vault secret not found. Creating the secret $webHookName"
            $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $webHookName -SecretValue $WebhookURISave
        }
        else
        {
            Write-Warning "        Key Vault secret found. Updating the secret $webHookName"
            $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $webHookName -SecretValue $WebhookURISave
        }
    }
}
#>

# ===============================================
# Starting runbooks
# ===============================================

Write-Host "`n`n=======================================" -ForegroundColor $CommandInfo
Write-Host "STARTING RUNBOOKS" -ForegroundColor $CommandInfo
Write-Host "=======================================`n" -ForegroundColor $CommandInfo

#Running runbooks 01 and 02
Write-Host "Starting module update" -ForegroundColor $CommandInfo
Write-Host "  Please wait..."
$JobParams = @{"ResourceGroupName"=$ResourceGroupName;"AutomationAccountName"=$AutomationAccountName;"AzureModuleClass"="Az";"AzureEnvironment"="AzureCloud"}
$Job = Start-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb01") -Parameters $JobParams
$doLoop = $true
While ($doLoop) {
    Start-Sleep -Seconds 15
    $Job = Get-AzAutomationJob â€“AutomationAccountName $AutomationAccountName -Id $Job.JobId -ResourceGroupName $ResourceGroupName
    $Status = $Job.Status
    $doLoop = (($Status -ne "Completed") -and ($Status -ne "Failed") -and ($Status -ne "Suspended") -and ($Status -ne "Stopped"))
}
(Get-AzAutomationJobOutput â€“AutomationAccountName $AutomationAccountName -Id $Job.JobId -ResourceGroupName $ResourceGroupName â€“Stream Output).Summary
Write-Host "  Job status: "$($Job.Status)

Write-Host "Starting module installation" -ForegroundColor $CommandInfo
Write-Host "  Please wait..."
$JobParams = @{"ResourceGroupName"=$ResourceGroupName;"AutomationAccountName"=$AutomationAccountName;"AzureEnvironment"="AzureCloud"}
$Job = Start-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb02") -Parameters $JobParams
$doLoop = $true
While ($doLoop) {
    Start-Sleep -Seconds 15
    $Job = Get-AzAutomationJob â€“AutomationAccountName $AutomationAccountName -Id $Job.JobId -ResourceGroupName $ResourceGroupName
    $Status = $Job.Status
    $doLoop = (($Status -ne "Completed") -and ($Status -ne "Failed") -and ($Status -ne "Suspended") -and ($Status -ne "Stopped"))
}
(Get-AzAutomationJobOutput â€“AutomationAccountName $AutomationAccountName -Id $Job.JobId -ResourceGroupName $ResourceGroupName â€“Stream Output).Summary
Write-Host "  Job status: "$($Job.Status)

#Stopping Transscript
Stop-Transcript
