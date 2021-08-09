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
    05.11.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Configure-ServiceApplication-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "AzureAdPreview"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Configure-ServiceApplication | AZURE" -ForegroundColor $CommandInfo
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
    $AzureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertificateName -ErrorAction SilentlyContinue
}

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$CompName = Make-PascalCase($AlyaCompanyNameShort)
$applicationName = "$($CompName)SharePointRunAsApp"
$AzureAdApplication = Get-AzADApplication -DisplayName $applicationName -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    Write-Warning "Azure AD Application not found. Creating the Azure AD Application $applicationName"

    try
    {

        #Exporting certificate
        Write-Host "Exporting certificate" -ForegroundColor $CommandInfo
        $PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($AzureCertificateName + ".pfx")
        $PfxCertPlainPasswordForRunAsAccount = "`$" + [Guid]::NewGuid().ToString() + "!"
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
        $CertificateRetrieved = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertificateName
        $CertificateBytes = $CertificateRetrieved.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        [System.IO.File]::WriteAllBytes($CerCertPathForRunAsAccount, $CertificateBytes)
        #Read the .pfx file 
        $PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)
        $KeyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())
        $startDate = $PfxCert.NotBefore
        $endDate = $PfxCert.NotAfter

        #Creating application and service principal
        $KeyId = [Guid]::NewGuid()
        $HomePageUrl = $AlyaSharePointAdminUrl
        $AzureAdApplication = New-AzADApplication -DisplayName $applicationName -HomePage $HomePageUrl -IdentifierUris ("http://" + $KeyId)
        $AzureAdServicePrincipal = New-AzADServicePrincipal -ApplicationId $AzureAdApplication.ApplicationId

        #Create credential
        $AzureAdApplicationCredential = New-AzADAppCredential -ApplicationId $AzureAdApplication.ApplicationId -CertValue $KeyValue -StartDate $startDate -EndDate $endDate

    }
    finally
    {
        #Removing exported certificate
        Remove-Item -Path $PfxCertPathForRunAsAccount -Force | Out-Null
        Remove-Item -Path $CerCertPathForRunAsAccount -Force | Out-Null
    }

    #TODO
    #remove 'Contributor' over scope '/subscriptions/02016285-d8fb-4cd2-a126-3cbd9e1df1d2'

    #Setting its own as owner (required for automated cert updates)
    $AdAzureAdApplication = Get-AzureADApplication -Filter "AppId eq '$($AzureAdApplication.ApplicationId)'"
    #$AdAzureAdServicePrincipal = Get-AzureADServicePrincipal -Filter "AppId eq '$($AzureAdApplication.ApplicationId)'"
    #Add-AzureADApplicationOwner -ObjectId $AdAzureAdApplication.ObjectId -RefObjectId $AdAzureAdServicePrincipal.ObjectId

    #Adding type Microsoft.Open.AzureAD.Model.ResourceAccess
    #$module = Get-InstalledModule -Name AzureAd
    #$instLoc = $module.InstalledLocation
    #Add-Type -Path "$instLoc\Microsoft.Open.AzureAD16.Graph.Client.dll"

    #Granting permissions
    $AppPermissionAdGraph = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "824c81eb-e3f8-4ee6-8f6d-de7f50d565b7","Role"
    $RequiredResourceAccessAdGraph = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $RequiredResourceAccessAdGraph.ResourceAppId = "00000002-0000-0000-c000-000000000000"
    $RequiredResourceAccessAdGraph.ResourceAccess = $AppPermissionAdGraph

    $AppPermissionMsGraph = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "18a4783c-866b-4cc7-a460-3d5e5662c884","Role"
    $RequiredResourceAccessMsGraph = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $RequiredResourceAccessMsGraph.ResourceAppId = "00000003-0000-0000-c000-000000000000"
    $RequiredResourceAccessMsGraph.ResourceAccess = $AppPermissionMsGraph

    $AppPermissionSharePoint1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "fbcd29d2-fcca-4405-aded-518d457caae4","Role"
    $AppPermissionSharePoint2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "678536fe-1083-478a-9c59-b99265e6b0d3","Role"
    $AppPermissionSharePoint3 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "9bff6588-13f2-4c48-bbf2-ddab62256b36","Role"
    $AppPermissionSharePoint4 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "c8e3537c-ec53-43b9-bed3-b2bd3617ae97","Role"
    $AppPermissionSharePoint5 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "741f803b-c850-494e-b5df-cde7c675a1ca","Role"
    $AppPermissionSharePoint6 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "df021288-bdef-4463-88db-98f22de89214","Role"
    $RequiredResourceAccessSharePoint = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $RequiredResourceAccessSharePoint.ResourceAppId = "00000003-0000-0ff1-ce00-000000000000"
    $RequiredResourceAccessSharePoint.ResourceAccess = $AppPermissionSharePoint1, $AppPermissionSharePoint2, $AppPermissionSharePoint3, $AppPermissionSharePoint4, $AppPermissionSharePoint5, $AppPermissionSharePoint6

    Set-AzureADApplication -ObjectId $AdAzureAdApplication.ObjectId -RequiredResourceAccess $RequiredResourceAccessAdGraph, $RequiredResourceAccessMsGraph, $RequiredResourceAccessSharePoint
    $tmp = Get-AzureADApplication -ObjectId $AdAzureAdApplication.ObjectId
    while ($tmp.RequiredResourceAccess.Count -lt 3)
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
        Write-Warning "Can't aquire an access token. Please give admin consent to application '$($applicationName)' in the portal!"
        pause
    }
    else
    {
        $header = @{'Authorization'='Bearer '+$apiToken;'X-Requested-With'='XMLHttpRequest';'x-ms-client-request-id'=[guid]::NewGuid();'x-ms-correlation-id'=[guid]::NewGuid();}
        $url = "https://main.iam.ad.ext.azure.com/api/RegisteredApplications/$($AzureAdApplication.ApplicationId)/Consent?onBehalfOfAll=true"
        Invoke-RestMethod -Uri $url -Headers $header -Method POST -ErrorAction Stop
        #TODO consent was working?
        Write-Warning "Please check in portal if admin consent was working"
    }
}
else
{
    $AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $applicationName
}

$AlyaSharePointAppId = $AzureAdServicePrincipal.ApplicationId
$AlyaSharePointAppCertificate = $AzureKeyVaultCertificate.Thumbprint
Write-Host "ClientId: $AlyaSharePointAppId"
Write-Host "Thumbprint: $AlyaSharePointAppCertificate"

#Stopping Transscript
Stop-Transcript