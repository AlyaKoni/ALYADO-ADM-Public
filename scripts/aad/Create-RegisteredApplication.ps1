#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    25.09.2025 Konrad Brunner       Initial Version
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Creates or updates a registered Azure AD application and its service principal with required permissions, authentication credentials, and optional Exchange Online RBAC configuration.

.DESCRIPTION
The Create-RegisteredApplication.ps1 script automates the process of creating and configuring a registered application in Azure Active Directory. It checks for required modules, establishes authenticated sessions with Azure and Microsoft Graph, and ensures that the specified application exists with the correct configuration. Depending on the provided parameters, it can assign secret or certificate-based authentication, register required resource access permissions, assign administrative consent, and configure Exchange Online RBAC access for a specific user. Additionally, the script integrates with Azure Key Vault for storing or generating certificates and secrets necessary for secure authentication.

.PARAMETER ApplicationName
Specifies the name of the Azure AD application to create or update.

.PARAMETER AssignKeyAuth
If specified, assigns a client secret authentication method and stores the secret in Azure Key Vault.

.PARAMETER AssignCertAuth
If specified, assigns a certificate-based authentication method using a certificate stored or created in Azure Key Vault.

.PARAMETER RequiredResourceAccess
An optional object specifying required API permissions for the application.

.PARAMETER SetRequiredResourceAccessForContacts
If specified, configures the application with Microsoft Graph permissions necessary for reading and writing contacts.

.PARAMETER SetRequiredResourceAccessForGuestManagement
If specified, configures the application with Microsoft Graph permissions necessary for managing guest users.

.PARAMETER SetExchangeRbacForUPN
If specified, configures Exchange Online RBAC access for the provided UPN by creating the necessary Exchange service principal and role assignments.

.PARAMETER PublicClientRedirectUri
Specifies the redirect URI for public client applications.

.PARAMETER SignInAudience
Defines the application’s sign-in audience. Defaults to "AzureADMyOrg".

.PARAMETER IdentifierUri
Optional unique identifier URI for the application. If not provided, a default based on the tenant name and a unique GUID is generated.

.INPUTS
None. This script does not accept pipeline input.

.OUTPUTS
None. The script outputs status messages to the console and writes a detailed log file to the configured logging location.

.EXAMPLE
PS> .\Create-RegisteredApplication.ps1 -ApplicationName "MyApp" -AssignCertAuth -SetRequiredResourceAccessForGuestManagement

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$ApplicationName = $null,
    [switch]$AssignKeyAuth,
    [switch]$AssignCertAuth,
    [object]$RequiredResourceAccess = $null,
    [switch]$SetRequiredResourceAccessForContacts,
    [switch]$SetRequiredResourceAccessForGuestManagement,
    [switch]$SetExchangeRbacForUPN = $null,
    [string]$PublicClientRedirectUri = $null,
    [string]$SignInAudience = "AzureADMyOrg",
    [string]$IdentifierUri = $null
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Create-RegisteredApplication-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Constants
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$KeyVaultResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
if (-Not $ApplicationName.StartsWith($AlyaCompanyNameShortM365))
{
    $ApplicationName = "$($AlyaCompanyNameShortM365)$($ApplicationName)"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.KeyVault"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Applications"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"
if ($SetExchangeRbacForUPN)
{
    Install-ModuleIfNotInstalled "ExchangeOnlineManagement"
}

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MgGraph -Scopes @("Directory.Read.All","AppRoleAssignment.ReadWrite.All","Application.ReadWrite.All","DelegatedPermissionGrant.ReadWrite.All")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Automation | Create-RegisteredApplication | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

if ($AssignKeyAuth  -or $AssignCertAuth)
{

    # Checking KeyVault ressource group
    Write-Host "Checking KeyVault ressource group for keyvault" -ForegroundColor $CommandInfo
    $ResGrpKeyVault = Get-AzResourceGroup -Name $KeyVaultResourceGroupName -ErrorAction SilentlyContinue
    if (-Not $ResGrpKeyVault)
    {
        throw "KeyVault Ressource Group not found. Please create the Ressource Group $KeyVaultResourceGroupName"
    }

    # Checking key vault
    Write-Host "Checking key vault" -ForegroundColor $CommandInfo
    $KeyVault = Get-AzKeyVault -ResourceGroupName $KeyVaultResourceGroupName -VaultName $KeyVaultName -ErrorAction SilentlyContinue
    if (-Not $KeyVault)
    {
        throw "Key Vault not found. Please create the Key Vault $KeyVaultName"
    }

    # Setting own key vault access
    Write-Host "Setting own key vault access" -ForegroundColor $CommandInfo
    $user = Get-AzAdUser -UserPrincipalName $Context.Account.Id
    if ($KeyVault.EnableRbacAuthorization)
    {
        $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $user.Id -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
        $Retries = 0;
        While ($null -eq $RoleAssignment -and $Retries -le 6)
        {
            $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $user.Id -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue
            Start-Sleep -s 10
            $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $user.Id -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
            $Retries++;
        }
        if ($Retries -gt 6)
        {
            throw "Was not able to set role assigment 'Key Vault Administrator' for user $($user.Id) on scope $($KeyVault.ResourceId)"
        }
    }
    else
    {
        Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $user.Id -PermissionsToCertificates "All" -PermissionsToSecrets "All" -PermissionsToKeys "All" -PermissionsToStorage "All" -ErrorAction Continue
    }

}

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$MgApplication = Get-MgBetaApplication -Filter "DisplayName eq '$ApplicationName'" -Property "*"
if (-Not $MgApplication)
{
    Write-Warning "App not found. Creating the App $ApplicationName"

    #Creating application and service principal
    Write-Host "Creating application and service principal"
    if (-Not $IdentifierUri)
    {
        $KeyId = [Guid]::NewGuid()
        $IdentifierUri = "http://$AlyaTenantName/$KeyId"
    }
    $MgApplication = New-MgBetaApplication -DisplayName $ApplicationName `
        -SignInAudience $SignInAudience `
        -IdentifierUris $IdentifierUri
    $MgServicePrincipal = New-MgBetaServicePrincipal -AppId $MgApplication.AppId
}
else
{
    Write-Warning "Application found."
    $MgServicePrincipal = Get-MgBetaServicePrincipal -Filter "AppId eq '$($MgApplication.AppId)'"
}

# Checking public client redirect uri
if ($PublicClientRedirectUri)
{
    Write-Host "Checking public client redirect uri" -ForegroundColor $CommandInfo
    Update-MgBetaApplication -ApplicationId $MgApplication.Id -PublicClient @{
        RedirectUris = @($PublicClientRedirectUri)
    }
}

# Merging ressource access
Write-Host "Merging ressource access" -ForegroundColor $CommandInfo
$MgApp = Get-MgBetaApplication -ApplicationId $MgApplication.Id -Property "RequiredResourceAccess"
if (-Not $RequiredResourceAccess)
{
    $RequiredResourceAccess = $MgApp.RequiredResourceAccess
}
else
{
    foreach($AppPermission in $MgApp.RequiredResourceAccess)
    {
        $ExistingAppPermission = $RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq $AppPermission.ResourceAppId }
        if ($ExistingAppPermission)
        {
            foreach($access in $AppPermission.ResourceAccess)
            {
                if ($ExistingAppPermission.ResourceAccess | Where-Object { $_.Id -eq $access.Id } )
                {
                    Write-Host "  $($access.Id) permission already exists"
                }
                else
                {
                    Write-Host "  Adding $($access.Id) permission"
                    $ExistingAppPermission.ResourceAccess += @{
                        Id = $GuestPermission.Id
                        Type = "Role"
                    }
                }
            }
        }
        else
        {
            Write-Host "  Adding $_.ResourceAppId app permissions"
            $RequiredResourceAccess += @{
                ResourceAppId = $AppPermission.ResourceAppId
                ResourceAccess = $AppPermission.ResourceAccess
            }
        }
    }
}

function Merge-ApplicationPermission($GraphApp, $Permission, $RequiredResourceAccess)
{
    $GuestPermission = $GraphApp.AppRoles | Where-Object {$_.Value -eq $Permission -and $_.AllowedMemberTypes -contains "Application"} | Select-Object -First 1
    if (-Not $GuestPermission)
    {
        throw "Can't find $Permission permission in Microsoft Graph application"
    }

    $ExistingAppPermission = $RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq $GraphApp.AppId }
    if ($ExistingAppPermission)
    {
        if ($ExistingAppPermission.ResourceAccess | Where-Object { $_.Id -eq $GuestPermission.Id } )
        {
            Write-Host "  $Permission permission already exists"
        }
        else
        {
            Write-Host "  Adding $Permission permission"
            $ExistingAppPermission.ResourceAccess += @{
                Id = $GuestPermission.Id
                Type = "Role"
            }
        }
    }
    else
    {
        Write-Host "  Adding $Permission permission"
        $RequiredResourceAccess += @{
            ResourceAppId = $GraphApp.AppId
            ResourceAccess = @(@{
                Id = $GuestPermission.Id
                Type = "Role"
            })
        }
    }
}

#Granting permissions
if ($RequiredResourceAccess -or $SetRequiredResourceAccessForContacts -or $SetRequiredResourceAccessForGuestManagement)
{
    Write-Host "Granting permissions" -ForegroundColor $CommandInfo

    # Microsoft Graph App
    $GraphApp = Get-MgBetaServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'" -Property "*" | Select-Object -First 1
    if (-Not $GraphApp)
    {
        throw "Can't find Microsoft Graph application"
    }
    
    if ($SetRequiredResourceAccessForGuestManagement)
    {
        Merge-ApplicationPermission -GraphApp $GraphApp -Permission "User.Invite.All" -RequiredResourceAccess $RequiredResourceAccess
        Merge-ApplicationPermission -GraphApp $GraphApp -Permission "User.ReadWrite.All" -RequiredResourceAccess $RequiredResourceAccess
        Merge-ApplicationPermission -GraphApp $GraphApp -Permission "User.ReadWrite.CrossCloud" -RequiredResourceAccess $RequiredResourceAccess
    }

    if ($SetRequiredResourceAccessForContacts)
    {
        Merge-ApplicationPermission -GraphApp $GraphApp -Permission "Contacts.ReadWrite" -RequiredResourceAccess $RequiredResourceAccess
    }

    $params = @{
        RequiredResourceAccess = $RequiredResourceAccess
    }
    Update-MgBetaApplication -ApplicationId $MgApplication.Id -BodyParameter $params

    # Waiting for admin consent
    $tmp = Get-MgBetaApplication -ApplicationId $MgApplication.Id -Property "RequiredResourceAccess"
    while ($tmp.RequiredResourceAccess.Count -lt 1)
    {
        Start-Sleep -Seconds 10
        $tmp = Get-MgBetaApplication -ApplicationId $MgApplication.Id -Property "RequiredResourceAccess"
    }
    Start-Sleep -Seconds 60 # Looks like there is some time issue for admin consent #TODO 60 seconds enough

    #Admin consent
    Write-Host "Setting principal admin consent" -ForegroundColor $CommandInfo
    foreach($resourceAccess in $RequiredResourceAccess)
    {
        $appId = $resourceAccess.ResourceAppId
        $app = Get-MgBetaServicePrincipal -Filter "AppId eq '$appId'" -Property "*"
        $perms = $resourceAccess.ResourceAccess
        $scopes = ($app.PublishedPermissionScopes | Where-Object { $_.Id -in $perms.Id }).Value -join " "
        try {
            New-MgBetaOauth2PermissionGrant -ClientId $MgServicePrincipal.Id -ConsentType "AllPrincipals" -ResourceId $app.Id -Scope $scopes -ExpiryTime ([DateTime]::MaxValue)
        }
        catch {
            Write-Error $_.Exception -ErrorAction Continue
            Write-Warning "Principal admin consent was not working. Please check in portal if principal admin consent was given to application '$($ApplicationName)'!"
        }
    }
}

if ($AssignCertAuth)
{
    try
    {

        # Checking azure key vault certificate
        Write-Host "Checking azure key vault certificate" -ForegroundColor $CommandInfo
        $AzureCertifcateAssetName = "$($ApplicationName)Certificate"
        $AzureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertifcateAssetName -ErrorAction SilentlyContinue
        if (-Not $AzureKeyVaultCertificate)
        {
            Write-Warning "Key Vault certificate not found or needs update. Creating the certificate $AzureCertifcateAssetName"
            $SelfSignedCertNoOfMonthsUntilExpired = 120
            $SelfSignedCertPlainPassword = "-"+[Guid]::NewGuid().ToString()+"]"
            $PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($AzureCertifcateAssetName + ".pfx")
            $CerPassword = ConvertTo-SecureString $SelfSignedCertPlainPassword -AsPlainText -Force
            Clear-Variable -Name "SelfSignedCertPlainPassword" -Force -ErrorAction SilentlyContinue
            $Cert = New-SelfSignedCertificate -Subject "CN=$AzureCertifcateAssetName" -CertStoreLocation Cert:\CurrentUser\My `
                                -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
                                -NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddMonths($SelfSignedCertNoOfMonthsUntilExpired) -HashAlgorithm SHA256
            Export-PfxCertificate -Cert ("Cert:\CurrentUser\My\" + $Cert.Thumbprint) -FilePath $PfxCertPathForRunAsAccount -Password $CerPassword -Force | Write-Verbose
            $AzureKeyVaultCertificate = Import-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertifcateAssetName -FilePath $PfxCertPathForRunAsAccount -Password $CerPassword
            $AzureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertifcateAssetName
            Remove-Item -Path $PfxCertPathForRunAsAccount -Force -ErrorAction SilentlyContinue | Out-Null
        }

        #Exporting certificate
        Write-Host "Exporting certificate" -ForegroundColor $CommandInfo
        $PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($AzureCertifcateAssetName + ".pfx")
        $PfxCertPlainPasswordForRunAsAccount = "A-" + [Guid]::NewGuid().ToString().Substring(0, 8) + "-C"
        #Getting the certificate 
        $CertificateRetrieved = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AzureCertifcateAssetName
        $CertificateBytes = [System.Convert]::FromBase64String(($CertificateRetrieved.SecretValue | Foreach-Object { [System.Net.NetworkCredential]::new("", $_).Password }))
        $CertCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $CertCollection.Import($CertificateBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        #Export the .pfx file 
        $ProtectedCertificateBytes = $CertCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $PfxCertPlainPasswordForRunAsAccount)
        [System.IO.File]::WriteAllBytes($PfxCertPathForRunAsAccount, $ProtectedCertificateBytes)
        #Read the .pfx file 
        $PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)
        $CerKeyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())
        $CerThumbprint = [System.Convert]::ToBase64String($PfxCert.GetCertHash())
        $CerStartDate = $PfxCert.NotBefore
        $CerEndDate = $PfxCert.NotAfter

        # Checking application credential
        Write-Host "Checking application credential" -ForegroundColor $CommandInfo
        $AppCredential = Get-AzADAppCredential -ApplicationId $MgApplication.AppId -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq "AsymmetricX509Cert" -or $_.Type -eq "Symmetric" }
        if (-Not $AppCredential)
        {
            Write-Host "  Not found" -ForegroundColor $CommandWarning
            $AppCredential = New-AzADAppCredential -ApplicationId $MgApplication.AppId -CustomKeyIdentifier $CerThumbprint -CertValue $CerKeyValue -StartDate $CerStartDate -EndDate $CerEndDate 
        }
        else
        {
            if ([System.Convert]::ToBase64String($AppCredential.CustomKeyIdentifier) -ne $CerThumbprint)
            {
                Write-Host "  Updating"
                Remove-AzADAppCredential -ObjectId $MgApplication.Id -KeyId $AppCredential.KeyId
                $AppCredential = New-AzADAppCredential -ApplicationId $MgApplication.AppId -CustomKeyIdentifier $CerThumbprint -CertValue $CerKeyValue -StartDate $CerStartDate -EndDate $CerEndDate 
            }
            else
            {
                Write-Host "  Found"
            }
        }
    }
    catch
    {
        Write-Error $_
        throw
    }
    finally
    {
        #Removing exported certificate
        Remove-Item -Path $PfxCertPathForRunAsAccount -Force -ErrorAction SilentlyContinue | Out-Null
    }

}

if ($AssignKeyAuth)
{
    # Checking application key
    Write-Host "Checking application key" -ForegroundColor $CommandInfo
    $keyIdentifier = ([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("KeyVault $KeyVaultName")))
    $AppCredential = Get-AzADAppCredential -ApplicationId $MgApplication.AppId -ErrorAction SilentlyContinue | Where-Object { [Convert]::ToBase64String($_.CustomKeyIdentifier) -eq $keyIdentifier }
    if (-Not $AppCredential)
    {
        Write-Host "  Not found" -ForegroundColor $CommandWarning
	    $startDate = (Get-Date)
	    $endDate = (Get-Date).AddYears(2)
	    $AppCredential = New-AzADAppCredential -ApplicationId $MgApplication.AppId -CustomKeyIdentifier $keyIdentifier -StartDate $startDate -EndDate $endDate

        # Checking azure key vault key
        Write-Host "Checking azure key vault key" -ForegroundColor $CommandInfo
        $AzureKeyAssetName = "$($ApplicationName)Key"
        $AzureKeyVaultKey = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AzureKeyAssetName -ErrorAction SilentlyContinue
        if (-Not $AzureKeyVaultKey)
        {
            $PasswordSec = ConvertTo-SecureString $AppCredential.SecretText -AsPlainText -Force
            $AzureKeyVaultKey = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AzureKeyAssetName -SecretValue $PasswordSec
        }
    }
    else
    {
        Write-Host "  Found"
    }
}

if ($SetExchangeRbacForUPN)
{
    try {
        LoginTo-EXO
    }
    catch {
        Write-Error $_.Exception -ErrorAction Continue
        LogoutFrom-EXOandIPPS
        LoginTo-EXO
    }

    # Checking exchange service principal
    Write-Host "Checking exchange service principal" -ForegroundColor $CommandInfo
    $ExServPrinc = Get-ServicePrincipal -Identity $ApplicationName -ErrorAction SilentlyContinue
    if (-Not $ExServPrinc)
    {
        Write-Warning "Exchange service principal not found. Creating the exchange service principal $ApplicationName"
        $ExServPrinc = New-ServicePrincipal -AppId $MgApplication.AppId -ObjectId $MgServicePrincipal.id -DisplayName $ApplicationName
        $ExServPrinc = Get-ServicePrincipal -Identity $ApplicationName -ErrorAction SilentlyContinue
    }

    # Checking exchange management scope
    Write-Host "Checking exchange management scope" -ForegroundColor $CommandInfo
    $ExManScope = Get-ManagementScope -Identity $ApplicationName -ErrorAction SilentlyContinue
    if (-Not $ExManScope)
    {
        Write-Warning "Exchange management scope not found. Creating the exchange management scope $ApplicationName"
        $ExManScope = New-ManagementScope -Name $ApplicationName -RecipientRestrictionFilter "userPrincipalName -eq '$SetExchangeRbacForUPN'"
        $ExManScope = Get-ManagementScope -Identity $ApplicationName
    }

    # Checking exchange management scope assignment
    Write-Host "Checking exchange management scope assignment" -ForegroundColor $CommandInfo
    $ExRolAss = Get-ManagementRoleAssignment | Where-Object { $_.Role -eq "Application Exchange Full Access" -and $_.App -eq $ExServPrinc.id -and $_.CustomResourceScope -eq $ApplicationName }
    if (-Not $ExRolAss)
    {
        Write-Warning "Exchange management scope assignment not found. Creating the exchange management scope assignment $ApplicationName"
        $ExRolAss = New-ManagementRoleAssignment -App $ExServPrinc.id -Role "Application Exchange Full Access" -CustomResourceScope $ApplicationName
        $ExRolAss = Get-ManagementRoleAssignment | Where-Object { $_.Role -eq "Application Exchange Full Access" -and $_.App -eq $ExServPrinc.id -and $_.CustomResourceScope -eq $ApplicationName }
    }

    # Testing access rights
    Write-Host "Testing access rights" -ForegroundColor $CommandInfo
    Test-ServicePrincipalAuthorization -Resource $SetExchangeRbacForUPN -Identity $ApplicationName

}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD3xsap/ilF4y/q
# mhKS/4EcvyxHMbVW7c+3m2U4D862AaCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g604YfM/tV
# 5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD4ED6gVYD
# U/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S/gJXhZrh
# 0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp8nKmrVa4
# 6Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqtf2phU7+y
# R2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJQWTEE/bP
# 0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKXvYkPbEdx
# +QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4yMYgcMKb
# 9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmYF8T4xO2k
# 6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2mMIVpqWC
# Z1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7spNY6rQb
# 3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd2jANBgkq
# hkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy/fAHsVv1
# RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW2H3Bh6zN
# XULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0MP6pBPKO
# L6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/pFL9zlcc
# tWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcexU0bcV0hL
# Q4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf6AMOGaM5
# 6A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzECp9LnR+34
# c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9mUF5qE6Yw
# QqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+KuaJRsz+cn
# ZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/JlN6m6GM1j
# EhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutofdgNBzMUx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPYBPYvhLmQbbeXZ
# udv+/x4ZI+WJxBoVF3Iki4Jhyx3HMA0GCSqGSIb3DQEBAQUABIICAMNvNMMyptb5
# 57BB6EOWD2SHtZ9wmI3U2ItwVQr/9+3bkEky6StePMyWXF6oJLWu7AoRQuVqQ8Oi
# bt0nvTiecsDWeurSTB5wq2ze6XYewOTAkqzEVP3UwqPUZceVV1NNS6ONWe3hN0Kf
# jsxICJC2QjqOiEaZZxmJ6VwoDqUDmz4A3sO5l3ZRV39kwUwd9xjALuO4j2ewfy7c
# L4FV0x4NV1F4g0zw7Klq+WGjkwaBrhjHOsmMqr3F5F8E5EP9NN63E2TgnvRvAd7f
# 18x7q3kJIJPh7vRglpIhLGwjz3B1z1mhLCyJschpZ6QVhriZmpCYnfoKEPSFy3pG
# eNQ/qLUMAGiq52fuHYFpoYxI6qGoqG7FpDplReo1PnXE263Ys03gQZMAMLbdfpSn
# pmlQxi5vKzpCjFuC+r2h6LIZCsq+EqewYpxQgim65wmdo6+2WsI1OlweNtcx8xMT
# AAxhmn3h6mBcy7OYNuZvBxqsDM8JqiMM1PNXasE6dfX56QLap1JPwi4ecTu4gYJ6
# QeA1ZQP+RuUHzGD1oWcMiMsFAEAdKIj2UxJ377OVnexbfYqIvD/1j8Cuik3W5pjt
# 9y1CGaDGHaUhkuD2r3pqhgG1mubEVcHr/VuS9ldGRmbmLmmH2lKbHGtQgpkCwKdt
# /bdc79hIrEAeRLu8Ula2LDuMeNOmmaILoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCByyILZKTagQXe6PKld4LRnNvpUO47+1bUWTw/37Mp1VgIUVaKUk4oEZCa5
# TvBNHBC3tubJemcYDzIwMjYwMjA2MTEzODU5WjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# IEnhh1BtEI56MD3yTnGNe0N3XgFWOnjk50ihZMQyCA/rMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAl9YmNck783mk
# lXmzkx2FZyLnxERPMjFT10tHSn3z1o65sAPlBhNRst9sL/tAJBOUccZW20YBBlcx
# N7ztoc+Jwx11MyvAseT8JRMipjg5AfiJ/YGtbTWOuPtX/r0pXhPuT/sCYxGTAoEV
# 7J4nDWGNqsXRuJa1p86gTDRIdJUxKzvg6UPeFoVh7+53wB1rA3UhBPaE0e34ZThd
# enbE75vBiBqx9ncyhVcCpkTrIDNrNlTTZ4OAYQJFKixCTKVIizsqSjgEMSyCWEzl
# 7u2+rk9KSB63Emy3i+RLdri4XRtXRyKYCNhxddnBHPVpkECmD9k96RzSz21JN4Ws
# hkePOT9HzHw0vtREl/nv0nqaa3teRRQA7jiGUoi/TzjDi2CczLQAfjp3CDjK+7RO
# shMljdezcsg5gIIGJEQPKUbFTk09E15o/PB7Ggzxa86EeEMa+N+C6K4xEOuZ2jC6
# 4ANdw1sJsnATBZdgIMwlqoLvK2FB6GlRxoskeOxLguThuulXe9H0
# SIG # End signature block
