#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2024

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
    05.11.2020 Konrad Brunner       Initial Version
    16.09.2024 Konrad Brunner       Rework with Graph

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
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.KeyVault"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Applications"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MgGraph -Scopes @("Directory.Read.All","AppRoleAssignment.ReadWrite.All","Application.ReadWrite.All")

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

# Checking azure key vault certificate
Write-Host "Checking azure key vault certificate" -ForegroundColor $CommandInfo
$AzureCertifcateAssetName = "$($CompName)SharePointRunAsCertificate"
$SharePointCertificateName = $AzureCertifcateAssetName
$AzureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $SharePointCertificateName -ErrorAction SilentlyContinue
if ($AzureKeyVaultCertificate)
{
    if ($AzureKeyVaultCertificate.Expires -lt (Get-Date).AddMonths(3))
    {
        Write-Host "  Certificate in key vault needs update"
        $AzureKeyVaultCertificate = $null
    }
}
if (-Not $AzureKeyVaultCertificate)
{
    Write-Warning "Key Vault certificate not found or needs update. Creating the certificate $SharePointCertificateName"
	$SelfSignedCertNoOfMonthsUntilExpired = 120
	$SelfSignedCertPlainPassword = "`$" + [Guid]::NewGuid().ToString() + "!"
	$PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($SharePointCertificateName + ".pfx")
	$CerPassword = ConvertTo-SecureString $SelfSignedCertPlainPassword -AsPlainText -Force
	Clear-Variable -Name "SelfSignedCertPlainPassword" -Force -ErrorAction SilentlyContinue
	$Cert = New-SelfSignedCertificate -Subject "CN=$SharePointCertificateName" -CertStoreLocation Cert:\CurrentUser\My `
						-KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
						-NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddMonths($SelfSignedCertNoOfMonthsUntilExpired) -HashAlgorithm SHA256
	Export-PfxCertificate -Cert ("Cert:\CurrentUser\My\" + $Cert.Thumbprint) -FilePath $PfxCertPathForRunAsAccount -Password $CerPassword -Force | Write-Verbose
	$AzureKeyVaultCertificate = Import-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $SharePointCertificateName -FilePath $PfxCertPathForRunAsAccount -Password $CerPassword
	$AzureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $SharePointCertificateName
    Remove-Item -Path $PfxCertPathForRunAsAccount -Force -ErrorAction SilentlyContinue | Out-Null
}

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$CompName = Make-PascalCase($AlyaCompanyNameShort)
$applicationName = "$($CompName)SharePointRunAsApp"
$AzAdApplication = Get-AzADApplication -DisplayName $applicationName -ErrorAction SilentlyContinue
if (-Not $AzAdApplication)
{
    Write-Warning "Azure AD Application not found. Creating the Azure AD Application $applicationName"

    try
    {

        #Exporting certificate
        Write-Host "Exporting certificate" -ForegroundColor $CommandInfo
        $PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($SharePointCertificateName + ".pfx")
        $PfxCertPlainPasswordForRunAsAccount = "`$" + [Guid]::NewGuid().ToString() + "!"
        $CerCertPathForRunAsAccount = Join-Path $env:TEMP ($SharePointCertificateName + ".cer")
        #Getting the certificate 
        $CertificateRetrieved = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SharePointCertificateName
        $CertificateBytes = [System.Convert]::FromBase64String(($CertificateRetrieved.SecretValue | Foreach-Object { [System.Net.NetworkCredential]::new("", $_).Password }))
        $CertCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $CertCollection.Import($CertificateBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        #Export the .pfx file 
        $ProtectedCertificateBytes = $CertCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $PfxCertPlainPasswordForRunAsAccount)
        [System.IO.File]::WriteAllBytes($PfxCertPathForRunAsAccount, $ProtectedCertificateBytes)
        #Export the .cer file 
        $CertificateRetrieved = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $SharePointCertificateName
        $CertificateBytes = $CertificateRetrieved.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        [System.IO.File]::WriteAllBytes($CerCertPathForRunAsAccount, $CertificateBytes)
        #Read the .pfx file 
        $PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)
        $CerKeyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())
        $CerThumbprint = [System.Convert]::ToBase64String($PfxCert.GetCertHash())
        $CerStartDate = $PfxCert.NotBefore
        $CerEndDate = $PfxCert.NotAfter

        #Creating application and service principal
        $KeyId = [Guid]::NewGuid()
        $HomePageUrl = $AlyaSharePointAdminUrl
        $AzAdApplication = New-AzADApplication -DisplayName $applicationName -HomePage $HomePageUrl -IdentifierUris ("http://$AlyaTenantName/$KeyId")
        $AzureAdServicePrincipal = New-AzADServicePrincipal -ApplicationId $AzAdApplication.AppId

        #Create credential
        $AzAdApplicationCredential = New-AzADAppCredential -ApplicationId $AzAdApplication.AppId -CustomKeyIdentifier $CerThumbprint -CertValue $CerKeyValue -StartDate $CerStartDate -EndDate $CerEndDate 

    }
    finally
    {
        #Removing exported certificate
        Remove-Item -Path $PfxCertPathForRunAsAccount -Force | Out-Null
        Remove-Item -Path $CerCertPathForRunAsAccount -Force | Out-Null
    }

    #Granting permissions
    Write-Host "Granting permissions"
    $SpApp = Get-MgBetaServicePrincipal -Filter "DisplayName eq 'Office 365 SharePoint Online'" -Property "*"
    $SpAppRoleSite = $SpApp.AppRoles | Where-Object {$_.Value -eq "Sites.FullControl.All" -and $_.AllowedMemberTypes -contains "Application"}
    $SpAppRoleTerm = $SpApp.AppRoles | Where-Object {$_.Value -eq "TermStore.ReadWrite.All" -and $_.AllowedMemberTypes -contains "Application"}
    $SpAppRoleUser = $SpApp.AppRoles | Where-Object {$_.Value -eq "User.ReadWrite.All" -and $_.AllowedMemberTypes -contains "Application"}
    $GraphApp = Get-MgBetaServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'" -Property "*"
    $GraphAppRoleSite = $GraphApp.AppRoles | Where-Object {$_.Value -eq "Sites.FullControl.All" -and $_.AllowedMemberTypes -contains "Application"}
    $GraphAppRoleTerm = $GraphApp.AppRoles | Where-Object {$_.Value -eq "TermStore.ReadWrite.All" -and $_.AllowedMemberTypes -contains "Application"}
    $GraphAppRoleUser = $GraphApp.AppRoles | Where-Object {$_.Value -eq "Directory.Read.All" -and $_.AllowedMemberTypes -contains "Application"}
    $GraphAppRoleMember = $GraphApp.AppRoles | Where-Object {$_.Value -eq "GroupMember.ReadWrite.All" -and $_.AllowedMemberTypes -contains "Application"}

    $params = @{
        RequiredResourceAccess = @(
            @{
                ResourceAppId = "$($SpApp.AppId)"
                ResourceAccess = @(
                    @{
                        Id = "$($SpAppRoleSite.Id)"
                        Type = "Role"
                    },
                    @{
                        Id = "$($SpAppRoleUser.Id)"
                        Type = "Role"
                    },
                    @{
                        Id = "$($SpAppRoleTerm.Id)"
                        Type = "Role"
                    }
                )
            },
            @{
                ResourceAppId = "$($GraphApp.AppId)"
                ResourceAccess = @(
                    @{
                        Id = "$($GraphAppRoleSite.Id)"
                        Type = "Role"
                    },
                    @{
                        Id = "$($GraphAppRoleTerm.Id)"
                        Type = "Role"
                    },
                    @{
                        Id = "$($GraphAppRoleUser.Id)"
                        Type = "Role"
                    },
                    @{
                        Id = "$($GraphAppRoleMember.Id)"
                        Type = "Role"
                    }
                )
            }
        )
    }
    Update-MgBetaApplication -ApplicationId $AzAdApplication.Id -BodyParameter $params

    # Waiting for admin consent
    $tmp = Get-MgBetaApplication -ApplicationId $AzAdApplication.Id -Property "RequiredResourceAccess"
    while ($tmp.RequiredResourceAccess.Count -lt 2)
    {
        Start-Sleep -Seconds 10
        $tmp = Get-MgBetaApplication -ApplicationId $AzAdApplication.Id -Property "RequiredResourceAccess"
    }
    Start-Sleep -Seconds 60 # Looks like there is some time issue for admin consent #TODO 60 seconds enough

    #Admin consent
    $apiToken = Get-AzAccessToken
    if (-Not $apiToken)
    {
        Write-Warning "Can't aquire an access token. Please give admin consent to application '$($RunasAppName)' in the portal!"
        pause
    }
    else
    {
        $header = @{'Authorization'='Bearer '+$apiToken;'X-Requested-With'='XMLHttpRequest';'x-ms-client-request-id'=[guid]::NewGuid();'x-ms-correlation-id'=[guid]::NewGuid();}
        $url = "https://main.iam.ad.ext.azure.com/api/RegisteredApplications/$($AzAdApplication.AppId)/Consent?onBehalfOfAll=true"
        Invoke-RestMethod -Uri $url -Headers $header -Method POST -ErrorAction Stop
        #TODO consent was working?
        Write-Warning "Please check in portal if admin consent was working"
    }
}
else
{
    $AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $applicationName
}

$AlyaSharePointAppId = $AzureAdServicePrincipal.AppId
$AlyaSharePointAppCertificate = $AzureKeyVaultCertificate.Thumbprint
Write-Host "ClientId: $AlyaSharePointAppId"
Write-Host "Thumbprint: $AlyaSharePointAppCertificate"

#Stopping Transscript
Stop-Transcript
