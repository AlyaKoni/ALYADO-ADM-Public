#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2023

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
    14.11.2019 Konrad Brunner       Initial Version
    31.05.2023 Konrad Brunner       Fixes and enhancements

#>

[CmdletBinding()]
Param(
    [bool]$UpdateRunbooks = $true,
    [bool]$DeployGroupUpdater = $false
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
if ($true -eq $AlyaResEnableInsightsAndAlerts)
{
    $AnalyticsResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
    $AnalyticsStorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdAuditStorage)"
    $AnalyticsWrkspcName = "$($AlyaNamingPrefix)loga$($AlyaResIdLogAnalytics)"
}
if (-Not (Test-Path $SolutionDataRoot))
{
    $null = New-Item -Path $SolutionDataRoot -ItemType Directory -Force
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
if ($true -eq $AlyaResEnableInsightsAndAlerts)
{
    Install-ModuleIfNotInstalled "Az.OperationalInsights"
    Install-ModuleIfNotInstalled "Az.Monitor"
}
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Applications"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MgGraph -Scopes @("Directory.Read.All","AppRoleAssignment.ReadWrite.All","Application.ReadWrite.All")

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

if ($true -eq $AlyaResEnableInsightsAndAlerts)
{
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
}

# Checking subscriptions
Write-Host "Checking subscriptions" -ForegroundColor $CommandInfo
$Subscriptions = ""
foreach ($SubscriptionName in $SubscriptionNames)
{
    $Subs = Get-AzSubscription -SubscriptionName $SubscriptionName -WarningAction SilentlyContinue
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
else
{
    Write-Host "Updating"
    $null = Set-AzResourceGroup -Name $ResourceGroupName -Tag @{displayName="Automation";ownerEmail=$Context.Account.Id}
}

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
    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ServicePrincipalName $AutomationAccount.Identity.PrincipalId -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
    $Retries = 0;
    While ($null -eq $RoleAssignment -and $Retries -le 6)
    {
        $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ServicePrincipalName $AutomationAccount.Identity.PrincipalId -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue
        Start-Sleep -s 10
        $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ServicePrincipalName $AutomationAccount.Identity.PrincipalId -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
        $Retries++;
    }
    if ($Retries -gt 6)
    {
        throw "Was not able to set role assigment 'Key Vault Administrator' for app $($AutomationAccount.Identity.PrincipalId) on scope $($KeyVault.ResourceId)"
    }
}
else
{
    Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $user.Id -PermissionsToCertificates "All" -PermissionsToSecrets "All" -PermissionsToKeys "All" -PermissionsToStorage "All"
}

# Checking azure key vault certificate
Write-Host "Checking azure key vault certificate" -ForegroundColor $CommandInfo
$AzureCertifcateAssetName = "AzureRunAsCertificate"
$AzureCertificateName = $AutomationAccountName + $AzureCertifcateAssetName
$AzureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertificateName -ErrorAction SilentlyContinue
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
    Write-Warning "Key Vault certificate not found or needs update. Creating the certificate $AzureCertificateName"
	$SelfSignedCertNoOfMonthsUntilExpired = 120
	$SelfSignedCertPlainPassword = "-"+[Guid]::NewGuid().ToString()+"]"
	$PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($AzureCertificateName + ".pfx")
	$CerPassword = ConvertTo-SecureString $SelfSignedCertPlainPassword -AsPlainText -Force
	Clear-Variable -Name "SelfSignedCertPlainPassword" -Force -ErrorAction SilentlyContinue
	$Cert = New-SelfSignedCertificate -Subject "CN=$AzureCertificateName" -CertStoreLocation Cert:\CurrentUser\My `
						-KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
						-NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddMonths($SelfSignedCertNoOfMonthsUntilExpired) -HashAlgorithm SHA256
	Export-PfxCertificate -Cert ("Cert:\CurrentUser\My\" + $Cert.Thumbprint) -FilePath $PfxCertPathForRunAsAccount -Password $CerPassword -Force | Write-Verbose
	$AzureKeyVaultCertificate = Import-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertificateName -FilePath $PfxCertPathForRunAsAccount -Password $CerPassword
	$AzureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertificateName
    Remove-Item -Path $PfxCertPathForRunAsAccount -Force -ErrorAction SilentlyContinue | Out-Null
}

try
{
    #Exporting certificate
    Write-Host "Exporting certificate" -ForegroundColor $CommandInfo
    $PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($AzureCertificateName + ".pfx")
    $PfxCertPlainPasswordForRunAsAccount = "Alya-" + [Guid]::NewGuid().ToString().Substring(0, 8) + "-Consulting"
    #Getting the certificate 
    $CertificateRetrieved = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AzureCertificateName
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
    $CerThumbprintString = $PfxCert.Thumbprint
    $CerStartDate = $PfxCert.NotBefore
    $CerEndDate = $PfxCert.NotAfter

    # Checking automation account
    Write-Host "Checking automation account" -ForegroundColor $CommandInfo
    $AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
    if (-Not $AutomationAccount)
    {
        Write-Warning "Automation Account not found. Creating the Automation Account $AutomationAccountName"
        $AutomationAccount = New-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -Location $AlyaLocation
    }

    if ($true -eq $AlyaResEnableInsightsAndAlerts)
    {
        # Checking ressource group
        Write-Host "Checking analytics ressource group" -ForegroundColor $CommandInfo
        $ResGrpParent = Get-AzResourceGroup -Name $AnalyticsResourceGroupName -ErrorAction SilentlyContinue
        if (-Not $ResGrpParent)
        {
            throw "Does not exist. Please create it first with the script \scripts\azure\Create-AzureLogAnalyticsWorkspace.ps1."
        }

        # Checking storage account
        Write-Host "Checking analytics storage account" -ForegroundColor $CommandInfo
        $StrgAccountParent = Get-AzStorageAccount -ResourceGroupName $AnalyticsResourceGroupName -Name $AnalyticsStorageAccountName -ErrorAction SilentlyContinue
        if (-Not $StrgAccountParent)
        {
            throw "Does not exist. Please create it first with the script \scripts\azure\Create-AzureLogAnalyticsWorkspace.ps1."
        }

        # Checking log analytics workspace
        Write-Host "Checking log analytics workspace $AnalyticsWrkspcName" -ForegroundColor $CommandInfo
        $LogAnaWrkspcParent = Get-AzOperationalInsightsWorkspace -ResourceGroupName $AnalyticsResourceGroupName -Name $AnalyticsWrkspcName -ErrorAction SilentlyContinue
        if (-Not $LogAnaWrkspcParent)
        {
            throw "Does not exist. Please create it first with the script \scripts\azure\Create-AzureLogAnalyticsWorkspace.ps1."
        }

        # Setting diagnostic setting automation account
        $AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
        $AutomationAccountId = "/subscriptions/$($AutomationAccount.SubscriptionId)/resourceGroups/$($AutomationAccount.ResourceGroupName)/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName"
        $DiagnosticRuleName = "$AutomationAccountName-diag"
        Write-Host "Setting diagnostic setting $DiagnosticRuleName" -ForegroundColor $CommandInfo
        $catListLog = @(); $catListMetric = @()
        Get-AzDiagnosticSettingCategory -ResourceId $AutomationAccountId | ForEach-Object {
            if ($_.CategoryType -eq "Logs")
            {
                $catListLog += (New-AzDiagnosticSettingLogSettingsObject -Category $_.Name -Enabled $true)
            }
            else
            {
                $catListMetric += (New-AzDiagnosticSettingMetricSettingsObject -Category $_.Name -Enabled $true)
            }
        }
        $null = New-AzDiagnosticSetting -Name $DiagnosticRuleName -ResourceId $AutomationAccountId -Log $catListLog -Metric $catListMetric -WorkspaceId $LogAnaWrkspcParent.ResourceId -StorageAccountId $StrgAccountParent.Id

    }

    # Checking automation account identity
    Write-Host "Checking automation account identity" -ForegroundColor $CommandInfo
    if (-Not $AutomationAccount.Identity)
    {
        Set-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -AssignSystemIdentity
        $AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
        while (-Not $AutomationAccount.Identity)
        {
            $AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
            Write-Host "Waiting for Automation Account Identity"
            if (-Not $FunctionApp.Identity) { Start-Sleep -Seconds 5 }
        }
    }

    # Setting automation account identity key vault access
    Write-Host "Setting automation account identity key vault access" -ForegroundColor $CommandInfo
    if ($KeyVault.EnableRbacAuthorization)
    {
        $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ServicePrincipalName $AutomationAccount.Identity.PrincipalId -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
        $Retries = 0;
        While ($null -eq $RoleAssignment -and $Retries -le 6)
        {
            $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ServicePrincipalName $AutomationAccount.Identity.PrincipalId -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue
            Start-Sleep -s 10
            $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ServicePrincipalName $AutomationAccount.Identity.PrincipalId -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
            $Retries++;
        }
        if ($Retries -gt 6)
        {
            throw "Was not able to set role assigment 'Key Vault Administrator' for app $($AutomationAccount.Identity.PrincipalId) on scope $($KeyVault.ResourceId)"
        }
    }
    else
    {
        Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $AutomationAccount.Identity.PrincipalId -PermissionsToCertificates "All" -PermissionsToSecrets "All"
    }
    
    # Checking automation account identity access
    Write-Host "Checking automation account identity access" -ForegroundColor $CommandInfo
    $AcIdentity = Get-AzADServicePrincipal -DisplayName $AutomationAccountName
    if (-Not $AcIdentity)
    {
        throw "ServicePrincipal with name '$($AutomationAccountName)' not found"
    }
    $GraphApp = Get-MgServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'" -Property "*"
    $AppRole = $GraphApp.AppRoles | Where-Object {$_.Value -eq "Mail.Send" -and $_.AllowedMemberTypes -contains "Application"}
    $Assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $AcIdentity.Id -All
    if ($null -eq ($Assignments | Where-Object {$_.AppRoleId -eq $AppRole.Id -and $_.ResourceId -eq $GraphApp.Id}))
    {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $AcIdentity.Id -PrincipalId $AcIdentity.Id -ResourceId $GraphApp.Id -AppRoleId $AppRole.Id
    }
    $AppRole = $GraphApp.AppRoles | Where-Object {$_.Value -eq "Application.ReadWrite.OwnedBy" -and $_.AllowedMemberTypes -contains "Application"}
    if ($null -eq ($Assignments | Where-Object {$_.AppRoleId -eq $AppRole.Id -and $_.ResourceId -eq $GraphApp.Id}))
    {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $AcIdentity.Id -PrincipalId $AcIdentity.Id -ResourceId $GraphApp.Id -AppRoleId $AppRole.Id
    }
    $AutomationAccountId = "/subscriptions/$($AutomationAccount.SubscriptionId)/resourceGroups/$($AutomationAccount.ResourceGroupName)/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName"
    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Contributor" -ObjectId $AcIdentity.Id -Scope $AutomationAccountId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $AutomationAccountId }
    $Retries = 0;
    While ($null -eq $RoleAssignment -and $Retries -le 6)
    {
        $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Contributor" -ApplicationId $AcIdentity.AppId -Scope $AutomationAccountId -ErrorAction SilentlyContinue
        Start-Sleep -s 10
        $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Contributor" -ObjectId $AcIdentity.Id -Scope $AutomationAccountId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $AutomationAccountId }
        $Retries++;
    }
    if ($Retries -gt 6)
    {
        throw "Was not able to set role assigment 'Contributor' for app $($AcIdentity.Id) on scope $($AutomationAccountId)"
    }

    # Checking RunAs application
    Write-Host "Checking application" -ForegroundColor $CommandInfo
    $RunasAppName = "$($AutomationAccountName)RunAsApp"
    $AzAdApplication = Get-AzADApplication -DisplayName $RunasAppName -ErrorAction SilentlyContinue
    if (-Not $AzAdApplication)
    {
        Write-Warning "RunAsApp not found. Creating the RunAsApp $RunasAppName"

        #Creating application and service principal
        Write-Host "Creating application and service principal"
        $KeyId = [Guid]::NewGuid()
        $HomePageUrl = "https://management.azure.com/subscriptions/$($Context.Subscription.Id)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.Automation/automationAccounts/$($AutomationAccountName)"
        $AzAdApplication = New-AzADApplication -DisplayName $RunasAppName -HomePage $HomePageUrl -IdentifierUris ("http://$AlyaTenantName/$KeyId")
        $AzAdServicePrincipal = New-AzADServicePrincipal -ApplicationId $AzAdApplication.AppId

        #Create credential 
        $null = New-AzADAppCredential -ApplicationId $AzAdApplication.AppId -CustomKeyIdentifier $CerThumbprint -CertValue $CerKeyValue -StartDate $CerStartDate -EndDate $CerEndDate 

        #Setting identity as owner (required for automated cert updates)
        Write-Host "Setting identity as owner"
        $owner = Get-MgApplicationOwner -ApplicationId $AzAdApplication.Id -All | Where-Object { $_.Id -eq $AcIdentity.Id}
        if ($null -eq $owner)
        {
            $params = @{
                "@odata.id" = "https://graph.microsoft.com/beta/directoryObjects/{$($AcIdentity.Id)}"
            }
            New-MgApplicationOwnerByRef -ApplicationId $AzAdApplication.Id -BodyParameter $params
        }

        #Granting permissions
        Write-Host "Granting permissions"
        $SpApp = Get-MgServicePrincipal -Filter "DisplayName eq 'Office 365 SharePoint Online'" -Property "*"
        $SpAppRoleSite = $SpApp.AppRoles | Where-Object {$_.Value -eq "Sites.FullControl.All" -and $_.AllowedMemberTypes -contains "Application"}
        $SpAppRoleUser = $SpApp.AppRoles | Where-Object {$_.Value -eq "User.Read.All" -and $_.AllowedMemberTypes -contains "Application"}
        $GraphAppRoleReadAll = $GraphApp.AppRoles | Where-Object {$_.Value -eq "Directory.Read.All" -and $_.AllowedMemberTypes -contains "Application"}
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
                        }
                    )
                },
                @{
                    ResourceAppId = "$($GraphApp.AppId)"
                    ResourceAccess = @(
                        @{
                            Id = "$($GraphAppRoleReadAll.Id)"
                            Type = "Role"
                        }
                    )
                }
            )
        }
        Update-MgApplication -ApplicationId $AzAdApplication.Id -BodyParameter $params

        # Waiting for admin consent
        $tmp = Get-MgApplication -ApplicationId $AzAdApplication.Id -Property "RequiredResourceAccess"
        while ($tmp.RequiredResourceAccess.Count -lt 2)
        {
            Start-Sleep -Seconds 10
            $tmp = Get-MgApplication -ApplicationId $AzAdApplication.Id -Property "RequiredResourceAccess"
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
        $AzAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $RunasAppName
    }

    # Checking application credential
    Write-Host "Checking application credential" -ForegroundColor $CommandInfo
    $AppCredential = Get-AzADAppCredential -ApplicationId $AzAdApplication.AppId -ErrorAction SilentlyContinue
    if (-Not $AppCredential)
    {
        Write-Host "  Not found" -ForegroundColor $CommandWarning
        $AppCredential = New-AzADAppCredential -ApplicationId $AzAdApplication.AppId -CustomKeyIdentifier $CerThumbprint -CertValue $CerKeyValue -StartDate $CerStartDate -EndDate $CerEndDate 
    }
    else
    {
        if ([System.Convert]::ToBase64String($AppCredential.CustomKeyIdentifier) -ne $CerThumbprint)
        {
            Write-Host "  Updating"
            Remove-AzADAppCredential -ObjectId $AzAdApplication.Id -KeyId $AppCredential.KeyId
            $AppCredential = New-AzADAppCredential -ApplicationId $AzAdApplication.AppId -CustomKeyIdentifier $CerThumbprint -CertValue $CerKeyValue -StartDate $CerStartDate -EndDate $CerEndDate 
        }
    }
	
    # Checking automation certificate asset
    Write-Host "Checking automation certificate asset" -ForegroundColor $CommandInfo
    $AutomationCertificate = Get-AzAutomationCertificate -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $AzureCertifcateAssetName -ErrorAction SilentlyContinue
    $CerPassword = ConvertTo-SecureString $PfxCertPlainPasswordForRunAsAccount -AsPlainText -Force
    if (-Not $AutomationCertificate)
    {
        Write-Warning "Automation Certificate not found. Creating the Automation Certificate $AzureCertifcateAssetName"
        New-AzAutomationCertificate -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $AzureCertifcateAssetName -Path $PfxCertPathForRunAsAccount -Password $CerPassword -Exportable:$true
    }
    else
    {
        if ($AutomationCertificate.Thumbprint -ne $CerThumbprintString)
        {
            Write-Host "  Updating"
	        Set-AzAutomationCertificate -ResourceGroupName $ResourceGroupName `
                -AutomationAccountName $AutomationAccountName -Name $AzureCertifcateAssetName `
                -Path $PfxCertPathForRunAsAccount -Password $CerPassword -Exportable:$true
        }
    }
    #Remove-AzAutomationCertificate -ResourceGroupName -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $AzureCertificateName -ErrorAction SilentlyContinue

}
finally
{
    #Removing exported certificate
    Remove-Item -Path $PfxCertPathForRunAsAccount -Force -ErrorAction SilentlyContinue | Out-Null
}

# Checking app management group access
Write-Host "Checking app management group access" -ForegroundColor $CommandInfo
$mgrp = $null
try {
    $mgrps = Get-AzManagementGroup
    $mgrp = $mgrps[0]
    if ($mgrps.Count -gt 1)
    {
        $mgrp = Select-Item -list $mgrps -message "Please select the root mangement group"
    }
    $user = Get-AzAdUser -UserPrincipalName $Context.Account.Id
    $ass = Get-AzRoleAssignment -ObjectId $user.Id -Scope $mgrp.Id -RoleDefinitionName "Management Group Contributor" | Where-Object { $_.Scope -eq $mgrp.Id }
    if (-Not $ass)
    {
        $ass = New-AzRoleAssignment -ObjectId $user.Id -Scope $mgrp.Id -RoleDefinitionName "Management Group Contributor"
    }
    $ass = Get-AzRoleAssignment -ObjectId $user.Id -Scope $mgrp.Id -RoleDefinitionName "User Access Administrator" | Where-Object { $_.Scope -eq $mgrp.Id }
    if (-Not $ass)
    {
        $ass = New-AzRoleAssignment -ObjectId $user.Id -Scope $mgrp.Id -RoleDefinitionName "User Access Administrator"
    }
}
catch {
    Write-Warning "You need access to the root amangement group!"
    Write-Warning "Please go to https://portal.azure.com/?feature.msaljs=true#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Properties"
    Write-Warning "And enable 'Access management for Azure resources'"
    Write-Warning "Restart this script"
    pause
    exit
}
$RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Contributor" -ServicePrincipalName $AzAdServicePrincipal.AppId -Scope $mgrp.Id -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $mgrp.Id }
$Retries = 0;
While ($null -eq $RoleAssignment -and $Retries -le 6)
{
    $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Contributor" -ServicePrincipalName $AzAdServicePrincipal.AppId -Scope $mgrp.Id -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 10
    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Contributor" -ServicePrincipalName $AzAdServicePrincipal.AppId -Scope $mgrp.Id -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $mgrp.Id }
    $Retries++;
}
if ($Retries -gt 6)
{
    throw "Was not able to set role assigment Contributor for app $($AzAdServicePrincipal.AppId) on scope $($mgrp.Id)"
}
        
# Checking app key vault access
Write-Host "Checking app key vault access" -ForegroundColor $CommandInfo
if ($KeyVault.EnableRbacAuthorization)
{
    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Secrets User" -ServicePrincipalName $AzAdServicePrincipal.AppId -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
    $Retries = 0;
    While ($null -eq $RoleAssignment -and $Retries -le 6)
    {
        $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Key Vault Secrets User" -ServicePrincipalName $AzAdServicePrincipal.AppId -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue
        Start-Sleep -s 10
        $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Secrets User" -ServicePrincipalName $AzAdServicePrincipal.AppId -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
        $Retries++;
    }
    if ($Retries -gt 6)
    {
        throw "Was not able to set role assigment 'Key Vault Secrets User' for app $($AzAdServicePrincipal.AppId) on scope $($KeyVault.ResourceId)"
    }
}
else
{
    Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $AzAdServicePrincipal.Id -PermissionsToCertificates "Get" -PermissionsToSecrets "Get"
}

# Checking if AVD is enabled
$AvdEnabled = $false
if ($AlyaAvdDomainAdminUPN)
{
    $AvdEnabled = $true
    #TODO RunAsApp access to AVD resources and user messaging!
}

# Publish runbooks
if (-Not (Test-Path "$SolutionDataRoot\$($AutomationAccountName)"))
{
    New-Item -Path "$SolutionDataRoot\$($AutomationAccountName)" -ItemType Directory -Force
}
Write-Host "Checking automation runbook 01" -ForegroundColor $CommandInfo
$runbookPath = "$SolutionDataRoot\$($AutomationAccountName)\$($AutomationAccountName)rb01.ps1"
if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
{
    $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook01.ps1" -Raw -Encoding UTF8
    $rbContent = $rbContent.Replace("##AlyaResourceGroupName##", $ResourceGroupName)
    $rbContent = $rbContent.Replace("##AlyaAutomationAccountName##", $AutomationAccountName)
    $rbContent = $rbContent.Replace("##AlyaRunbookName##", ($AutomationAccountName+"rb01"))
    $rbContent = $rbContent.Replace("##AlyaApplicationId##", $AzAdApplication.AppId)
    $rbContent = $rbContent.Replace("##AlyaTenantId##", $Context.Tenant.Id)
    $rbContent = $rbContent.Replace("##AlyaCertificateKeyVaultName##", $keyVaultName)
    $rbContent = $rbContent.Replace("##AlyaCertificateSecretName##", $AzureCertificateName)
    $rbContent = $rbContent.Replace("##AlyaSubscriptionId##", $Context.Subscription.Id)
    $rbContent = $rbContent.Replace("##AlyaFromMail##", "DoNotReply@$($AlyaDomainName)")
    $rbContent = $rbContent.Replace("##AlyaToMail##", $AlyaSupportEmail)
    $rbContent = $rbContent.Replace("##AlyaAllExternalsGroup##", $AlyaAllExternals)
    $rbContent = $rbContent.Replace("##AlyaAllInternalsGroup##", $AlyaAllInternals)
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
    $null = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb01") -Type PowerShell -Description "Updates the Azure modules in the automation account" -Tags @{displayName="Module Updater"} -Path $runbookPath -Force
    $null = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb01")
    $Schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "Monthly2AM" -ErrorAction SilentlyContinue
    if (-Not $Schedule)
    {
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "Monthly2AM" -StartTime ((Get-Date "02:00:00").AddDays(1)) -MonthInterval 1 -DaysOfMonth One -TimeZone ([System.TimeZoneInfo]::Local).Id
    }
    $null = Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName ($AutomationAccountName+"rb01") -ScheduleName "Monthly2AM"
}
else
{
    if ($UpdateRunbooks)
    {
        Write-Host "Automation Runbook 01 found. Updating the Automation Runbook $($AutomationAccountName+"rb01")"
        $null = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb01") -Type PowerShell -Description "Updates the Azure modules in the automation account" -Tags @{displayName="Module Updater"} -Path $runbookPath -Force
        $null = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb01")
    }
}
Write-Host "Checking automation runbook 02" -ForegroundColor $CommandInfo
$runbookPath = "$SolutionDataRoot\$($AutomationAccountName)\$($AutomationAccountName)rb02.ps1"
if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
{
    $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook02.ps1" -Raw -Encoding UTF8
    $modules = "@{Name=`"Az.Accounts`"; Version=`$null}, @{Name=`"Az.Automation`"; Version=`$null}, @{Name=`"Az.Storage`"; Version=`$null}, @{Name=`"Az.Compute`"; Version=`$null}, @{Name=`"Az.Resources`"; Version=`$null}, @{Name=`"Az.KeyVault`"; Version=`$null}"
    if ($AvdEnabled) { $modules += ", @{Name=`"Az.DesktopVirtualization`"; Version=`$null}" }
    $rbContent = $rbContent.Replace("##AlyaModules##", $modules)
    $rbContent = $rbContent.Replace("##AlyaResourceGroupName##", $ResourceGroupName)
    $rbContent = $rbContent.Replace("##AlyaAutomationAccountName##", $AutomationAccountName)
    $rbContent = $rbContent.Replace("##AlyaRunbookName##", ($AutomationAccountName+"rb02"))
    $rbContent = $rbContent.Replace("##AlyaApplicationId##", $AzAdApplication.AppId)
    $rbContent = $rbContent.Replace("##AlyaTenantId##", $Context.Tenant.Id)
    $rbContent = $rbContent.Replace("##AlyaCertificateKeyVaultName##", $keyVaultName)
    $rbContent = $rbContent.Replace("##AlyaCertificateSecretName##", $AzureCertificateName)
    $rbContent = $rbContent.Replace("##AlyaSubscriptionId##", $Context.Subscription.Id)
    $rbContent = $rbContent.Replace("##AlyaFromMail##", "DoNotReply@$($AlyaDomainName)")
    $rbContent = $rbContent.Replace("##AlyaToMail##", $AlyaSupportEmail)
    $rbContent = $rbContent.Replace("##AlyaAllExternalsGroup##", $AlyaAllExternals)
    $rbContent = $rbContent.Replace("##AlyaAllInternalsGroup##", $AlyaAllInternals)
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
    $null = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb02") -Type PowerShell -Description "Installs required modules in the automation account" -Tags @{displayName="Module Installer"} -Path $runbookPath -Force
    $null = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb02")
    $Schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "Monthly3AM" -ErrorAction SilentlyContinue
    if (-Not $Schedule)
    {
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "Monthly3AM" -StartTime ((Get-Date "03:00:00").AddDays(1)) -MonthInterval 1 -DayOfWeek Friday -DayOfWeekOccurrence First -TimeZone ([System.TimeZoneInfo]::Local).Id
    }
    $null = Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName ($AutomationAccountName+"rb02") -ScheduleName "Monthly3AM"
}
else
{
    if ($UpdateRunbooks)
    {
        Write-Host "Automation Runbook 02 found. Updating the Automation Runbook $($AutomationAccountName+"rb02")"
        $null = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb02") -Type PowerShell -Description "Installs required modules in the automation account" -Tags @{displayName="Module Installer"} -Path $runbookPath -Force
        $null = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb02")
    }
}
Write-Host "Checking automation runbook 03" -ForegroundColor $CommandInfo
$runbookPath = "$SolutionDataRoot\$($AutomationAccountName)\$($AutomationAccountName)rb03.ps1"
if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
{
    $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook03.ps1" -Raw -Encoding UTF8
    $rbContent = $rbContent.Replace("##AlyaResourceGroupName##", $ResourceGroupName)
    $rbContent = $rbContent.Replace("##AlyaAutomationAccountName##", $AutomationAccountName)
    $rbContent = $rbContent.Replace("##AlyaRunbookName##", ($AutomationAccountName+"rb03"))
    $rbContent = $rbContent.Replace("##AlyaApplicationId##", $AzAdApplication.AppId)
    $rbContent = $rbContent.Replace("##AlyaTenantId##", $Context.Tenant.Id)
    $rbContent = $rbContent.Replace("##AlyaCertificateKeyVaultName##", $keyVaultName)
    $rbContent = $rbContent.Replace("##AlyaCertificateSecretName##", $AzureCertificateName)
    $rbContent = $rbContent.Replace("##AlyaSubscriptionId##", $Context.Subscription.Id)
    $rbContent = $rbContent.Replace("##AlyaFromMail##", "DoNotReply@$($AlyaDomainName)")
    $rbContent = $rbContent.Replace("##AlyaToMail##", $AlyaSupportEmail)
    $rbContent = $rbContent.Replace("##AlyaAllExternalsGroup##", $AlyaAllExternals)
    $rbContent = $rbContent.Replace("##AlyaAllInternalsGroup##", $AlyaAllInternals)
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
    $null = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb03") -Type PowerShell -Description "Updates the run as certificate" -Tags @{displayName="Certificate Updater"} -Path $runbookPath -Force
    $null = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb03")
    $Schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "Monthly4AM" -ErrorAction SilentlyContinue
    if (-Not $Schedule)
    {
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "Monthly4AM" -StartTime ((Get-Date "04:00:00").AddDays(1)) -MonthInterval 1 -DaysOfMonth One -TimeZone ([System.TimeZoneInfo]::Local).Id
    }
    $null = Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName ($AutomationAccountName+"rb03") -ScheduleName "Monthly4AM"
}
else
{
    if ($UpdateRunbooks)
    {
        Write-Host "Automation Runbook 03 found. Updating the Automation Runbook $($AutomationAccountName+"rb03")"
        $null = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb03") -Type PowerShell -Description "Updates the run as certificate" -Tags @{displayName="Certificate Updater"} -Path $runbookPath -Force
        $null = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb03")
    }
}
Write-Host "Checking automation runbook 04" -ForegroundColor $CommandInfo
$runbookPath = "$SolutionDataRoot\$($AutomationAccountName)\$($AutomationAccountName)rb04.ps1"
if ($AvdEnabled)
{
    if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
    {
        $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook04avd.ps1" -Raw -Encoding UTF8
        $rbContent = $rbContent.Replace("##AlyaResourceGroupName##", $ResourceGroupName)
        $rbContent = $rbContent.Replace("##AlyaAutomationAccountName##", $AutomationAccountName)
        $rbContent = $rbContent.Replace("##AlyaRunbookName##", ($AutomationAccountName+"rb04"))
        $rbContent = $rbContent.Replace("##AlyaLocalDomainName##", $AlyaLocalDomainName)
        $rbContent = $rbContent.Replace("##AlyaApplicationId##", $AzAdApplication.AppId)
        $rbContent = $rbContent.Replace("##AlyaTenantId##", $Context.Tenant.Id)
        $rbContent = $rbContent.Replace("##AlyaCertificateKeyVaultName##", $keyVaultName)
        $rbContent = $rbContent.Replace("##AlyaCertificateSecretName##", $AzureCertificateName)
        $rbContent = $rbContent.Replace("##AlyaSubscriptionId##", $Context.Subscription.Id)
        $rbContent = $rbContent.Replace("##AlyaFromMail##", "DoNotReply@$($AlyaDomainName)")
        $rbContent = $rbContent.Replace("##AlyaToMail##", $AlyaSupportEmail)
        $rbContent = $rbContent.Replace("##AlyaAllExternalsGroup##", $AlyaAllExternals)
        $rbContent = $rbContent.Replace("##AlyaAllInternalsGroup##", $AlyaAllInternals)
        $rbContent | Set-Content -Path $runbookPath -Force -Encoding UTF8
    }
}
else
{
    if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
    {
        $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook04.ps1" -Raw -Encoding UTF8
        $rbContent = $rbContent.Replace("##AlyaResourceGroupName##", $ResourceGroupName)
        $rbContent = $rbContent.Replace("##AlyaAutomationAccountName##", $AutomationAccountName)
        $rbContent = $rbContent.Replace("##AlyaRunbookName##", ($AutomationAccountName+"rb04"))
        $rbContent = $rbContent.Replace("##AlyaApplicationId##", $AzAdApplication.AppId)
        $rbContent = $rbContent.Replace("##AlyaTenantId##", $Context.Tenant.Id)
        $rbContent = $rbContent.Replace("##AlyaCertificateKeyVaultName##", $keyVaultName)
        $rbContent = $rbContent.Replace("##AlyaCertificateSecretName##", $AzureCertificateName)
        $rbContent = $rbContent.Replace("##AlyaSubscriptionId##", $Context.Subscription.Id)
        $rbContent = $rbContent.Replace("##AlyaFromMail##", "DoNotReply@$($AlyaDomainName)")
        $rbContent = $rbContent.Replace("##AlyaToMail##", $AlyaSupportEmail)
        $rbContent = $rbContent.Replace("##AlyaAllExternalsGroup##", $AlyaAllExternals)
        $rbContent = $rbContent.Replace("##AlyaAllInternalsGroup##", $AlyaAllInternals)
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
    $null = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb04") -Type PowerShell -Description "Starts and stops VMs based on specified times in Vm tags" -Tags @{displayName="Start/Stop VM"} -Path $runbookPath -Force
    $null = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb04")
    $Schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "Hourly" -ErrorAction SilentlyContinue
    if (-Not $Schedule)
    {
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "Hourly" -StartTime ((Get-Date "00:10:00").AddDays(1)) -HourInterval 1 -TimeZone ([System.TimeZoneInfo]::Local).Id
    }
    $null = Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName ($AutomationAccountName+"rb04") -ScheduleName "Hourly"
}
else
{
    if ($UpdateRunbooks)
    {
        Write-Host "Automation Runbook 04 found. Updating the Automation Runbook $($AutomationAccountName+"rb04")"
        $null = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb04") -Type PowerShell -Description "Will be called, when a new item in sharepoint is created" -Tags @{displayName="New Item Received"} -Path $runbookPath -Force
        $null = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb04")
    }
}
if ($DeployGroupUpdater)
{
    Write-Host "Checking automation runbook 09" -ForegroundColor $CommandInfo
    $runbookPath = "$SolutionDataRoot\$($AutomationAccountName)\$($AutomationAccountName)rb09.ps1"
    if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
    {
        $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook09.ps1" -Raw -Encoding UTF8
        $rbContent = $rbContent.Replace("##AlyaResourceGroupName##", $ResourceGroupName)
        $rbContent = $rbContent.Replace("##AlyaAutomationAccountName##", $AutomationAccountName)
        $rbContent = $rbContent.Replace("##AlyaRunbookName##", ($AutomationAccountName+"rb09"))
        $rbContent = $rbContent.Replace("##AlyaApplicationId##", $AzAdApplication.AppId)
        $rbContent = $rbContent.Replace("##AlyaTenantId##", $Context.Tenant.Id)
        $rbContent = $rbContent.Replace("##AlyaCertificateKeyVaultName##", $keyVaultName)
        $rbContent = $rbContent.Replace("##AlyaCertificateSecretName##", $AzureCertificateName)
        $rbContent = $rbContent.Replace("##AlyaSubscriptionId##", $Context.Subscription.Id)
        $rbContent = $rbContent.Replace("##AlyaFromMail##", "DoNotReply@$($AlyaDomainName)")
        $rbContent = $rbContent.Replace("##AlyaToMail##", $AlyaSupportEmail)
        $rbContent = $rbContent.Replace("##AlyaAllExternalsGroup##", $AlyaAllExternals)
        $rbContent = $rbContent.Replace("##AlyaAllInternalsGroup##", $AlyaAllInternals)
        $rbContent | Set-Content -Path $runbookPath -Force -Encoding UTF8
    }
    $Runnbook = Get-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb09") -ErrorAction SilentlyContinue
    if (-Not $Runnbook)
    {
        Write-Warning "Automation Runbook 09 not found. Creating the Automation Runbook $($AutomationAccountName+"rb09")"
        if (-Not (Test-Path $runbookPath))
        {
            Write-Error "Can't find runbook $($runbookPath)" -ErrorAction Continue 
            Exit 4
        }
        $null = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb09") -Type PowerShell -Description "Updates the all internals and all externals groups" -Tags @{displayName="Group Updater"} -Path $runbookPath -Force
        $null = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb09")
        $Schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "FourTimesADay" -ErrorAction SilentlyContinue
        if (-Not $Schedule)
        {
            $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "FourTimesADay" -StartTime ((Get-Date "04:00:00").AddDays(1)) -HourInterval 6 -TimeZone ([System.TimeZoneInfo]::Local).Id
        }
        $null = Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName ($AutomationAccountName+"rb09") -ScheduleName "FourTimesADay"
    }
    else
    {
        if ($UpdateRunbooks)
        {
            Write-Host "Automation Runbook 09 found. Updating the Automation Runbook $($AutomationAccountName+"rb09")"
            $null = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb09") -Type PowerShell -Description "Updates the all internals and all externals groups" -Tags @{displayName="Group Updater"} -Path $runbookPath -Force
            $null = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb09")
        }
    }
}

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
    $Job = Get-AzAutomationJob -AutomationAccountName $AutomationAccountName -Id $Job.JobId -ResourceGroupName $ResourceGroupName
    $Status = $Job.Status
    $doLoop = (($Status -ne "Completed") -and ($Status -ne "Failed") -and ($Status -ne "Suspended") -and ($Status -ne "Stopped"))
}
(Get-AzAutomationJobOutput -AutomationAccountName $AutomationAccountName -Id $Job.JobId -ResourceGroupName $ResourceGroupName -Stream Output).Summary
Write-Host "  Job status: "$($Job.Status)

Write-Host "Starting module installation" -ForegroundColor $CommandInfo
Write-Host "  Please wait..."
$JobParams = @{"ResourceGroupName"=$ResourceGroupName;"AutomationAccountName"=$AutomationAccountName;"AzureEnvironment"="AzureCloud"}
$Job = Start-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb02") -Parameters $JobParams
$doLoop = $true
While ($doLoop) {
    Start-Sleep -Seconds 15
    $Job = Get-AzAutomationJob -AutomationAccountName $AutomationAccountName -Id $Job.JobId -ResourceGroupName $ResourceGroupName
    $Status = $Job.Status
    $doLoop = (($Status -ne "Completed") -and ($Status -ne "Failed") -and ($Status -ne "Suspended") -and ($Status -ne "Stopped"))
}
(Get-AzAutomationJobOutput -AutomationAccountName $AutomationAccountName -Id $Job.JobId -ResourceGroupName $ResourceGroupName -Stream Output).Summary
Write-Host "  Job status: "$($Job.Status)

#Stopping Transscript
Stop-Transcript
