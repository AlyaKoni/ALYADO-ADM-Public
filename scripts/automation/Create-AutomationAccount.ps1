#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

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
    [bool]$DeployGroupUpdater = $false,
    [bool]$DeployStartStopVm = $true,
    [bool]$PreparePs7RuntimeEnv = $true
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
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Applications"

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

# Setting variable
$AlyaSubscriptionIds = ""
foreach ($AlyaSubscriptionName in ($AlyaAllSubscriptions | Select-Object -Unique))
{
    $sub = Get-AzSubscription -SubscriptionName $AlyaSubscriptionName
    if (-Not $AlyaSubscriptionIds.Contains($sub.Id))
    {
        if (-Not [string]::IsNullOrEmpty($AlyaSubscriptionIds))
        {
            $AlyaSubscriptionIds += ","
        }
        $AlyaSubscriptionIds += $sub.Id
    }
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
    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $user.Id -Scope $KeyVault.ResourceId -ErrorAction Continue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
    $Retries = 0;
    While ($null -eq $RoleAssignment -and $Retries -le 6)
    {
        $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $user.Id -Scope $KeyVault.ResourceId -ErrorAction Continue
        Start-Sleep -s 10
        $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $user.Id -Scope $KeyVault.ResourceId -ErrorAction Continue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
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
        while (-Not $AutomationAccount.Identity.PrincipalId)
        {
            $AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
            Write-Host "Waiting for Automation Account Identity"
            if (-Not $AutomationAccount.Identity.PrincipalId) { Start-Sleep -Seconds 5 }
        }
    }

    # Setting automation account identity key vault access
    Write-Host "Setting automation account identity key vault access" -ForegroundColor $CommandInfo
    $retries = 10
    while ($true)
    {
        try {
            if ($KeyVault.EnableRbacAuthorization)
            {
                $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $AutomationAccount.Identity.PrincipalId -Scope $KeyVault.ResourceId -ErrorAction Continue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
                $Retries = 0;
                While ($null -eq $RoleAssignment -and $Retries -le 6)
                {
                    $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $AutomationAccount.Identity.PrincipalId -Scope $KeyVault.ResourceId -ErrorAction Continue
                    Start-Sleep -s 10
                    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $AutomationAccount.Identity.PrincipalId -Scope $KeyVault.ResourceId -ErrorAction Continue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
                    $Retries++;
                }
                if ($Retries -gt 6)
                {
                    throw "Was not able to set role assigment 'Key Vault Administrator' for app $($AutomationAccount.Identity.PrincipalId) on scope $($KeyVault.ResourceId)"
                }
            }
            else
            {
                Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $AutomationAccount.Identity.PrincipalId -PermissionsToCertificates "All" -PermissionsToSecrets "All" -ErrorAction Stop
            }
            break
        }
        catch {
            $retries--
            if ($retries -lt 0)
            {
                throw $_
            }
            Write-Warning "Retrying"
            Start-Sleep -Seconds 10
        }
    }
    
    # Checking automation account identity access
    Write-Host "Checking automation account identity access" -ForegroundColor $CommandInfo
    $AcIdentity = Get-AzADServicePrincipal -DisplayName $AutomationAccountName
    if (-Not $AcIdentity)
    {
        throw "ServicePrincipal with name '$($AutomationAccountName)' not found"
    }
    $GraphApp = Get-MgBetaServicePrincipal -Filter "DisplayName eq 'Microsoft Graph'" -Property "*"
    $AppRole = $GraphApp.AppRoles | Where-Object {$_.Value -eq "Mail.Send" -and $_.AllowedMemberTypes -contains "Application"}
    $Assignments = Get-MgBetaServicePrincipalAppRoleAssignment -ServicePrincipalId $AcIdentity.Id -All
    if ($null -eq ($Assignments | Where-Object {$_.AppRoleId -eq $AppRole.Id -and $_.ResourceId -eq $GraphApp.Id}))
    {
        New-MgBetaServicePrincipalAppRoleAssignment -ServicePrincipalId $AcIdentity.Id -PrincipalId $AcIdentity.Id -ResourceId $GraphApp.Id -AppRoleId $AppRole.Id
    }
    $AppRole = $GraphApp.AppRoles | Where-Object {$_.Value -eq "Application.ReadWrite.OwnedBy" -and $_.AllowedMemberTypes -contains "Application"}
    if ($null -eq ($Assignments | Where-Object {$_.AppRoleId -eq $AppRole.Id -and $_.ResourceId -eq $GraphApp.Id}))
    {
        New-MgBetaServicePrincipalAppRoleAssignment -ServicePrincipalId $AcIdentity.Id -PrincipalId $AcIdentity.Id -ResourceId $GraphApp.Id -AppRoleId $AppRole.Id
    }
    $AutomationAccountId = "/subscriptions/$($AutomationAccount.SubscriptionId)/resourceGroups/$($AutomationAccount.ResourceGroupName)/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName"
    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Contributor" -ObjectId $AcIdentity.Id -Scope $AutomationAccountId -ErrorAction Continue | Where-Object { $_.Scope -eq $AutomationAccountId }
    $Retries = 0;
    While ($null -eq $RoleAssignment -and $Retries -le 6)
    {
        $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Contributor" -ObjectId $AcIdentity.Id -Scope $AutomationAccountId -ErrorAction Continue
        Start-Sleep -s 10
        $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Contributor" -ObjectId $AcIdentity.Id -Scope $AutomationAccountId -ErrorAction Continue | Where-Object { $_.Scope -eq $AutomationAccountId }
        $Retries++;
    }
    if ($Retries -gt 6)
    {
        throw "Was not able to set role assigment 'Contributor' for app $($AcIdentity.Id) on scope $($AutomationAccountId)"
    }

    # Checking RunAs application
    Write-Host "Checking RunAs application" -ForegroundColor $CommandInfo
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
        $retries = 10
        while ($true)
        {
            try {
                $owner = Get-MgBetaApplicationOwner -ApplicationId $AzAdApplication.Id -All | Where-Object { $_.Id -eq $AcIdentity.Id}
                break
            }
            catch {
                $retries--
                if ($retries -lt 0)
                {
                    throw $_
                }
                Write-Warning "Waiting for application"
                Start-Sleep -Seconds 3
            }
        }
        if ($null -eq $owner)
        {
            $params = @{
                "@odata.id" = "$AlyaGraphEndpoint/beta/directoryObjects/{$($AcIdentity.Id)}"
            }
            New-MgBetaApplicationOwnerByRef -ApplicationId $AzAdApplication.Id -BodyParameter $params
        }

        #Granting permissions
        Write-Host "Granting permissions"
        $SpApp = Get-MgBetaServicePrincipal -Filter "DisplayName eq 'Office 365 SharePoint Online'" -Property "*"
        $SpAppRoleSite = $SpApp.AppRoles | Where-Object {$_.Value -eq "Sites.FullControl.All" -and $_.AllowedMemberTypes -contains "Application"}
        $SpAppRoleUser = $SpApp.AppRoles | Where-Object {$_.Value -eq "User.Read.All" -and $_.AllowedMemberTypes -contains "Application"}
        $GraphAppRoleReadAll = $GraphApp.AppRoles | Where-Object {$_.Value -eq "Directory.Read.All" -and $_.AllowedMemberTypes -contains "Application"}
        $GraphAppRoleGroupMemberReadWriteAll = $GraphApp.AppRoles | Where-Object {$_.Value -eq "GroupMember.ReadWrite.All" -and $_.AllowedMemberTypes -contains "Application"}

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

        if ($DeployGroupUpdater)
        {
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
                            },
                            @{
                                Id = "$($GraphAppRoleGroupMemberReadWriteAll.Id)"
                                Type = "Role"
                            }
                        )
                    }
                )
            }
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
        Write-Host "Setting principal admin consent" -ForegroundColor $CommandInfo
        foreach($resourceAccess in $params.RequiredResourceAccess)
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

# Checking own management group access
Write-Host "Checking own management group access" -ForegroundColor $CommandInfo
$mgrp = $null
try {
    $mgrps = Get-AzManagementGroup
    $mgrp = $mgrps[0]
    if ($mgrps.Count -gt 1)
    {
        $mgrp = Select-Item -list $mgrps -message "Please select the root mangement group"
    }
    $user = Get-AzAdUser -UserPrincipalName $Context.Account.Id

    $RoleAssignment = Get-AzRoleAssignment -ObjectId $user.Id -Scope $mgrp.Id -RoleDefinitionName "Management Group Contributor" -ErrorAction Continue | Where-Object { $_.Scope -eq $mgrp.Id }
    $Retries = 0;
    While ($null -eq $RoleAssignment -and $Retries -le 6)
    {
        $RoleAssignment = New-AzRoleAssignment -ObjectId $user.Id -Scope $mgrp.Id -RoleDefinitionName "Management Group Contributor" -ErrorAction Continue
        Start-Sleep -Seconds 10
        $RoleAssignment = Get-AzRoleAssignment -ObjectId $user.Id -Scope $mgrp.Id -RoleDefinitionName "Management Group Contributor" -ErrorAction Continue | Where-Object { $_.Scope -eq $mgrp.Id }
        $Retries++;
    }
    if ($Retries -gt 6)
    {
        throw "Was not able to set role assigment 'Management Group Contributor' for user $($user.Id) on scope $($mgrp.Id)"
    }
    $RoleAssignment = Get-AzRoleAssignment -ObjectId $user.Id -Scope $mgrp.Id -RoleDefinitionName "User Access Administrator" -ErrorAction Continue | Where-Object { $_.Scope -eq $mgrp.Id }
    $Retries = 0;
    While ($null -eq $RoleAssignment -and $Retries -le 6)
    {
        $RoleAssignment = New-AzRoleAssignment -ObjectId $user.Id -Scope $mgrp.Id -RoleDefinitionName "User Access Administrator" -ErrorAction Continue
        Start-Sleep -Seconds 10
        $RoleAssignment = Get-AzRoleAssignment -ObjectId $user.Id -Scope $mgrp.Id -RoleDefinitionName "User Access Administrator" -ErrorAction Continue | Where-Object { $_.Scope -eq $mgrp.Id }
        $Retries++;
    }
    if ($Retries -gt 6)
    {
        throw "Was not able to set role assigment 'User Access Administrator' for user $($user.Id) on scope $($mgrp.Id)"
    }

}
catch {
    Write-Warning "You need access to the root mangement group!"
    Write-Warning "Please go to https://portal.azure.com/?feature.msaljs=true#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Properties"
    Write-Warning "and enable 'Access management for Azure resources'"
    Write-Warning "Also go to https://portal.azure.com/?feature.msaljs=true#view/Microsoft_Azure_ManagementGroups/ManagementGroupBrowseBlade/~/MGBrowse_overview"
    Write-Warning "and press 'Start using management groups'"
    Write-Warning "Restart this script"
    pause
    exit
}

# Checking app management group access
Write-Host "Checking app management group access" -ForegroundColor $CommandInfo
$RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Contributor" -ObjectId $AzAdServicePrincipal.Id -Scope $mgrp.Id -ErrorAction Continue | Where-Object { $_.Scope -eq $mgrp.Id }
$Retries = 0;
While ($null -eq $RoleAssignment -and $Retries -le 6)
{
    $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Contributor" -ObjectId $AzAdServicePrincipal.Id -Scope $mgrp.Id -ErrorAction Continue
    Start-Sleep -Seconds 10
    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Contributor" -ObjectId $AzAdServicePrincipal.Id -Scope $mgrp.Id -ErrorAction Continue | Where-Object { $_.Scope -eq $mgrp.Id }
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
    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Secrets User" -ObjectId $AzAdServicePrincipal.Id -Scope $KeyVault.ResourceId -ErrorAction Continue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
    $Retries = 0;
    While ($null -eq $RoleAssignment -and $Retries -le 6)
    {
        $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Key Vault Secrets User" -ObjectId $AzAdServicePrincipal.Id -Scope $KeyVault.ResourceId -ErrorAction Continue
        Start-Sleep -s 10
        $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Secrets User" -ObjectId $AzAdServicePrincipal.Id -Scope $KeyVault.ResourceId -ErrorAction Continue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
        $Retries++;
    }
    if ($Retries -gt 6)
    {
        throw "Was not able to set role assigment 'Key Vault Secrets User' for app $($AzAdServicePrincipal.AppId) on scope $($KeyVault.ResourceId)"
    }
    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Certificate User" -ObjectId $AzAdServicePrincipal.Id -Scope $KeyVault.ResourceId -ErrorAction Continue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
    $Retries = 0;
    While ($null -eq $RoleAssignment -and $Retries -le 6)
    {
        $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Key Vault Certificate User" -ObjectId $AzAdServicePrincipal.Id -Scope $KeyVault.ResourceId -ErrorAction Continue
        Start-Sleep -s 10
        $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName "Key Vault Certificate User" -ObjectId $AzAdServicePrincipal.Id -Scope $KeyVault.ResourceId -ErrorAction Continue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
        $Retries++;
    }
    if ($Retries -gt 6)
    {
        throw "Was not able to set role assigment 'Key Vault Certificate User' for app $($AzAdServicePrincipal.AppId) on scope $($KeyVault.ResourceId)"
    }
}
else
{
    Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $AzAdServicePrincipal.Id -PermissionsToCertificates "Get" -PermissionsToSecrets "Get" -ErrorAction Continue
}

# Checking if AVD is enabled
$AvdEnabled = $false
if ($AlyaAvdDomainAdminUPN)
{
    $AvdEnabled = $true
    #TODO RunAsApp access to AVD resources and user messaging!
}

# Checking PreparePs7RuntimeEnv
if ($PreparePs7RuntimeEnv)
{
    Write-Host "Checking runtime environments in Automation Account" -ForegroundColor $CommandInfo
    Write-Host "  Please enable now runtime environments in Automation Account"
    pause
    & "$AlyaScripts\automation\Create-RuntimeEnvironment.ps1"
    & "$AlyaScripts\automation\Install-RuntimeEnvironmentPackages"
    & "$AlyaScripts\automation\Update-RuntimeEnvironmentPackages.ps1"
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
    $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook01.ps1" -Raw -Encoding $AlyaUtf8Encoding
    $rbContent = $rbContent.Replace("##AlyaAzureEnvironment##", $AlyaAzureEnvironment)
    $rbContent = $rbContent.Replace("##AlyaResourceGroupName##", $ResourceGroupName)
    $rbContent = $rbContent.Replace("##AlyaAutomationAccountName##", $AutomationAccountName)
    $rbContent = $rbContent.Replace("##AlyaRunbookName##", ($AutomationAccountName+"rb01"))
    $rbContent = $rbContent.Replace("##AlyaApplicationId##", $AzAdApplication.AppId)
    $rbContent = $rbContent.Replace("##AlyaTenantId##", $Context.Tenant.Id)
    $rbContent = $rbContent.Replace("##AlyaCertificateKeyVaultName##", $keyVaultName)
    $rbContent = $rbContent.Replace("##AlyaCertificateSecretName##", $AzureCertificateName)
    $rbContent = $rbContent.Replace("##AlyaSubscriptionId##", $Context.Subscription.Id)
    $rbContent = $rbContent.Replace("##AlyaSubscriptionIds##", $AlyaSubscriptionIds)
    $rbContent = $rbContent.Replace("##AlyaTimeZone##", $AlyaTimeZone)
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
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "Monthly2AM" -StartTime ((Get-Date "02:00:00").AddDays(1)) -MonthInterval 1 -DayOfWeek Saturday -DayOfWeekOccurrence First -TimeZone ([System.TimeZoneInfo]::Local).Id
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
    $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook02.ps1" -Raw -Encoding $AlyaUtf8Encoding
    $modules = "@{Name=`"Az.Accounts`"; Version=`$null}, @{Name=`"Az.Automation`"; Version=`$null}, @{Name=`"Az.Storage`"; Version=`$null}, @{Name=`"Az.Compute`"; Version=`$null}, @{Name=`"Az.Resources`"; Version=`$null}, @{Name=`"Az.KeyVault`"; Version=`$null}"
    if ($AvdEnabled) { $modules += ", @{Name=`"Az.DesktopVirtualization`"; Version=`$null}" }
    $rbContent = $rbContent.Replace("##AlyaModules##", $modules)
    $rbContent = $rbContent.Replace("##AlyaAzureEnvironment##", $AlyaAzureEnvironment)
    $rbContent = $rbContent.Replace("##AlyaResourceGroupName##", $ResourceGroupName)
    $rbContent = $rbContent.Replace("##AlyaAutomationAccountName##", $AutomationAccountName)
    $rbContent = $rbContent.Replace("##AlyaRunbookName##", ($AutomationAccountName+"rb02"))
    $rbContent = $rbContent.Replace("##AlyaApplicationId##", $AzAdApplication.AppId)
    $rbContent = $rbContent.Replace("##AlyaTenantId##", $Context.Tenant.Id)
    $rbContent = $rbContent.Replace("##AlyaCertificateKeyVaultName##", $keyVaultName)
    $rbContent = $rbContent.Replace("##AlyaCertificateSecretName##", $AzureCertificateName)
    $rbContent = $rbContent.Replace("##AlyaSubscriptionId##", $Context.Subscription.Id)
    $rbContent = $rbContent.Replace("##AlyaSubscriptionIds##", $AlyaSubscriptionIds)
    $rbContent = $rbContent.Replace("##AlyaTimeZone##", $AlyaTimeZone)
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
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "Monthly3AM" -StartTime ((Get-Date "03:00:00").AddDays(1)) -MonthInterval 1 -DayOfWeek Saturday -DayOfWeekOccurrence First -TimeZone ([System.TimeZoneInfo]::Local).Id
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
    $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook03.ps1" -Raw -Encoding $AlyaUtf8Encoding
    $rbContent = $rbContent.Replace("##AlyaAzureEnvironment##", $AlyaAzureEnvironment)
    $rbContent = $rbContent.Replace("##AlyaResourceGroupName##", $ResourceGroupName)
    $rbContent = $rbContent.Replace("##AlyaAutomationAccountName##", $AutomationAccountName)
    $rbContent = $rbContent.Replace("##AlyaRunbookName##", ($AutomationAccountName+"rb03"))
    $rbContent = $rbContent.Replace("##AlyaApplicationId##", $AzAdApplication.AppId)
    $rbContent = $rbContent.Replace("##AlyaTenantId##", $Context.Tenant.Id)
    $rbContent = $rbContent.Replace("##AlyaCertificateKeyVaultName##", $keyVaultName)
    $rbContent = $rbContent.Replace("##AlyaCertificateSecretName##", $AzureCertificateName)
    $rbContent = $rbContent.Replace("##AlyaSubscriptionId##", $Context.Subscription.Id)
    $rbContent = $rbContent.Replace("##AlyaSubscriptionIds##", $AlyaSubscriptionIds)
    $rbContent = $rbContent.Replace("##AlyaTimeZone##", $AlyaTimeZone)
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
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "Monthly4AM" -StartTime ((Get-Date "04:00:00").AddDays(1)) -MonthInterval 1 -DayOfWeek Saturday -DayOfWeekOccurrence First -TimeZone ([System.TimeZoneInfo]::Local).Id
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

if ($DeployStartStopVm)
{
    Write-Host "Checking automation runbook 04" -ForegroundColor $CommandInfo
    $runbookPath = "$SolutionDataRoot\$($AutomationAccountName)\$($AutomationAccountName)rb04.ps1"
    if ($AvdEnabled)
    {
        if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
        {
            $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook04avd.ps1" -Raw -Encoding $AlyaUtf8Encoding
            $rbContent = $rbContent.Replace("##AlyaAzureEnvironment##", $AlyaAzureEnvironment)
            $rbContent = $rbContent.Replace("##AlyaResourceGroupName##", $ResourceGroupName)
            $rbContent = $rbContent.Replace("##AlyaAutomationAccountName##", $AutomationAccountName)
            $rbContent = $rbContent.Replace("##AlyaRunbookName##", ($AutomationAccountName+"rb04"))
            $rbContent = $rbContent.Replace("##AlyaLocalDomainName##", $AlyaLocalDomainName)
            $rbContent = $rbContent.Replace("##AlyaApplicationId##", $AzAdApplication.AppId)
            $rbContent = $rbContent.Replace("##AlyaTenantId##", $Context.Tenant.Id)
            $rbContent = $rbContent.Replace("##AlyaCertificateKeyVaultName##", $keyVaultName)
            $rbContent = $rbContent.Replace("##AlyaCertificateSecretName##", $AzureCertificateName)
            $rbContent = $rbContent.Replace("##AlyaSubscriptionId##", $Context.Subscription.Id)
            $rbContent = $rbContent.Replace("##AlyaSubscriptionIds##", $AlyaSubscriptionIds)
            $rbContent = $rbContent.Replace("##AlyaTimeZone##", $AlyaTimeZone)
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
            $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook04.ps1" -Raw -Encoding $AlyaUtf8Encoding
            $rbContent = $rbContent.Replace("##AlyaAzureEnvironment##", $AlyaAzureEnvironment)
            $rbContent = $rbContent.Replace("##AlyaResourceGroupName##", $ResourceGroupName)
            $rbContent = $rbContent.Replace("##AlyaAutomationAccountName##", $AutomationAccountName)
            $rbContent = $rbContent.Replace("##AlyaRunbookName##", ($AutomationAccountName+"rb04"))
            $rbContent = $rbContent.Replace("##AlyaApplicationId##", $AzAdApplication.AppId)
            $rbContent = $rbContent.Replace("##AlyaTenantId##", $Context.Tenant.Id)
            $rbContent = $rbContent.Replace("##AlyaCertificateKeyVaultName##", $keyVaultName)
            $rbContent = $rbContent.Replace("##AlyaCertificateSecretName##", $AzureCertificateName)
            $rbContent = $rbContent.Replace("##AlyaSubscriptionId##", $Context.Subscription.Id)
            $rbContent = $rbContent.Replace("##AlyaSubscriptionIds##", $AlyaSubscriptionIds)
            $rbContent = $rbContent.Replace("##AlyaTimeZone##", $AlyaTimeZone)
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
}

if ($PreparePs7RuntimeEnv)
{
    Write-Host "Checking automation runbook 05" -ForegroundColor $CommandInfo
    $runbookPath = "$SolutionDataRoot\$($AutomationAccountName)\$($AutomationAccountName)rb05.ps1"
    if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
    {
        $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook05.ps1" -Raw -Encoding $AlyaUtf8Encoding
        $modules = "@{Name=`"Az.Accounts`"; Version=`$null}, @{Name=`"Az.Automation`"; Version=`$null}, @{Name=`"Az.Storage`"; Version=`$null}, @{Name=`"Az.Compute`"; Version=`$null}, @{Name=`"Az.Resources`"; Version=`$null}, @{Name=`"Az.KeyVault`"; Version=`$null}"
        if ($AvdEnabled) { $modules += ", @{Name=`"Az.DesktopVirtualization`"; Version=`$null}" }
        $rbContent = $rbContent.Replace("##AlyaModules##", $modules)
        $rbContent = $rbContent.Replace("##AlyaAzureEnvironment##", $AlyaAzureEnvironment)
        $rbContent = $rbContent.Replace("##AlyaResourceGroupName##", $ResourceGroupName)
        $rbContent = $rbContent.Replace("##AlyaAutomationAccountName##", $AutomationAccountName)
        $rbContent = $rbContent.Replace("##AlyaRunbookName##", ($AutomationAccountName+"rb05"))
        $rbContent = $rbContent.Replace("##AlyaApplicationId##", $AzAdApplication.AppId)
        $rbContent = $rbContent.Replace("##AlyaTenantId##", $Context.Tenant.Id)
        $rbContent = $rbContent.Replace("##AlyaCertificateKeyVaultName##", $keyVaultName)
        $rbContent = $rbContent.Replace("##AlyaCertificateSecretName##", $AzureCertificateName)
        $rbContent = $rbContent.Replace("##AlyaSubscriptionId##", $Context.Subscription.Id)
        $rbContent = $rbContent.Replace("##AlyaSubscriptionIds##", $AlyaSubscriptionIds)
        $rbContent = $rbContent.Replace("##AlyaTimeZone##", $AlyaTimeZone)
        $rbContent = $rbContent.Replace("##AlyaFromMail##", "DoNotReply@$($AlyaDomainName)")
        $rbContent = $rbContent.Replace("##AlyaToMail##", $AlyaSupportEmail)
        $rbContent = $rbContent.Replace("##AlyaAllExternalsGroup##", $AlyaAllExternals)
        $rbContent = $rbContent.Replace("##AlyaAllInternalsGroup##", $AlyaAllInternals)
        $rbContent | Set-Content -Path $runbookPath -Force -Encoding UTF8
    }
    $Runnbook = Get-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb05") -ErrorAction SilentlyContinue
    if (-Not $Runnbook)
    {
        Write-Warning "Automation Runbook 05 not found. Creating the Automation Runbook $($AutomationAccountName+"rb05")"
        if (-Not (Test-Path $runbookPath))
        {
            Write-Error "Can't find runbook $($runbookPath)" -ErrorAction Continue 
            Exit 3
        }
        $null = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb05") -Type PowerShell -Description "Updates required modules in the automation account" -Tags @{displayName="Module Updater"} -Path $runbookPath -Force
        $null = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb05")
        $Schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "Monthly3AM" -ErrorAction SilentlyContinue
        if (-Not $Schedule)
        {
            $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name "Monthly3AM" -StartTime ((Get-Date "03:00:00").AddDays(1)) -MonthInterval 1 -DayOfWeek Saturday -DayOfWeekOccurrence First -TimeZone ([System.TimeZoneInfo]::Local).Id
        }
        $null = Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName ($AutomationAccountName+"rb05") -ScheduleName "Monthly3AM"
    }
    else
    {
        if ($UpdateRunbooks)
        {
            Write-Host "Automation Runbook 05 found. Updating the Automation Runbook $($AutomationAccountName+"rb05")"
            $null = Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb05") -Type PowerShell -Description "Updates required modules in the automation account" -Tags @{displayName="Module Updater"} -Path $runbookPath -Force
            $null = Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb05")
        }
    }

    $reqUrl = "$($AutomationAccountId)/runtimeEnvironments?api-version=2024-10-23"
    $resp = Invoke-AzRestMethod -Method Get -Path $reqUrl
    if ($resp.StatusCode -ge 400)
    {
        throw "Error getting runtime environments: $($resp.Content)"
    }
    $runEnvs = $resp.Content | ConvertFrom-Json
    $runEnvs = $runEnvs.value | Where-Object { $_.properties.runtime.language -eq $Language }
    if (-Not $runEnvs)
    {
        throw "Can't get runtime environments"
    }
    $runtimeEnvironment = @(($runEnvs | Where-Object { $_.properties.description -notlike "System-generated*" -and $_.properties.description-like "*PowerShell*" }).Name | Sort-Object -Descending)[0]

    $reqUrl = "$($AutomationAccountId)/runbooks/$($AutomationAccountName+"rb05")?api-version=2024-10-23"
    $body = @{
        properties = @{
            runtimeEnvironment = $runtimeEnvironment
        }
    }
    $resp = Invoke-AzRestMethod -Method Patch -Path $reqUrl -Payload ($body | ConvertTo-Json -Depth 10)
}

if ($DeployGroupUpdater)
{
    Write-Host "Checking automation runbook 09" -ForegroundColor $CommandInfo
    $runbookPath = "$SolutionDataRoot\$($AutomationAccountName)\$($AutomationAccountName)rb09.ps1"
    if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
    {
        $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook09.ps1" -Raw -Encoding $AlyaUtf8Encoding
        $rbContent = $rbContent.Replace("##AlyaAzureEnvironment##", $AlyaAzureEnvironment)
        $rbContent = $rbContent.Replace("##AlyaResourceGroupName##", $ResourceGroupName)
        $rbContent = $rbContent.Replace("##AlyaAutomationAccountName##", $AutomationAccountName)
        $rbContent = $rbContent.Replace("##AlyaRunbookName##", ($AutomationAccountName+"rb09"))
        $rbContent = $rbContent.Replace("##AlyaApplicationId##", $AzAdApplication.AppId)
        $rbContent = $rbContent.Replace("##AlyaTenantId##", $Context.Tenant.Id)
        $rbContent = $rbContent.Replace("##AlyaCertificateKeyVaultName##", $keyVaultName)
        $rbContent = $rbContent.Replace("##AlyaCertificateSecretName##", $AzureCertificateName)
        $rbContent = $rbContent.Replace("##AlyaSubscriptionId##", $Context.Subscription.Id)
        $rbContent = $rbContent.Replace("##AlyaSubscriptionIds##", $AlyaSubscriptionIds)
        $rbContent = $rbContent.Replace("##AlyaTimeZone##", $AlyaTimeZone)
        $rbContent = $rbContent.Replace("##AlyaFromMail##", "DoNotReply@$($AlyaDomainName)")
        $rbContent = $rbContent.Replace("##AlyaToMail##", $AlyaSupportEmail)
        $rbContent = $rbContent.Replace("##AlyaAllExternalsGroup##", $AlyaAllExternals)
        $rbContent = $rbContent.Replace("##AlyaAllInternalsGroup##", $AlyaAllInternals)
        $rbContent = $rbContent.Replace("##AlyaDefaultTeamsGroup##", "$($AlyaCompanyNameShortM365.ToUpper())TM")
        $rbContent = $rbContent.Replace("##AlyaProjectTeamsGroup##", "$($AlyaCompanyNameShortM365.ToUpper())TM-PRJ-ProjekteIntern")
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
$Job = Start-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb01")
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
$Job = Start-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb02")
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

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDu/Ff+fnSIh7zv
# BwXKZ+jV2XfpaGEoXPM1USjovU1Jp6CCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFWXUm+8h2SJFKOj
# rEvHYCM/nZrQ5EdlKigOf57Pl4uwMA0GCSqGSIb3DQEBAQUABIICAJhaLtxAqxo6
# 4sJgGGr75xtseGIja3SWUe0Ts2oFwDKky169ONVC81rdxCNIJt5yIOstHjGX1XLX
# 8qsaSSnKDgENFV0JHXx8DKjjncZX0RHotS2r5tk6Gx4PF1lmYsezKaiqx2KwUbWE
# LhsPXO/COkULxLxlMigVVEzD5s17mX6OIgzFZXjq9tWgyl4Y5Syc7aq56oTaBDFU
# Nxo+0HUcZwtXLPEejMGrYg9ilAqpnnlbigDJmR4P+qyeDZIp0f8k/aKpojeY3QZm
# mPThStw9wb8LUYkrW7sGp2c7+f7P1ACFKFIJRDdnXZF2i9XCMfzMuKWSHQ6k6XyU
# 5++VpP3MkJTcUf+CLORJGJgNu501HgJBfIvfO7phJNRNMOATw0GC0T56h0yET1cx
# nlvuIX7YJHqx8HzeqYCUY9HT4GdQQrpsy1A1TKcGq+UEW3HTguRXWHrOocuyVa1G
# J850GGzV/mDtRqvnpN9NoAkuU82cHlLEJle7Fz4I9QL7vxOR58jiM1jp4z02Ah/n
# WTaRvGAk5E3NujIdvGq0xKcvTBOeKVuSryexwqyiZblg2MLvpxHE7pq3RY8sQGIU
# 7ICkRwxgKknqTV9NZQpzbAPxWfXcPN9Xc8oknleYIj8Himcp9Crvjtl8rSuRJwAv
# bOc2GOqe+doxlrUAT5ncoXpSM83shttzoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCBs5YQEmj9R/Ng/SSI2eWblvns9HdLzWbi6Ct3KSX/iAQIUY1A80zdWY2bb
# cot0FMXfpawCmJAYDzIwMjYwMTIwMDk0NDQwWjADAgEBoFikVjBUMQswCQYDVQQG
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
# IEolKZ/sAf2gB4GsfZhfrtshXtphxRhQZy1iL/cmxrs0MIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAKfpejF08OGcu
# Ve72b/vKPsODNbydWEDJ45K/aFYfFW9FWqjDOeaO/eKdrZ8BJNMoVATBkSaQuQEl
# DV3mALq8py6NkebsIeGOq7a/7OYyLSFxdgIMSI8oO1QOyKdPMRTxr5naPKCwKNfR
# EAVV7pUIqCdchV1DOiijK4Z9pfbpY6ShReQ+YTRr+309PkVpc0kEY51KxK768Mkm
# ltpmcEzlOlG1XcCdBF2QCPbAaqTu/Yh+uuCB7mAV3YBYauUl6ppLAI/DVmSM7xGW
# YbiEQHATOHZaVxI72h+aff5DmR8PQUF/aFK0pgMBdosflMHswOrmSyRvWtQUQSNH
# g2GSg5eDrjQOXNkIVSr8Av9D2Sotwz7XtNRo164FtmhXnTIKaSwLwKc3J9RwFox7
# 5pRR91piBulitqjXipbGea826YIQ/a1qwrJl9hb5tJA1cPlqJEE1lVJc2AZS7Ivt
# ad+bW1pV0bp1PJ5EKhlfhfaZ7bwE/NMAIS7HUsR6Hh9aNvEbfE01
# SIG # End signature block
