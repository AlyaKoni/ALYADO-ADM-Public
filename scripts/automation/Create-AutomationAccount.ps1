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
    14.11.2019 Konrad Brunner       Initial Version
    31.05.2023 Konrad Brunner       Fixes and enhancements
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Creates and configures an Azure Automation Account with necessary identities, permissions, key vault access, and runbooks.

.DESCRIPTION
The Create-AutomationAccount.ps1 script automates the creation and configuration of an Azure Automation Account within a defined resource group. It ensures required Azure modules are installed, resource providers are registered, and necessary infrastructure such as Key Vaults, resource groups, and log analytics workspaces are available. The script sets RBAC permissions for users, managed identities, and automation service principals. It creates and assigns certificates, RunAs accounts, and associated Azure AD applications. The script optionally deploys additional runbooks for group updating, VM start/stop automation, and PowerShell 7 runtime environment preparation. It also manages diagnostic settings and module update automation.

.PARAMETER UpdateRunbooks
Indicates whether existing runbooks should be updated or recreated. Default is $true.

.PARAMETER DeployGroupUpdater
Specifies whether to deploy the runbook responsible for updating Azure AD groups such as AllInternals and AllExternals. Default is $false.

.PARAMETER DeployStartStopVm
Indicates whether to deploy and schedule the runbook responsible for starting and stopping virtual machines based on defined tag times. Default is $true.

.PARAMETER PreparePs7RuntimeEnv
Specifies whether to set up and configure PowerShell 7 runtime environments within the automation account. Default is $true.

.INPUTS
None. The script uses environmental variables defined in the loaded configuration script.

.OUTPUTS
Log file written to the automation logs directory summarizing execution steps and results.

.EXAMPLE
PS> .\Create-AutomationAccount.ps1 -UpdateRunbooks $true -DeployGroupUpdater $true -DeployStartStopVm $true -PreparePs7RuntimeEnv $true

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [bool]$UpdateRunbooks = $true,
    [bool]$DeployGroupUpdater = $false,
    [bool]$DeployStartStopVm = $true,
    [bool]$PreparePs5Runbooks = $false,
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
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"
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
    Set-AzKeyVaultAccessPolicy -VaultName $KeyVault.VaultName -ObjectId $user.Id -PermissionsToCertificates "All" -PermissionsToSecrets "All" -PermissionsToKeys "All" -PermissionsToStorage "All" -ErrorAction Continue
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
        $servicePrincipalId = $AzAdServicePrincipal.Id
        foreach($resourceAccess in $params.RequiredResourceAccess)
        {
            $appId = $resourceAccess.ResourceAppId
            $app = Get-MgBetaServicePrincipal -Filter "AppId eq '$appId'" -Property "*"
            $perms = $resourceAccess.ResourceAccess
            $scopes = ($app.PublishedPermissionScopes | Where-Object { $_.Id -in $perms.Id }).Value -join " "
            if ($scopes -and @($scopes).Count -gt 0)
            {
                try {
                    New-MgBetaOauth2PermissionGrant -ClientId $servicePrincipalId -ConsentType "AllPrincipals" -ResourceId $app.Id -Scope $scopes -ExpiryTime ([DateTime]::MaxValue)
                }
                catch {
                    Write-Error $_.Exception -ErrorAction Continue
                    Write-Warning "Principal admin consent was not working. Please check in portal if principal admin consent was given to application '$servicePrincipalId'!"
                }
            }
            foreach($perm in ($perms | Where-Object { $_.Type -eq "Role" }))
            {
                $extAss = Get-MgBetaServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipalId -All | Where-Object { $_.ResourceId -eq $app.Id -and $_.AppRoleId -eq $perm.Id }
                if (-Not $extAss)
                {
                    try {
                        New-MgBetaServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipalId -PrincipalId $servicePrincipalId -ResourceId $app.Id -AppRoleId $perm.Id
                    }
                    catch {
                        Write-Error $_.Exception -ErrorAction Continue
                        Write-Warning "Principal admin consent was not working. Please check in portal if principal admin consent was given to application '$servicePrincipalId'!"
                    }
                }
            }
        }
    }
    else
    {
        $AzAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $RunasAppName | Where-Object { $_.AppId -eq $AzAdApplication.AppId }
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
}

# Publish runbooks
if (-Not (Test-Path "$SolutionDataRoot\$($AutomationAccountName)"))
{
    New-Item -Path "$SolutionDataRoot\$($AutomationAccountName)" -ItemType Directory -Force
}

if ($PreparePs5Runbooks)
{

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
if ($PreparePs7RuntimeEnv)
{
    $reqUrl = "$($AutomationAccountId)/runbooks/$($AutomationAccountName+"rb03")?api-version=2024-10-23"
    $body = @{
        properties = @{
            runtimeEnvironment = $runtimeEnvironment
        }
    }
    $resp = Invoke-AzRestMethod -Method Patch -Path $reqUrl -Payload ($body | ConvertTo-Json -Depth 10)
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
    if ($PreparePs7RuntimeEnv)
    {
        $reqUrl = "$($AutomationAccountId)/runbooks/$($AutomationAccountName+"rb04")?api-version=2024-10-23"
        $body = @{
            properties = @{
                runtimeEnvironment = $runtimeEnvironment
            }
        }
        $resp = Invoke-AzRestMethod -Method Patch -Path $reqUrl -Payload ($body | ConvertTo-Json -Depth 10)
    }
}

if ($PreparePs7RuntimeEnv)
{
    Write-Host "Checking automation runbook 05" -ForegroundColor $CommandInfo
    $runbookPath = "$SolutionDataRoot\$($AutomationAccountName)\$($AutomationAccountName)rb05.ps1"
    if (-Not (Test-Path $runbookPath) -or $UpdateRunbooks)
    {
        $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook05.ps1" -Raw -Encoding $AlyaUtf8Encoding
        $modules = ""
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
    if ($PreparePs7RuntimeEnv)
    {
        $reqUrl = "$($AutomationAccountId)/runbooks/$($AutomationAccountName+"rb09")?api-version=2024-10-23"
        $body = @{
            properties = @{
                runtimeEnvironment = $runtimeEnvironment
            }
        }
        $resp = Invoke-AzRestMethod -Method Patch -Path $reqUrl -Payload ($body | ConvertTo-Json -Depth 10)
    }
}

# ===============================================
# Starting runbooks
# ===============================================

Write-Host "`n`n=======================================" -ForegroundColor $CommandInfo
Write-Host "STARTING RUNBOOKS" -ForegroundColor $CommandInfo
Write-Host "=======================================`n" -ForegroundColor $CommandInfo

if ($PreparePs5Runbooks)
{

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

}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIwlQYJKoZIhvcNAQcCoIIwhjCCMIICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAWOksMa+ijFQHq
# b34blQgiAf0gd/g/Dzr8OyITqRoXWaCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# giEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHYyAstjK2/5x70V
# sQVffopPBy5g4oaVYo3VLPXOJOauMA0GCSqGSIb3DQEBAQUABIICAE1oV+8tM8kx
# UmkplcmwoSoymnMoOZCjMFr+CCtjMqYPlX5DXlrvEwf0tNqZd3XWJlpgb8ujpXjX
# 8lZNsmBiX0Ua2gj0xGNRI68Pbckul3mWWLwGYxlFRY3ojrxXmKB3dB3AzeNyTlXB
# d2b/dD9TFpwSQ59V92h4rdoYTeNvkkyuUE7sO0j1tTaAP/O2OapfheHazcpTby5J
# KO+y/EsPP5/ih5EK2EW9AcSqQU0Ld/E5kAh6l3vE+jBIBnSRMfV2/CikHOA92HQl
# zrgJGGcHJZIh2tNulZiMDJcogFTfnBMNI4u6HmNn+e2luqzJxV5kZZvlXhhWK9Wb
# YDR0BLN6cxqN8kJUmKP9E5tFE1Kh1NdIQZpc5G/xvUJ9gtb5xh2ypg9jIKlTFJJ7
# mZz/w9N7L102NUTv6LrB99jlsyJSVdEitpdfK95l4jPdga0p3k6u4domWBxXZwL8
# sNFM3lWKKMtV9K6wudSXRIxKWQDG8fWBX2qS+mAMTCnNboYBb4t9ohVBMNeImcOw
# s4OIF641k4ZoD7oAu/UEPO1JCCLVXpxBG8WtIT448O7RWAgxJyH2bopWZVKuXZFz
# rGM1s0GI/+5QR1RlG8IEhtY9aq6UuLHKyRLJab9E7BKgqb6AWGLJggDY/yudPO4b
# YyFh+adv0WiFUN5Jf2KyB8dKi8H6jXOpoYId7TCCHekGCisGAQQBgjcDAwExgh3Z
# MIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIwgeQGCyqG
# SIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCGSAFlAwQC
# AQUABCBJliT8sQELdGRaqUmtpkv8fgyYc/dnun6uhg9Veuf2eAIUOX8xDyl5ivCp
# nSSouml/YF0FcNQYDzIwMjYwNTEyMTAzMjIyWjADAgEBoF2kWzBZMQswCQYDVQQG
# EwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFs
# c2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCCBHKgAwIB
# AgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNp
# Z24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUxMDE1MDcy
# NTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xv
# YmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNBIGZvciBD
# b2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDR
# So2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6rVD8pgy1
# sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6qADUMn96m
# qHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6CjX0t3wJfh
# L0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHux0InYS7R
# r54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKOC7QkFbkl
# hPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ0SoibbUq
# xsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQbPGs02Ba
# 8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+TfueCIU0C
# AwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEF
# BQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8dPIxlNigG
# GTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYBBQUHAQEE
# gZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dz
# b2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0cDovL3Nl
# Y3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGltZXN0YW1w
# Y2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmdsb2JhbHNp
# Z24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYDVR0gBE8w
# TTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8v
# d3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBDAUAA4IC
# AQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOfBvhcvoFQ
# w4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SCNLHs6vCg
# 6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdByiHteLxgj
# ugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRWLzPVcUkR
# k9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZsH8EXwiT
# UTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdPL/F8VCMK
# j3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWIV3hgRl+V
# yKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/xCB0/lSK
# LnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJsnmVbS0x
# 50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5+6PokOkQ
# 8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSIoAMCAQIC
# EQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNVBAYTAkJF
# MRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWdu
# IFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00MTA3MTYw
# MDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNh
# MTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFtcGluZyBD
# QSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW+O19i+Ld
# AoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzoZ3nN0CMn
# cZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hfGMG4PJvY
# FvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSaZKraMxFt
# 676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJexYwEVU0
# GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVrYXEdhfVL
# wuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfFJC4P5FW1
# SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z8oTvSaSI
# REovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDzPk+UbLmg
# ZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlTZbVHdqNi
# u0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxUYgoVSxqb
# 4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1UdDwEB/wQE
# AwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/AgEAMB0G
# A1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRGshx34XsV
# 8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcwAYYraHR0
# cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBEBggrBgEF
# BQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvdGltZXN0
# YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAIMAYGBFUd
# IAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1n//quXGL
# VfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM+YjPEf8A
# tC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3yZ6Vcu6Ha
# 0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8njTvAwaT
# MGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534nUINB9whO
# RicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+sQdBidnP
# uLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTfd4yw4nQd
# k1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7NacoTVxZnKG
# kv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZxci6TX78
# smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDXQbEfa93l
# hikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6DC74n5+O5
# bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkqhkiG9w0B
# AQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UE
# ChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEyMDkwMDAw
# MDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBS
# b290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0M+wn3BI4
# IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0lHI7cQ0a
# 72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/WrNU0Pn1k7
# 9S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8NyiwAS+CA6
# YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOooMUz5IWqo
# zfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+PuNF2cvN8
# oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMsDpt3UCA0
# QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvbQhQFB6r7
# FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6SW/bPnf+
# uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jhan+HKd45
# m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32xRdvPBUQ
# sA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNVHQ8BAf8E
# BAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
# HQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwFo5MT4qLn
# 4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJodHRwOi8v
# b2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9odHRwOi8v
# c2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2BgNVHR8E
# LzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3Js
# MEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5n
# bG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAi0i6
# Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l74Z/4omN
# laV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VPZnpmqUdU
# M7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+CLDZZCv5
# 6vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPVSbj/S9Il
# T0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTVha1Fe7Wf
# uy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXeP6Z/xyjv
# oW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb5O1mjj2A
# naSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZmIVHCh5i
# 2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDaI4lgH4Nx
# krXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvxbwPBKVLi
# lL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgECAg5F5rsD
# gzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWdu
# IFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xv
# YmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMaw
# iGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjI
# ElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0y
# BqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3
# YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHN
# V5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTah
# b1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV
# 2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9
# ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmF
# zzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT
# 6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEw
# DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOT
# E+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1Og
# MA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jW
# ZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMT
# VlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgH
# M3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3b
# mZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9Bx
# gXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1e
# bcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRg
# emSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2Zla
# tJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQl
# p7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l3
# 1VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MF
# WsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2Jh
# bFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBSNDUgVGlt
# ZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCGSAFlAwQC
# AqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3DQEJNDEe
# MBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJBDEyBDDx
# R6hQtFtWTNUCLWOExG7u9+dbnIYKWjFc+Rv7jozbQwwrY48ByePqTIYz3g+R19Yw
# gbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS858bMJhdk
# iChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xv
# YmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5lIFI0NSBU
# aW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcN
# AQEMBQAEggGAeuszYFCepxZhO8mQ+eujzwHx2M/TA1q9p/KbbRfK4HOMGaLDV1w1
# 8j1cVyXT+VdCl1sfvNtK/vhJnUi4OACxRLNRfvJmkvmSM6w2a3Xg2wQSBQIqeDwm
# 0ALVIoaE8Puy7i8D9NEvbJ3NBH7oSp9Ge8C0hZAs3WxeaURDd8Hun+hiotMn9Bwv
# zXDzmDbNocZ944gk2QuQqRRPCQ4yC3JheO7pz8V216lTEWJzF+sPsvBRSIMtQCT7
# fHTZLUrpUVBsrAqN1llkPAlU9HZ9YosPfYN1tMABAHClAY95KrKYrV2xuwgdFp8S
# N1E69L3X+iz3/siBw8TBwH9SOVqhAG6S6uUL4BbVTbb78YaUsmFNx0cuUq7RCvyQ
# 5CzTecR6gqrv15mlJFwKzdEQC+XHxRK7empYX+4b2M0JfMI2yYSn8iWI91YP2Kiu
# lDgI2mlu+VSvjhUEdVwwP/4xAsBxDl4ebtbwVzKZSasW7V2ZGqkBjZi1jaKoCRpm
# sj3yoU/pzfKa
# SIG # End signature block
