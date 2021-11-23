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
Install-ModuleIfNotInstalled "Az"
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

# Checking ressource group
Write-Host "Checking ressource group for keyvault" -ForegroundColor $CommandInfo
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

# Checking azure key vault certificate
Write-Host "Checking azure key vault certificate" -ForegroundColor $CommandInfo
$AzureCertifcateAssetName = "AzureRunAsCertificate"
$AzureCertificateName = $AutomationAccountName + $AzureCertifcateAssetName
$AzureKeyVaultCertificate = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertificateName -ErrorAction SilentlyContinue
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
    $CertificateRetrieved = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzureCertificateName
    $CertificateBytes = $CertificateRetrieved.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    [System.IO.File]::WriteAllBytes($CerCertPathForRunAsAccount, $CertificateBytes)
    #Read the .pfx file 
    $PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)
    $KeyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())
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
        $AzureAdApplication = New-AzADApplication -DisplayName $AutomationAccountName -HomePage $HomePageUrl -IdentifierUris ("http://" + $KeyId)
        $AzureAdServicePrincipal = New-AzADServicePrincipal -ApplicationId $AzureAdApplication.ApplicationId

        #Create credential 
        $AzureAdApplicationCredential = New-AzADAppCredential -ApplicationId $AzureAdApplication.ApplicationId -CertValue $KeyValue -StartDate $startDate -EndDate $endDate 

        #Application access rights
        $RoleAssignment = $null
        $Retries = 0;
        While ($RoleAssignment -eq $null -and $Retries -le 6)
        {
            $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $AzureAdApplication.ApplicationId -scope ("/subscriptions/" + $Context.Subscription.Id) -ErrorAction SilentlyContinue
            Start-Sleep -s 10
            $RoleAssignment = Get-AzRoleAssignment -ServicePrincipalName $AzureAdApplication.ApplicationId -ErrorAction SilentlyContinue
            $Retries++;
        }

        #Setting its own as owner (required for automated cert updates)
        $AdAzureAdApplication = Get-AzureADApplication -Filter "AppId eq '$($AzureAdApplication.ApplicationId)'"
        $AdAzureAdServicePrincipal = Get-AzureADServicePrincipal -Filter "AppId eq '$($AzureAdApplication.ApplicationId)'"
        Add-AzureADApplicationOwner -ObjectId $AdAzureAdApplication.ObjectId -RefObjectId $AdAzureAdServicePrincipal.ObjectId

        #Granting permissions
        $AppPermissionAdGraph = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "824c81eb-e3f8-4ee6-8f6d-de7f50d565b7","Role"
        $RequiredResourceAccessAdGraph = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
        $RequiredResourceAccessAdGraph.ResourceAppId = "00000002-0000-0000-c000-000000000000"
        $RequiredResourceAccessAdGraph.ResourceAccess = $AppPermissionAdGraph

        $AppPermissionMsGraph = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "18a4783c-866b-4cc7-a460-3d5e5662c884","Role"
        $RequiredResourceAccessMsGraph = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
        $RequiredResourceAccessMsGraph.ResourceAppId = "00000003-0000-0000-c000-000000000000"
        $RequiredResourceAccessMsGraph.ResourceAccess = $AppPermissionMsGraph

        Set-AzureADApplication -ObjectId $AdAzureAdApplication.ObjectId -RequiredResourceAccess $RequiredResourceAccessAdGraph, $RequiredResourceAccessMsGraph, $RequiredResourceAccessSharePoint
        $tmp = Get-AzureADApplication -ObjectId $AdAzureAdApplication.ObjectId
        while ($tmp.RequiredResourceAccess.Count -lt 2)
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
            $url = "https://main.iam.ad.ext.azure.com/api/RegisteredApplications/$($AzureAdApplication.ApplicationId)/Consent?onBehalfOfAll=true"
            Invoke-RestMethod -Uri $url -Headers $header -Method POST -ErrorAction Stop
            #TODO consent was working?
            Write-Warning "Please check in portal if admin consent was working"
        }
    }
    else
    {
        $AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AutomationAccountName
    }

    # Checking automation certificate asset
    Write-Host "Checking automation certificate asset" -ForegroundColor $CommandInfo
    $AutomationCertificate = Get-AzAutomationCertificate -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $AzureCertifcateAssetName -ErrorAction SilentlyContinue
    if (-Not $AutomationCertificate)
    {
        Write-Warning "Automation Certificate not found. Creating the Automation Certificate $AzureCertifcateAssetName"
        $CertPassword = ConvertTo-SecureString $PfxCertPlainPasswordForRunAsAccount -AsPlainText -Force
        New-AzAutomationCertificate -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $AzureCertifcateAssetName -Path $PfxCertPathForRunAsAccount -Password $CertPassword -Exportable
    }
    #Remove-AzAutomationCertificate -ResourceGroupName -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $AzureCertificateName -ErrorAction SilentlyContinue

}
finally
{
    #Removing exported certificate
    Remove-Item -Path $PfxCertPathForRunAsAccount -Force | Out-Null
    Remove-Item -Path $CerCertPathForRunAsAccount -Force | Out-Null
}

# Populate the ConnectionFieldValues
$ConnectionTypeName = "AzureServicePrincipal"
$ConnectionAssetName = "AzureRunAsConnection"
$ConnectionFieldValues = @{"ApplicationId" = $AzureAdApplication.ApplicationId; "TenantId" = $Context.Tenant.Id; "CertificateThumbprint" = $PfxCert.Thumbprint; "SubscriptionId" = $Context.Subscription.Id} 

# Create an Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
Write-Host "Checking automation connection asset" -ForegroundColor $CommandInfo
$AutomationConnection = Get-AzAutomationConnection -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $ConnectionAssetName -ErrorAction SilentlyContinue
if (-Not $AutomationConnection)
{
    Write-Warning "Automation Connection not found. Creating the Automation Connection $ConnectionAssetName"
    New-AzAutomationConnection -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $ConnectionAssetName -ConnectionTypeName $ConnectionTypeName -ConnectionFieldValues $ConnectionFieldValues 
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
            $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AzureAdServicePrincipal.ApplicationId, $appKeySec
            New-AzAutomationCredential -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $asset -Value $Credential
        }
        #Remove-AutomationCredential -ResourceGroupName $ResourceGroupOMS -automationAccountName $AutomationAccountName -Name $asset -Force -ErrorAction SilentlyContinue
    }
}

# Publish runbooks
Write-Host "Checking automation runbooks" -ForegroundColor $CommandInfo
$runbookPath = "$SolutionDataRoot\$($AutomationAccountName)rb01.ps1"
if (-Not (Test-Path $runbookPath))
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
    $Schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName –Name "Monthly2AM" -ErrorAction SilentlyContinue
    if (-Not $Schedule)
    {
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName –Name "Monthly2AM" -StartTime ((Get-Date "02:00:00").AddDays(1)) -MonthInterval 1 -DaysOfMonth One -TimeZone ([System.TimeZoneInfo]::Local).Id
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
$runbookPath = "$SolutionDataRoot\$($AutomationAccountName)rb02.ps1"
if (-Not (Test-Path $runbookPath))
{
    $rbContent = Get-Content -Path "$SolutionScriptsRoot\runbook02.ps1" -Raw -Encoding UTF8
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
    $Schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName –Name "Monthly3AM" -ErrorAction SilentlyContinue
    if (-Not $Schedule)
    {
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName –Name "Monthly3AM" -StartTime ((Get-Date "03:00:00").AddDays(1)) -MonthInterval 1 -DaysOfWeek Sunday -DayOfWeekOccurrence First -TimeZone ([System.TimeZoneInfo]::Local).Id
    }
    $JobParams = @{"SubscriptionName"=$AlyaSubscriptionName;"ResourceGroupName"=$ResourceGroupName;"AutomationAccountName"=$AutomationAccountName;"AzureEnvironment"="AzureCloud"}
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
$runbookPath = "$SolutionDataRoot\$($AutomationAccountName)rb03.ps1"
if (-Not (Test-Path $runbookPath))
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
    $Schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName –Name "Monthly4AM" -ErrorAction SilentlyContinue
    if (-Not $Schedule)
    {
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName –Name "Monthly4AM" -StartTime ((Get-Date "04:00:00").AddDays(1)) -MonthInterval 1 -DaysOfMonth One -TimeZone ([System.TimeZoneInfo]::Local).Id
    }
    $JobParams = @{"ResourceGroupName"=$ResourceGroupName;"AutomationAccountName"=$AutomationAccountName;"SubscriptionName"=$AlyaSubscriptionName;"AzureEnvironment"="AzureCloud"}
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
$runbookPath = "$SolutionDataRoot\$($AutomationAccountName)rb04.ps1"
if ($AlyaWvdTenantNameProd)
{
    if (-Not (Test-Path $runbookPath))
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
    if (-Not (Test-Path $runbookPath))
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
    $Schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName –Name "Hourly" -ErrorAction SilentlyContinue
    if (-Not $Schedule)
    {
        $Schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName –Name "Hourly" -StartTime ((Get-Date "00:10:00").AddDays(1)) -HourInterval 1 -TimeZone ([System.TimeZoneInfo]::Local).Id
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

# ===============================================
# Starting runbooks
# ===============================================

Write-Host "`n`n=======================================" -ForegroundColor $CommandInfo
Write-Host "STARTING RUNBOOKS" -ForegroundColor $CommandInfo
Write-Host "=======================================`n" -ForegroundColor $CommandInfo

#Running runbooks 01 and 02
Write-Host "Starting module update" -ForegroundColor $CommandInfo
Write-Host "  Please wait..."
$JobParams = @{"ResourceGroupName"=$ResourceGroupName;"AutomationAccountName"=$AutomationAccountName;"AzureModuleClass"="AzureRm";"AzureEnvironment"="AzureCloud"}
$Job = Start-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb01") -Parameters $JobParams
$doLoop = $true
While ($doLoop) {
    Start-Sleep -Seconds 15
    $Job = Get-AzAutomationJob –AutomationAccountName $AutomationAccountName -Id $Job.JobId -ResourceGroupName $ResourceGroupName
    $Status = $Job.Status
    $doLoop = (($Status -ne "Completed") -and ($Status -ne "Failed") -and ($Status -ne "Suspended") -and ($Status -ne "Stopped"))
}
(Get-AzAutomationJobOutput –AutomationAccountName $AutomationAccountName -Id $Job.JobId -ResourceGroupName $ResourceGroupName –Stream Output).Summary
Write-Host "  Job status: "$($Job.Status)

Write-Host "Starting module installation" -ForegroundColor $CommandInfo
Write-Host "  Please wait..."
$JobParams = @{"ResourceGroupName"=$ResourceGroupName;"AutomationAccountName"=$AutomationAccountName;"SubscriptionName"=$AlyaSubscriptionName;"AzureEnvironment"="AzureCloud"}
$Job = Start-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name ($AutomationAccountName+"rb02") -Parameters $JobParams
$doLoop = $true
While ($doLoop) {
    Start-Sleep -Seconds 15
    $Job = Get-AzAutomationJob –AutomationAccountName $AutomationAccountName -Id $Job.JobId -ResourceGroupName $ResourceGroupName
    $Status = $Job.Status
    $doLoop = (($Status -ne "Completed") -and ($Status -ne "Failed") -and ($Status -ne "Suspended") -and ($Status -ne "Stopped"))
}
(Get-AzAutomationJobOutput –AutomationAccountName $AutomationAccountName -Id $Job.JobId -ResourceGroupName $ResourceGroupName –Stream Output).Summary
Write-Host "  Job status: "$($Job.Status)

#Stopping Transscript
Stop-Transcript