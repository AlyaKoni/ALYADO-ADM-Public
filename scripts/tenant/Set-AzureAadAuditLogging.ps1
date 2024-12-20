﻿#Requires -Version 2.0

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
    26.02.2020 Konrad Brunner       Initial Version
    05.01.2021 Konrad Brunner       Fixed provider registration
	16.08.2021 Konrad Brunner		Added provider registration

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-AzureAadAuditLogging-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$StorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdAuditStorage)"
$LogAnaWrkspcName = "$($AlyaNamingPrefix)loga$($AlyaResIdLogAnalytics)"
$DiagnosticRuleName = "Diag-Aad-$($AlyaSubscriptionName)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Storage"
Install-ModuleIfNotInstalled "Az.OperationalInsights"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-AzureAadAuditLogging | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking resource provider registration
Write-Host "Checking resource provider registration Microsoft.Storage" -ForegroundColor $CommandInfo
$resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Storage" -Location $AlyaLocation
if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
{
    Write-Warning "Resource provider Microsoft.Storage not registered. Registering now resource provider Microsoft.Storage"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Storage" | Out-Null
    do
    {
        Start-Sleep -Seconds 5
        $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Storage" -Location $AlyaLocation
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

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ResourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $ResourceGroupName -Location $AlyaLocation -Tag @{displayName="Audit Logs";ownerEmail=$Context.Account.Id}
}

# Checking storage account
Write-Host "Checking storage account" -ForegroundColor $CommandInfo
$StrgAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-Not $StrgAccount)
{
    Write-Warning "Storage account not found. Creating the storage account $StorageAccountName"
    $StrgAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -SkuName "Standard_LRS" -Kind BlobStorage -AccessTier Cool -Tag @{displayName="Audit Log Storage"}
    if (-Not $StrgAccount)
    {
        Write-Error "Storage account $StorageAccountName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Checking log analytics workspace
Write-Host "Checking log analytics workspace" -ForegroundColor $CommandInfo
$LogAnaWrkspc = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $LogAnaWrkspcName -ErrorAction SilentlyContinue
if (-Not $LogAnaWrkspc)
{
    Write-Warning "Log analytics workspace not found. Creating the log analytics workspace $LogAnaWrkspcName"
    $LogAnaWrkspc = New-AzOperationalInsightsWorkspace -Name $LogAnaWrkspcName -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -Sku "pergb2018" -Tag @{displayName="Audit Log Workspace"} -RetentionInDays 180
    if (-Not $LogAnaWrkspc)
    {
        Write-Error "Log analytics workspace $StorageAccountName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Setting auditing on azure active directory
Write-Host "Setting auditing on azure active directory" -ForegroundColor $CommandInfo
$token = Get-AzAccessToken -audience "https://management.azure.com/"
$headers = @{
    "Authorization" = "Bearer $($token)"
    "Content-Type"  = "application/json"
}
#$uri = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" -f $DiagnosticRuleName
#$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
#TODO Sign in values for different license types
$body = @"
{
    "name": "$($DiagnosticRuleName)",
    "properties": {
        "logs": [{
                "category": "AuditLogs",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "SignInLogs",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "NonInteractiveUserSignInLogs",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "ServicePrincipalSignInLogs",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "ManagedIdentitySignInLogs",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "ProvisioningLogs",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "ADFSSignInLogs",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "RiskyUsers",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "UserRiskEvents",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "NetworkAccessTrafficLogs",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "RiskyServicePrincipals",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "ServicePrincipalRiskEvents",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "B2CRequestLogs",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "EnrichedOffice365AuditLogs",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "MicrosoftGraphActivityLogs",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "RemoteNetworkHealthLogs",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }, {
                "category": "NetworkAccessAlerts",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }
        ],
        "metrics": [],
        "storageAccountId": "$($StrgAccount.Id)",
        "workspaceId": "$($LogAnaWrkspc.ResourceId)"
  }
}
"@
$method = "Put"
$uri = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/{0}?api-version=2017-04-01-preview" -f $DiagnosticRuleName
$response = Invoke-WebRequestIndep -Method $method -Uri $uri -Body $body -Headers $headers

if ($response.StatusCode -ne 200) {
    throw "An error occured setting diagnostic settings on azure active directory: $($response | out-string)"
}

# Checking missing logs
Write-Host "Checking missing logs" -ForegroundColor $CommandInfo
$method = "Get"
$uri = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/{0}?api-version=2017-04-01-preview" -f $DiagnosticRuleName
$response = Invoke-WebRequestIndep -Method $method -Uri $uri -Headers $headers
$cats = $response.Content | ConvertFrom-Json
foreach($log in ($cats.properties.logs | Where-Object { $_.enabled -eq $false}))
{
    Write-Warning "Log $($log.Category) was not enabled. Please update this script!"
    $log.enabled = $true
}
$body = $cats | ConvertTo-Json -Depth 10
$method = "Put"
$uri = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/{0}?api-version=2017-04-01-preview" -f $DiagnosticRuleName
$response = Invoke-WebRequestIndep -Method $method -Uri $uri -Body $body -Headers $headers

#Stopping Transscript
Stop-Transcript
