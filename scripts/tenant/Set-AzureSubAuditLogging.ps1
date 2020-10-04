#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

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
    26.02.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-AzureSubAuditLogging-$($AlyaTimeString).log" | Out-Null

# Constants
$RessourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$StorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdAuditStorage)"
$LogAnaWrkspcName = "$($AlyaNamingPrefix)loga$($AlyaResIdLogAnalytics)"
$DiagnosticRuleName = "Diag-Sub-$($AlyaSubscriptionName)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-AzureSubAuditLogging | AZURE" -ForegroundColor $CommandInfo
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
$ResGrp = Get-AzResourceGroup -Name $RessourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $RessourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $RessourceGroupName -Location $AlyaLocation -Tag @{displayName="Audit Logs";ownerEmail=$Context.Account.Id}
}

# Checking storage account
Write-Host "Checking storage account" -ForegroundColor $CommandInfo
$StrgAccount = Get-AzStorageAccount -ResourceGroupName $RessourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-Not $StrgAccount)
{
    Write-Warning "Storage account not found. Creating the storage account $StorageAccountName"
    $StrgAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $RessourceGroupName -Location $AlyaLocation -SkuName "Standard_LRS" -Kind BlobStorage -AccessTier Cool -Tag @{displayName="Audit Log Storage"}
    if (-Not $StrgAccount)
    {
        Write-Error "Storage account $StorageAccountName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Checking log analytics workspace
Write-Host "Checking log analytics workspace" -ForegroundColor $CommandInfo
$LogAnaWrkspc = Get-AzOperationalInsightsWorkspace -ResourceGroupName $RessourceGroupName -Name $LogAnaWrkspcName -ErrorAction SilentlyContinue
if (-Not $LogAnaWrkspc)
{
    Write-Warning "Log analytics workspace not found. Creating the log analytics workspace $LogAnaWrkspcName"
    $LogAnaWrkspc = New-AzOperationalInsightsWorkspace -Name $LogAnaWrkspcName -ResourceGroupName $RessourceGroupName -Location $AlyaLocation -Sku Standard -Tag @{displayName="Audit Log Workspace"}
    if (-Not $LogAnaWrkspc)
    {
        Write-Error "Log analytics workspace $StorageAccountName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Setting auditing on subscription
Write-Host "Setting auditing on subscription" -ForegroundColor $CommandInfo
$subscriptionId = (Get-AzSubscription -SubscriptionName $($AlyaSubscriptionName)).Id
$token = Get-AzAccessToken("https://management.azure.com/")
$uri = "https://management.azure.com/subscriptions/{0}/providers/microsoft.insights/diagnosticSettings/{1}?api-version=2017-05-01-preview" -f $subscriptionId, $DiagnosticRuleName
$body = @"
{
  "name": "$($DiagnosticRuleName)",
  "properties": {
    "logs": [
      {
        "category": "Administrative",
        "enabled": true
      },
      {
        "category": "Security",
        "enabled": true
      },
      {
        "category": "ServiceHealth",
        "enabled": true
      },
      {
        "category": "Alert",
        "enabled": true
      },
      {
        "category": "Recommendation",
        "enabled": true
      },
      {
        "category": "Policy",
        "enabled": true
      },
      {
        "category": "Autoscale",
        "enabled": true
      },
      {
        "category": "ResourceHealth",
        "enabled": true
      }
    ],
    "metrics": [],
    "storageAccountId": "$($StrgAccount.Id)",
    "workspaceId": "$($LogAnaWrkspc.ResourceId)"
  }
}
"@
$headers = @{
    "Authorization" = "Bearer $($token)"
    "Content-Type"  = "application/json"
}
$response = Invoke-WebRequest -Method Put -Uri $uri -Body $body -Headers $headers

if ($response.StatusCode -ne 200) {
    throw "An error occured setting diagnostic settings on subscription: $($response | out-string)"

}

#Stopping Transscript
Stop-Transcript