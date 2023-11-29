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
    13.09.2022 Konrad Brunner       Initial version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Create-AzureServiceHealthAlerts-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"

$ActionGroupNameGeneral = "Send general service alerts"
$ActionGroupNameGeneralShort = "SndGSrvcAlrt"
if ($ActionGroupNameGeneralShort.Length -gt 12) { throw "`$ActionGroupNameGeneralShort is too long. max 12 chars allowed." }
$ActionGroupNameGeneralEmails = @($AlyaGeneralInformEmail)
$ServiceHealthLogAlertNameGeneral = "Send general service alerts"

$ActionGroupNameSecurity = "Send security service alerts"
$ActionGroupNameSecurityShort = "SndSSrvcAlrt"
if ($ActionGroupNameSecurityShort.Length -gt 12) { throw "`$ActionGroupNameSecurityShort is too long. max 12 chars allowed." }
$ActionGroupNameSecurityEmails = @($AlyaSecurityEmail)
$ServiceHealthLogAlertNameSecurity = "Send security service alerts"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Monitor"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Azure | Create-AzureServiceHealthAlerts | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking resource provider registration
Write-Host "Checking resource provider registration Microsoft.Insights" -ForegroundColor $CommandInfo
$resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Insights" -Location $AlyaLocation
if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
{
    Write-Host "Resource provider Microsoft.Insights not registered. Registering now resource provider Microsoft.Insights" -ForegroundColor $CommandWarning
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
    throw "Ressource Group not found. Please create the resource group with the script Create-AzureLogAnalyticsWorkspace.ps1"
}

# Checking action group general
Write-Host "Checking action group $ActionGroupNameGeneral" -ForegroundColor $CommandInfo
$actionGroup = Get-AzActionGroup -ResourceGroupName $ResourceGroupName -Name $ActionGroupNameGeneral -ErrorAction SilentlyContinue
$recvrs = @()
foreach($recvr in $ActionGroupNameGeneralEmails)
{
    $recvrs += New-AzActionGroupEmailReceiverObject -Name ("EmailTo-"+$recvr) `
      -EmailAddress $recvr `
      -UseCommonAlertSchema $true
}
if (-Not $actionGroup) {
  Write-Warning "    Does not exist. Creating it now"
  New-AzActionGroup -Name $ActionGroupNameGeneral `
      -ResourceGroup $ResourceGroupName `
      -ShortName $ActionGroupNameGeneralShort `
      -EmailReceiver $recvrs `
      -Location "Global"
} else {
  Write-Host "    Updating"
  Update-AzActionGroup -Name $ActionGroupNameGeneral `
      -ResourceGroup $ResourceGroupName `
      -ShortName $ActionGroupNameGeneralShort `
      -EmailReceiver $recvrs
}
$actionGroup = Get-AzActionGroup -ResourceGroupName $ResourceGroupName -Name $ActionGroupNameGeneral

# Checking ServiceHealth log alert general
Write-Host "Checking ServiceHealth log alert $ServiceHealthLogAlertNameGeneral" -ForegroundColor $CommandInfo
$serviceHealthLogAlert = Get-AzActivityLogAlert -ResourceGroupName $ResourceGroupName -Name $ServiceHealthLogAlertNameGeneral -ErrorAction SilentlyContinue
if (-Not $serviceHealthLogAlert)
{
    Write-Warning "    Does not exist. Creating it now"
}
else
{
    Write-Host "    Updating"
}
$json = @"
{
  "`$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources":
  [
    {
      "type": "microsoft.insights/activityLogAlerts",
      "apiVersion": "2017-04-01",
      "name": "$ServiceHealthLogAlertNameGeneral",
      "location": "Global",
      "properties": {
        "scopes": [
          "/subscriptions/$($Context.Subscription.Id)"
        ],
        "condition": {
          "allOf": [
            {
              "field": "category",
              "equals": "ServiceHealth"
            },
            {
                "anyOf": [
                    {
                        "field": "properties.incidentType",
                        "equals": "Incident"
                    },
                    {
                        "field": "properties.incidentType",
                        "equals": "Maintenance"
                    },
                    {
                        "field": "properties.incidentType",
                        "equals": "Informational"
                    },
                    {
                        "field": "properties.incidentType",
                        "equals": "ActionRequired"
                    }
                ]
            },
            {
                "field": "properties.impactedServices[*].ImpactedRegions[*].RegionName",
                "containsAny": [
                    "Global",
                    "Switzerland North",
                    "Switzerland West",
                    "West Europe",
                    "North Europe"
                ]
            }
          ]
        },
        "actions": {
          "actionGroups": [
            {
              "actionGroupId": "$($actionGroup.Id)",
              "webhookProperties": {}
            }
          ]
        },
        "enabled": true
      }
    }
  ]
}
"@
$tempFile = New-TemporaryFile
$json | Set-Content -Path $tempFile.FullName -Encoding UTF8 -Force
New-AzResourceGroupDeployment -Name ServiceHealthLogAlertNameGeneral -ResourceGroupName $ResourceGroupName -TemplateFile $tempFile.FullName
Remove-Item -Path $tempFile.FullName -Force -ErrorAction SilentlyContinue

# Checking action group security
Write-Host "Checking action group $ActionGroupNameSecurity" -ForegroundColor $CommandInfo
$actionGroup = Get-AzActionGroup -ResourceGroupName $ResourceGroupName -Name $ActionGroupNameSecurity -ErrorAction SilentlyContinue
$recvrs = @()
foreach($recvr in $ActionGroupNameSecurityEmails)
{
    $recvrs += New-AzActionGroupEmailReceiverObject -Name ("EmailTo-"+$recvr) `
      -EmailAddress $recvr `
      -UseCommonAlertSchema $true
}
if (-Not $actionGroup) {
  Write-Warning "    Does not exist. Creating it now"
  New-AzActionGroup -Name $ActionGroupNameSecurity `
      -ResourceGroup $ResourceGroupName `
      -ShortName $ActionGroupNameSecurityShort `
      -EmailReceiver $recvrs `
      -Location "Global"
} else {
  Write-Host "    Updating"
  Update-AzActionGroup -Name $ActionGroupNameSecurity `
      -ResourceGroup $ResourceGroupName `
      -ShortName $ActionGroupNameSecurityShort `
      -EmailReceiver $recvrs
}
$actionGroup = Get-AzActionGroup -ResourceGroupName $ResourceGroupName -Name $ActionGroupNameSecurity

# Checking ServiceHealth log alert security
Write-Host "Checking ServiceHealth log alert $ServiceHealthLogAlertNameSecurity" -ForegroundColor $CommandInfo
$serviceHealthLogAlert = Get-AzActivityLogAlert -ResourceGroupName $ResourceGroupName -Name $ServiceHealthLogAlertNameSecurity -ErrorAction SilentlyContinue
if (-Not $serviceHealthLogAlert)
{
    Write-Warning "    Does not exist. Creating it now"
}
else
{
    Write-Host "    Updating"
}
$json = @"
{
  "`$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources":
  [
    {
      "type": "microsoft.insights/activityLogAlerts",
      "apiVersion": "2017-04-01",
      "name": "$ServiceHealthLogAlertNameSecurity",
      "location": "Global",
      "properties": {
        "scopes": [
          "/subscriptions/$($Context.Subscription.Id)"
        ],
        "condition": {
          "allOf": [
            {
              "field": "category",
              "equals": "ServiceHealth"
            },
            {
                "anyOf": [
                    {
                        "field": "properties.incidentType",
                        "equals": "Security"
                    }
                ]
            },
            {
                "field": "properties.impactedServices[*].ImpactedRegions[*].RegionName",
                "containsAny": [
                    "Global",
                    "Switzerland North",
                    "Switzerland West",
                    "West Europe",
                    "North Europe"
                ]
            }
          ]
        },
        "actions": {
          "actionGroups": [
            {
              "actionGroupId": "$($actionGroup.Id)",
              "webhookProperties": {}
            }
          ]
        },
        "enabled": true
      }
    }
  ]
}
"@
$tempFile = New-TemporaryFile
$json | Set-Content -Path $tempFile.FullName -Encoding UTF8 -Force
New-AzResourceGroupDeployment -Name ServiceHealthLogAlertNameSecurity -ResourceGroupName $ResourceGroupName -TemplateFile $tempFile.FullName
Remove-Item -Path $tempFile.FullName -Force -ErrorAction SilentlyContinue

#Stopping Transscript
Stop-Transcript
