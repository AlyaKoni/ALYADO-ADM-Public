#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2022

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
    13.09.2022 Konrad Brunner       Initial version

    TODO: rule not showing up in Service Health / Resource Health
#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Create-AzureResourceHealthAlerts-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$ActionGroupNameGeneral = "Send resource alerts"
$ActionGroupNameGeneralEmails = @($AlyaGeneralInformEmail)
$ResourceHealthLogAlertNameGeneral = "Send resource alerts"

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
Write-Host "Azure | Create-AzureResourceHealthAlerts | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# adding actual user to email recipients
#if ($ActionGroupNameGeneralEmails -notcontains $Context.Account.Id)
#{
#    $ActionGroupNameGeneralEmails += $Context.Account.Id
#}

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

# Checking action group general
Write-Host "Checking action group $ActionGroupNameGeneral" -ForegroundColor $CommandInfo
$actionGroup = Get-AzActionGroup -ResourceGroupName $ResourceGroupName -Name $ActionGroupNameGeneral -ErrorAction SilentlyContinue
if (-Not $actionGroup) {
    Write-Warning "    Does not exist. Creating it now"
} else {
    Write-Host "    Updating"
}
$recvrs = @()
foreach($recvr in $ActionGroupNameGeneralEmails)
{
    $recvrs += New-AzActionGroupReceiver -Name ("EmailTo-"+$recvr) `
                    -EmailReceiver `
                    -EmailAddress $recvr `
                    -UseCommonAlertSchema:$true
}
Set-AzActionGroup -Name $ActionGroupNameGeneral `
    -ResourceGroup $ResourceGroupName `
    -ShortName "Send alerts" `
    -Receiver $recvrs
$actionGroup = Get-AzActionGroup -ResourceGroupName $ResourceGroupName -Name $ActionGroupNameGeneral

# Checking ResourceHealth log alert general
Write-Host "Checking ResourceHealth log alert $ResourceHealthLogAlertNameGeneral" -ForegroundColor $CommandInfo
$ResourceHealthLogAlert = Get-AzActivityLogAlert -ResourceGroupName $ResourceGroupName -Name $ResourceHealthLogAlertNameGeneral -ErrorAction SilentlyContinue
if (-Not $ResourceHealthLogAlert)
{
    Write-Warning "    Does not exist. Creating it now"
}
else
{
    Write-Host "    Updating"
}
$json = @"
{
    "`$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "resources": [
        {
            "type": "Microsoft.Insights/activityLogAlerts",
            "apiVersion": "2017-04-01",
            "name": "$ResourceHealthLogAlertNameGeneral",
            "location": "Global",
            "properties": {
                "enabled": true,
                "scopes": [
                    "/subscriptions/$($Context.Subscription.Id)"
                ],
                "condition": {
                    "allOf": [
                        {
                            "field": "category",
                            "equals": "ResourceHealth",
                            "containsAny": null
                        },
                        {
                            "anyOf": [
                                {
                                    "field": "properties.currentHealthStatus",
                                    "equals": "Available",
                                    "containsAny": null
                                },
                                {
                                    "field": "properties.currentHealthStatus",
                                    "equals": "Unavailable",
                                    "containsAny": null
                                },
                                {
                                    "field": "properties.currentHealthStatus",
                                    "equals": "Degraded",
                                    "containsAny": null
                                }
                            ]
                        },
                        {
                            "anyOf": [
                                {
                                    "field": "properties.previousHealthStatus",
                                    "equals": "Available",
                                    "containsAny": null
                                },
                                {
                                    "field": "properties.previousHealthStatus",
                                    "equals": "Unavailable",
                                    "containsAny": null
                                },
                                {
                                    "field": "properties.previousHealthStatus",
                                    "equals": "Degraded",
                                    "containsAny": null
                                }
                            ]
                        },
                        {
                            "anyOf": [
                                {
                                    "field": "properties.cause",
                                    "equals": "PlatformInitiated",
                                    "containsAny": null
                                }
                            ]
                        },
                        {
                            "anyOf": [
                                {
                                    "field": "status",
                                    "equals": "Active",
                                    "containsAny": null
                                },
                                {
                                    "field": "status",
                                    "equals": "Resolved",
                                    "containsAny": null
                                },
                                {
                                    "field": "status",
                                    "equals": "In Progress",
                                    "containsAny": null
                                },
                                {
                                    "field": "status",
                                    "equals": "Updated",
                                    "containsAny": null
                                }
                            ]
                        }
                    ]
                },
                "actions": {
                    "actionGroups": [
                        {
                            "actionGroupId": "$($actionGroup.Id)"
                        }
                    ]
                }
            }
        }
    ]
}
"@
$tempFile = New-TemporaryFile
$json | Set-Content -Path $tempFile.FullName -Encoding UTF8 -Force
New-AzResourceGroupDeployment -Name ResourceHealthLogAlertNameGeneral -ResourceGroupName $ResourceGroupName -TemplateFile $tempFile.FullName
Remove-Item -Path $tempFile.FullName -Force -ErrorAction SilentlyContinue

#Stopping Transscript
Stop-Transcript
