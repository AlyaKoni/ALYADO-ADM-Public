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
    13.11.2023 Konrad Brunner       Initial Version
    14.03.2024 Konrad Brunner       Fixes, general rework, added new workspaces

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\data\azure\Create-AzureLogAnalyticsSecurityAlerts-$($AlyaTimeString).log" | Out-Null

# Constants
$AlertResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$WrkspcResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$WrkspcName = "$($AlyaNamingPrefix)loga$($AlyaResIdLogAnalytics)"
$ActionGroupResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$ActionGroupName = "AlertSecurityByMail"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.OperationalInsights"
Install-ModuleIfNotInstalled "Az.Monitor"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "LogAnalytics | Create-AzureLogAnalyticsSecurityAlerts | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

function Create-Alert($Subscription, $AlertText,$AlertResourceGroupName,$LogAnaWrkspc,$ScheduledLogs,$ActionGroupId,$Severity,$QueryType,$ThresholdOperator,$Threshold,$FrequencyInMinutes,$TimeWindowInMinutes,$Query)
{
    # Checking alert
    $AlertName = "$($LogAnaWrkspc.Name) - $AlertText"
    Write-Host "Checking alert '$AlertName'" -ForegroundColor $CommandInfo
    $alertRule = Get-AzScheduledQueryRule -ResourceGroupName $AlertResourceGroupName -Name $AlertName -ErrorAction SilentlyContinue
    $isAzureDiagnostics = $false
    $SubscriptionId = $Subscription.id

    if ($ScheduledLogs)
    {

      if (-not $alertRule)
      {
        Write-Host "    Creating new rule" -ForegroundColor $CommandWarning

        $queryStr = $Query
        if ($Query.StartsWith("arg("))
        {
          $queryStr = "AzureDiagnostics"
          $isAzureDiagnostics = $true
        }
        $alertCondition = New-AzScheduledQueryRuleConditionObject `
          -Query $queryStr `
          -TimeAggregation $QueryType `
          -Operator $ThresholdOperator `
          -Threshold $Threshold `
          -FailingPeriodNumberOfEvaluationPeriod 1 `
          -FailingPeriodMinFailingPeriodsToAlert 1

        $alertRule = New-AzScheduledQueryRule `
          -Name $AlertName `
          -DisplayName $AlertName `
          -Description "Triggers an alert for the condition: $AlertText" `
          -ResourceGroupName $AlertResourceGroupName `
          -ActionGroupResourceId $ActionGroupId `
          -Location $AlyaLocation `
          -Enabled:$true `
          -Scope $LogAnaWrkspc.ResourceId `
          -Severity $Severity `
          -WindowSize ([System.TimeSpan]::FromMinutes($TimeWindowInMinutes)) `
          -EvaluationFrequency ([System.TimeSpan]::FromMinutes($FrequencyInMinutes)) `
          -CriterionAllOf $alertCondition

      }

      Write-Host "    Updating rule" -ForegroundColor $CommandWarning

      $json = @"
{
  "type": "Microsoft.Insights/scheduledQueryRules",
  "name": "$AlertName",
  "location": "$AlyaLocation",
  "identity": {
    "type": "SystemAssigned"
  },
  "properties": {
    "displayName": "$AlertName",
    "description": "Triggers an alert for the condition: $AlertText",
    "severity": $Severity,
    "enabled": true,
    "evaluationFrequency": "PT$($FrequencyInMinutes)M",
    "scopes": [
        "/subscriptions/$($SubscriptionId)/resourcegroups/$WrkspcResourceGroupName/providers/microsoft.operationalinsights/workspaces/$WrkspcName"
    ],
    "windowSize": "PT$($TimeWindowInMinutes)M",
    "criteria": {
        "allOf": [
            {
                "query": $($Query | ConvertTo-Json),
                "timeAggregation": "$QueryType",
                "operator": "$ThresholdOperator",
                "threshold": $Threshold,
                "failingPeriods": {
                    "numberOfEvaluationPeriods": 1,
                    "minFailingPeriodsToAlert": 1
                }
            }
        ]
    },
    "actions": {
        "actionGroups": [
            "$ActionGroupId"
        ]
    }
  }
}
"@
      Invoke-AzRestMethod -Path "/subscriptions/$($SubscriptionId)/resourcegroups/$WrkspcResourceGroupName/providers/Microsoft.Insights/scheduledQueryRules/$($AlertName)?api-version=2023-03-15-preview" -Method "Patch" -Payload $json
        
      $retries = 12
      do {
        $rulePrincipal = Get-AzADServicePrincipal -Filter "DisplayName eq '$AlertName'" -ErrorAction SilentlyContinue
        if ($rulePrincipal) {
          break
        } else {
          Start-Sleep -Seconds 10
        }
        $retries--
      } while ($retries -ge 0)

      if (-Not $rulePrincipal)
      {
        Write-Warning "We don't have actually a possibility to set the identity by PowerShell. Please:"
        Write-Warning " - Go to: 'https://portal.azure.com/#/resource/$($alertRule.Id)/overview'"
        Write-Warning " - Edit the rule and enable system assigned identity"
        Write-Warning " - Rerun this script"
        exit
      }
      else
      {
          $ruleRole = Get-AzRoleAssignment -Scope $LogAnaWrkspc.ResourceId -RoleDefinitionName "Reader" | Where-Object { $_.ObjectType -eq "ServicePrincipal" -and  $_.DisplayName -eq $AlertName }
          if (-Not $ruleRole)
          {
            $RoleAssignment = $null;
            $Retries = 0;
            While ($null -eq $RoleAssignment -and $Retries -le 6)
            {
                $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Reader" -ServicePrincipalName $rulePrincipal.AppId -Scope $LogAnaWrkspc.ResourceId -ErrorAction SilentlyContinue
                Start-Sleep -s 10
                $RoleAssignment = Get-AzRoleAssignment -Scope $LogAnaWrkspc.ResourceId -RoleDefinitionName "Reader" | Where-Object { $_.ObjectType -eq "ServicePrincipal" -and  $_.DisplayName -eq $AlertName }
                $Retries++;
            }
            if ($Retries -gt 6)
            {
                Write-Warning "We are not able to set the role assigment on workspace. insufficient access rights?"
                Write-Host " - Give the identity '$AlertName' read rights to the workspace"
                pause
            }
          }
          if ($isAzureDiagnostics)
          {
            $ruleRole = Get-AzRoleAssignment -Scope "/subscriptions/$($Subscription.id)" -RoleDefinitionName "Reader" | Where-Object { $_.ObjectType -eq "ServicePrincipal" -and  $_.DisplayName -eq $AlertName }
            if (-Not $ruleRole)
            {
              $RoleAssignment = $null;
              $Retries = 0;
              While ($null -eq $RoleAssignment -and $Retries -le 6)
              {
                  $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Reader" -ServicePrincipalName $rulePrincipal.AppId -Scope "/subscriptions/$($Subscription.id)" -ErrorAction SilentlyContinue
                  Start-Sleep -s 10
                  $RoleAssignment = Get-AzRoleAssignment -Scope "/subscriptions/$($Subscription.id)" -RoleDefinitionName "Reader" | Where-Object { $_.ObjectType -eq "ServicePrincipal" -and  $_.DisplayName -eq $AlertName }
                  $Retries++;
              }
              if ($Retries -gt 6)
              {
                  Write-Warning "We are not able to set the role assigment on workspace. insufficient access rights?"
                  Write-Host " - Give the identity '$AlertName' read rights to the workspace"
                  pause
              }
            }
          }
      }

    }
    else
    {
        if ($alertRule)
        {
            Write-Host "    Already exists. Deleting it first" -ForegroundColor $CommandWarning
            Remove-AzScheduledQueryRule -ResourceGroupName $AlertResourceGroupName -Name $AlertName
        }
        Write-Host "    Creating new rule" -ForegroundColor $CommandWarning
  
        $source = New-AzScheduledQueryRuleSource `
          -Query $Query `
          -DataSourceId $LogAnaWrkspc.ResourceId `
          -QueryType $QueryType
        
        $schedule = New-AzScheduledQueryRuleSchedule `
          -FrequencyInMinutes $FrequencyInMinutes `
          -TimeWindowInMinutes $TimeWindowInMinutes

        $triggerCondition = New-AzScheduledQueryRuleTriggerCondition `
          -ThresholdOperator $ThresholdOperator `
          -Threshold $Threshold

        $aznsActionGroup = New-AzScheduledQueryRuleAznsActionGroup `
          -ActionGroup $ActionGroupId `
          -EmailSubject "$WrkspcName Alert - $AlertText"

        $alertingAction = New-AzScheduledQueryRuleAlertingAction `
          -AznsAction $aznsActionGroup `
          -Severity $Severity `
          -Trigger $triggerCondition

        $null = New-AzScheduledQueryRule `
          -ResourceGroupName $AlertResourceGroupName `
          -Location $AlyaLocation `
          -Action $alertingAction `
          -Enabled $true `
          -Description "Triggers an alert for a $AlertText condition" `
          -Schedule $schedule `
          -Source $source `
          -Name $AlertName

    }
}

function Prepare-SecurityAlerts ($AlertSubscriptionName, $AlertResourceGroupName, $WrkspcResourceGroupName, $ActionGroupResourceGroupName, $ActionGroupName, $WrkspcName)
{
    # Switching subscription
    $sub = Get-AzSubscription -SubscriptionName $AlertSubscriptionName
    $null = Set-AzContext -Subscription $sub.Id

    # Checking ressource group
    Write-Host "Checking ressource group $WrkspcResourceGroupName" -ForegroundColor $CommandInfo
    $ResGrpParent = Get-AzResourceGroup -Name $WrkspcResourceGroupName -ErrorAction SilentlyContinue
    if (-Not $ResGrpParent)
    {
        throw "Does not exist. Please create it first"
    }

    # Checking log analytics workspace
    Write-Host "Checking log analytics workspace $WrkspcName" -ForegroundColor $CommandInfo
    $LogAnaWrkspc = Get-AzOperationalInsightsWorkspace -ResourceGroupName $WrkspcResourceGroupName -Name $WrkspcName -ErrorAction SilentlyContinue
    if (-Not $LogAnaWrkspc)
    {
        throw "Does not exist. Please create it first"
    }
    $LogAnaWrkspcLogVersResp = Invoke-AzRestMethod -Path "/subscriptions/$($sub.Id)/resourcegroups/$WrkspcResourceGroupName/providers/microsoft.operationalinsights/workspaces/$WrkspcName/alertsversion?api-version=2017-04-26-preview" -Method "Get"
    $LogAnaWrkspcLogVers = $LogAnaWrkspcLogVersResp.Content | ConvertFrom-Json

    # Checking action group
    Write-Host "Checking action group $ActionGroupName" -ForegroundColor $CommandInfo
    $actionGroup = Get-AzActionGroup -ResourceGroupName $ActionGroupResourceGroupName -Name $ActionGroupName -ErrorAction SilentlyContinue
    if (-Not $actionGroup)
    {
        throw "Does not exist. Please create it first with Create-AzureLogAnalyticsAlertActionGroups.ps1"
    }
    $actionGroupId = $actionGroup.Id

    # Checking breaking glass user
    Write-Host "Checking breaking glass user $AlyaBreakingGlassUserName" -ForegroundColor $CommandInfo
    if ($null -eq $AlyaBreakingGlassUserName -or $AlyaBreakingGlassUserName -eq "PleaseSpecify")
    {
        throw "Please specifiy in ConfigureEnv.ps1 the breaking glass login with the variable `$AlyaBreakingGlassUserName"
    }
    $breakGlassUser = Get-AzADUser -UserPrincipalName $AlyaBreakingGlassUserName
    if (-Not $breakGlassUser)
    {
        throw "Does not exist. Please create it first."
    }
    $breakGlassUserId = $breakGlassUser.Id

    # SignIn Breaking Glass Login
    Create-Alert `
        -Subscription $sub `
        -AlertText "SignIn Breaking Glass Login" `
        -AlertResourceGroupName $AlertResourceGroupName `
        -LogAnaWrkspc $LogAnaWrkspc `
        -ScheduledLogs ($LogAnaWrkspcLogVers.version -eq 2 -and $LogAnaWrkspcLogVers.scheduledQueryRulesEnabled -eq $true) `
        -ActionGroupId $actionGroupId `
        -Severity "0" `
        -QueryType "Count" `
        -ThresholdOperator "GreaterThan" `
        -Threshold 0 `
        -FrequencyInMinutes 30 `
        -TimeWindowInMinutes 30 `
        -Query "SigninLogs | where UserId == `"$breakGlassUserId`""

    # SignIn Breaking Glass Pwd Change
    Create-Alert `
        -Subscription $sub `
        -AlertText "SignIn Breaking Glass Pwd Change" `
        -AlertResourceGroupName $AlertResourceGroupName `
        -LogAnaWrkspc $LogAnaWrkspc `
        -ScheduledLogs ($LogAnaWrkspcLogVers.version -eq 2 -and $LogAnaWrkspcLogVers.scheduledQueryRulesEnabled -eq $true) `
        -ActionGroupId $actionGroupId `
        -Severity "0" `
        -QueryType "Count" `
        -ThresholdOperator "GreaterThan" `
        -Threshold 0 `
        -FrequencyInMinutes 30 `
        -TimeWindowInMinutes 240 `
        -Query "AuditLogs | where OperationName == `"Change user password`" and InitiatedBy.user.id == `"$breakGlassUserId`" | extend Actor = InitiatedBy.user.userPrincipalName"

    # Checking Global Admin Role Change
    Create-Alert `
        -Subscription $sub `
        -AlertText "Global Admin Role Change" `
        -AlertResourceGroupName $AlertResourceGroupName `
        -LogAnaWrkspc $LogAnaWrkspc `
        -ScheduledLogs ($LogAnaWrkspcLogVers.version -eq 2 -and $LogAnaWrkspcLogVers.scheduledQueryRulesEnabled -eq $true) `
        -ActionGroupId $actionGroupId `
        -Severity "1" `
        -QueryType "Count" `
        -ThresholdOperator "GreaterThan" `
        -Threshold 0 `
        -FrequencyInMinutes 15 `
        -TimeWindowInMinutes 15 `
        -Query "AuditLogs | where OperationName contains `"Add member to role`" and TargetResources contains `"Company Administrator`""

}

Prepare-SecurityAlerts `
    -AlertSubscriptionName $AlyaSubscriptionName `
    -AlertResourceGroupName $AlertResourceGroupName `
    -WrkspcResourceGroupName $WrkspcResourceGroupName `
    -WrkspcName $WrkspcName `
    -ActionGroupResourceGroupName $ActionGroupResourceGroupName `
    -ActionGroupName $ActionGroupName

#Stopping Transscript
Stop-Transcript
