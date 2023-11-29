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
    13.11.2023 Konrad Brunner       Initial Version

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

function Create-Alert($AlertText,$AlertResourceGroupName,$LogAnaWrkspc,$ScheduledLogs,$ActionGroupId,$Severity,$QueryType,$ThresholdOperator,$Threshold,$FrequencyInMinutes,$TimeWindowInMinutes,$Query)
{
    # Checking alert
    $AlertName = "$WrkspcName - $AlertText"
    Write-Host "Checking alert '$AlertName'" -ForegroundColor $CommandInfo
    $alertRule = Get-AzScheduledQueryRule -ResourceGroupName $AlertResourceGroupName -Name $AlertName -ErrorAction SilentlyContinue

    if ($ScheduledLogs)
    {

      if (-not $alertRule)
      {
        Write-Host "    Creating new rule" -ForegroundColor $CommandWarning

        <#
        #kind: "LogAlert",
        #"apiVersion": "2023-03-15-preview",
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
        "/subscriptions/$($Context.subscription.id)/resourcegroups/$WrkspcResourceGroupName/providers/microsoft.operationalinsights/workspaces/$WrkspcName"
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
Invoke-AzRestMethod -Path "/subscriptions/$($Context.subscription.id)/resourcegroups/$WrkspcResourceGroupName/providers/Microsoft.Insights/scheduledQueryRules?api-version=2023-03-15-preview" -Method "Post" -Payload $json

Invoke-AzRestMethod -Path "/subscriptions/$($Context.subscription.id)/resourcegroups/$WrkspcResourceGroupName/providers/microsoft.operationalinsights/workspaces/$WrkspcName?api-version=2023-03-15-preview" -Method "Post" -Payload $json
Invoke-AzRestMethod -Path "/subscriptions/$($Context.subscription.id)/resourcegroups/$WrkspcResourceGroupName/providers/microsoft.operationalinsights/workspaces/$WrkspcName?api-version=2023-03-15-preview" -Method "Put" -Payload $json
Invoke-AzRestMethod -Path "/subscriptions/$($Context.subscription.id)/resourcegroups/$WrkspcResourceGroupName/providers/Microsoft.Insights/scheduledQueryRules?api-version=2023-03-15-preview" -Method "Post" -Payload $json
Invoke-AzRestMethod -Path "/subscriptions/$($Context.subscription.id)/resourcegroups/$WrkspcResourceGroupName/providers/Microsoft.Insights/scheduledQueryRules?api-version=2023-03-15-preview" -Method "Put" -Payload $json
Invoke-AzRestMethod -Path "/subscriptions/$($Context.subscription.id)/resourcegroups/$WrkspcResourceGroupName/providers/microsoft.operationalinsights/workspaces/$WrkspcName/scheduledQueryRules?api-version=2022-10-01" -Method "Post" -Payload $json
Invoke-AzRestMethod -Path "/subscriptions/$($Context.subscription.id)/resourcegroups/$WrkspcResourceGroupName/providers/microsoft.operationalinsights/workspaces/$WrkspcName/scheduledQueryRules?api-version=2022-10-01" -Method "Put" -Payload $json

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
Invoke-AzRestMethod -Path "/subscriptions/6b392099-8a5d-4f63-a57e-986f278bc20d/resourceGroups/RG_AzureSentinel/providers/Microsoft.Insights/scheduledqueryrules/hanshundegger-azure-sentinel - Windows Low Disk Space?api-version=2023-03-15-preview" -Method "Patch" -Payload $json


          Invoke-AzRestMethod -Path "/subscriptions/$($Context.subscription.id)/resourcegroups/$WrkspcResourceGroupName/providers/microsoft.operationalinsights/workspaces/$WrkspcName/alertsversion?api-version=2017-04-26-preview" -Method "Get"
          Invoke-AzRestMethod -Path "/subscriptions/$($Context.subscription.id)/resourcegroups/$WrkspcResourceGroupName/providers/microsoft.operationalinsights/workspaces/$WrkspcName/alertsversion?api-version=2022-10-01" -Method "Get"
$json = @"
{
  "name": "hanshundegger-azure-sentinel - Windows Low Disk Space",
  "properties": {
    "displayName": "hanshundegger-azure-sentinel - Windows Low Disk Space",
    "description": "Triggers an alert for the condition: Windows Low Disk Space",
    "severity": 2,
    "enabled": true,
    "evaluationFrequency": "PT30M",
    "scopes": [
        "/subscriptions/6b392099-8a5d-4f63-a57e-986f278bc20d/resourcegroups/rg_azuresentinel/providers/microsoft.operationalinsights/workspaces/hanshundegger-azure-sentinel"
    ],
    "windowSize": "PT30M",
    "criteria": {
        "allOf": [
            {
                "query": "let _minValue = 10; Perf | where TimeGenerated >= ago(1h) | where CounterValue <= _minValue | where CounterName == \"% Free Space\" and InstanceName in (\"C:\", \"D:\", \"E:\", \"F:\", \"G:\")  | summarize mtgPerf=max(TimeGenerated), CounterValue=max(CounterValue) by Computer, InstanceName, CounterName, ObjectName, DriveLetter=replace(@\"(\\\\w).\",@\"\\\\1\", InstanceName) | join kind=inner ( Heartbeat | where OSType == \"Windows\" and ComputerEnvironment == \"Azure\" | summarize max(TimeGenerated) by Computer) on Computer | project Computer, ObjectName, CounterName, InstanceName, TimeGenerated=mtgPerf, round(CounterValue), DriveLetter, AlertType_s = \"Windows Low Disk Space\", Severity = 3, SeverityName_s = \"WARNING\", AffectedCI_s = strcat(Computer, \"/\", DriveLetter), AlertTitle_s = strcat(Computer, \": Low Disk Space on Drive \", DriveLetter), AlertDetails_s = strcat(\"Computer: \", Computer, \"\\\\r\\\\nDrive Letter: \", DriveLetter, \"\\\\r\\\\nPercent Free Space: \", round(CounterValue), \"%\\\\r\\\\nAlert Threshold: <= \", _minValue, \"%\")",
                "timeAggregation": "Count",
                "operator": "GreaterThan",
                "threshold": 0,
                "failingPeriods": {
                    "numberOfEvaluationPeriods": 1,
                    "minFailingPeriodsToAlert": 1
                }
            }
        ]
    },
    "actions": {
        "actionGroups": [
            "/subscriptions/6B392099-8A5D-4F63-A57E-986F278BC20D/resourceGroups/RG_AzureSentinel/providers/microsoft.insights/actionGroups/Alertmail IT"
        ]
    },
    "identity": {
      "type": "SystemAssigned",
      "tenantId": "d8af8c04-8701-44f5-b6d8-845367ef5a72",
      "principalId": "9640708e-fb58-41c6-a36e-7b6b75af5212"
    }
  }
}
"@
Invoke-AzRestMethod -Path "/subscriptions/6b392099-8a5d-4f63-a57e-986f278bc20d/resourceGroups/RG_AzureSentinel/providers/Microsoft.Insights/scheduledqueryrules/hanshundegger-azure-sentinel - Windows Low Disk Space?api-version=2023-03-15-preview" -Method "Patch" -Payload $json

$resp = Invoke-AzRestMethod -Path "/subscriptions/6b392099-8a5d-4f63-a57e-986f278bc20d/resourceGroups/RG_AzureSentinel/providers/Microsoft.Insights/scheduledqueryrules/hanshundegger-azure-sentinel - Unexpected Shutdown?api-version=2023-03-15-preview" -Method "Get"
$rule = $resp.Content | ConvertFrom-Json
($rule | ConvertTo-Json -Depth 99)

$rule.id = $null
$rule.systemData = $null
Invoke-AzRestMethod -Path "/subscriptions/6b392099-8a5d-4f63-a57e-986f278bc20d/resourceGroups/RG_AzureSentinel/providers/Microsoft.Insights/scheduledqueryrules/hanshundegger-azure-sentinel - Windows Low Disk Space?api-version=2023-03-15-preview" -Method "Patch" -Payload ($rule | ConvertTo-Json -Depth 99)
#>
        $queryStr = $Query
        if ($Query.StartsWith("arg("))
        {
          $queryStr = "AzureDiagnostics"
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
      #else
      #{
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
        "/subscriptions/$($Context.subscription.id)/resourcegroups/$WrkspcResourceGroupName/providers/microsoft.operationalinsights/workspaces/$WrkspcName"
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
        Invoke-AzRestMethod -Path "/subscriptions/$($Context.subscription.id)/resourcegroups/$WrkspcResourceGroupName/providers/Microsoft.Insights/scheduledQueryRules/$($AlertName)?api-version=2023-03-15-preview" -Method "Patch" -Payload $json
        
        <# TODO PowerShell update actually removes system assigned identity, created an issue

        $alertCondition = New-AzScheduledQueryRuleConditionObject `
          -Query $Query `
          -TimeAggregation $QueryType `
          -Operator $ThresholdOperator `
          -Threshold $Threshold `
          -FailingPeriodNumberOfEvaluationPeriod 1 `
          -FailingPeriodMinFailingPeriodsToAlert 1

        $null = Update-AzScheduledQueryRule -InputObject $alertRule.Id `
          -DisplayName $AlertName `
          -Description "Triggers an alert for the condition: $AlertText" `
          -ActionGroupResourceId $ActionGroupId `
          -Enabled:$true `
          -Scope $LogAnaWrkspc.ResourceId `
          -Severity $Severity `
          -WindowSize ([System.TimeSpan]::FromMinutes($TimeWindowInMinutes)) `
          -EvaluationFrequency ([System.TimeSpan]::FromMinutes($FrequencyInMinutes)) `
          -CriterionAllOf $alertCondition#>

      #}

      $retries = 10
      do {
        Start-Sleep -Seconds 5
        $rulePrincipal = Get-AzADServicePrincipal -Filter "DisplayName eq '$AlertName'" -ErrorAction SilentlyContinue
        if ($rulePrincipal) {
          break
        }
        $retries--
      } while ($retries -ge 0)

      if (-Not $rulePrincipal)
      {
        Write-Warning "We don't have actually any possibility to set the identity by PowerShell. Please:"
        Write-Host " - Go to: 'https://portal.azure.com/#/resource$($alertRule.Id)/overview'"
        Write-Host " - Enable system assigned identity"
        Write-Host " - Give the identity '$AlertName' read rights to the workspace"
        Write-Host " - Rerun this script"
      }
      else
      {
          $ruleRole = Get-AzRoleAssignment -Scope $LogAnaWrkspc.ResourceId -RoleDefinitionName "Reader" | Where-Object { $_.ObjectType -eq "ServicePrincipal" -and  $_.DisplayName -eq $AlertName }
          if (-Not $ruleRole)
          {
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
                Write-Warning "We are not able to set the role assigment. insufficient access rights?"
                Write-Host " - Give the identity '$AlertName' read rights to the workspace"
                pause
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
