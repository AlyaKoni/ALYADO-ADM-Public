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
    13.11.2023 Konrad Brunner       Initial Version
    14.03.2024 Konrad Brunner       Fixes, general rework, added new workspaces
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Creates and configures Azure Log Analytics security alerts for monitoring critical security-related events.

.DESCRIPTION
The Create-AzureLogAnalyticsSecurityAlerts.ps1 script automates the creation and maintenance of Azure Log Analytics scheduled query rules (alerts) that monitor specific security events such as breaking glass account sign-ins, password changes, and global administrator role modifications. It ensures that alerts are configured correctly with appropriate action groups, permissions, and settings. The script checks for required modules, authenticates to Azure, verifies workspace and resource group existence, and uses REST API calls to configure alert rules with system identities and role assignments.

.INPUTS
None.

.OUTPUTS
The script does not produce objects as output. It creates or updates Azure Monitor alert rules within a specified Log Analytics workspace and writes transcript logs to the defined log directory.

.EXAMPLE
PS> .\Create-AzureLogAnalyticsSecurityAlerts.ps1

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
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

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBjE/ijabxN8JvP
# IeZgTZLqoZTlqhwpcByQkGYK2tpWSaCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g604YfM/tV
# 5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD4ED6gVYD
# U/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S/gJXhZrh
# 0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp8nKmrVa4
# 6Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqtf2phU7+y
# R2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJQWTEE/bP
# 0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKXvYkPbEdx
# +QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4yMYgcMKb
# 9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmYF8T4xO2k
# 6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2mMIVpqWC
# Z1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7spNY6rQb
# 3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd2jANBgkq
# hkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy/fAHsVv1
# RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW2H3Bh6zN
# XULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0MP6pBPKO
# L6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/pFL9zlcc
# tWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcexU0bcV0hL
# Q4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf6AMOGaM5
# 6A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzECp9LnR+34
# c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9mUF5qE6Yw
# QqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+KuaJRsz+cn
# ZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/JlN6m6GM1j
# EhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutofdgNBzMUx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKgXi/3mMPecU5qe
# pD07VlPusxfmm0we25MEW5C1u/MRMA0GCSqGSIb3DQEBAQUABIICABWEgfgX5E3a
# n50B4eB4gFH23tqN6tRDhoYZNdYrKU0RLhC62DQRb116QKN/EXQaHAec9FNc5Uml
# JPz5diNsHlj5vGz0LjxeMRHZvFm9NyMMgcDhkvYXAMESWtQOU3YjNyNKNXnVfaaQ
# O3GOIODnpJgv88P+x+8dJdg6U8rgkc5KIWmAaDFE19kLuhhwdQDduKLY0VKRXNH8
# D1o2vOkW/BOiR9Tzem/YhWfSXWhmIEW/msqZQHETaQorP3VhoxBjvhK1oWyUdKcO
# ebVxZkpLVF2pfb6TQ/tAIentzC8MPURW9fCH0LeaAq6DGALCCb0jlv9+I6sxejk8
# yVgUxVrcZf0CrTFJBZEKCZwKDBWcuI9DzQQnsrwayLhuZu6LbpxZDYR3Q0RbtRNR
# wURD78QFyQ5ofgPs+FNBkQK/ZZxjTAPDrUaxJvcwVtlStKemyF/Cd5CcRxd5d7F/
# KQ/rvuKUhzXtECRvYj/Ko5FlopfGKt/JGbRJiFyLeEQYFgHjsufjseLccImXH2OS
# y6WXcwgx+p8yANr9+YjYaF0Ojh9TfWUl+FQf5jOa1sYbhAKVnV9MLK3D5Jm0nSdB
# 3+i7wIoswkRQ3cpE/57AyLuTZkqlv3DPV5kYGAm16Jmyflv8/cZpwuk5+pVAMdNI
# ws/hcqsYOrwwFsmSp61u3eLSvXlfH6+4oYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCDKPj7GMnzmQhqd6c7LNZfUY4rDThvRL14h1L4wioYOzgIUcjF3ObpULjgy
# eMP7rn0KZqJFn6sYDzIwMjYwMjA2MTE0ODI1WjADAgEBoFikVjBUMQswCQYDVQQG
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
# IPfcGTLUc3NSZcp7Tf0RjKo/cF5GoCuaK0WY8b9xA5gsMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGASCte26WHcvwD
# dvfVoK9C8zEtEfMIX5zCtaxUz6iI9lI7FzrV9+xqRdPcp3p9D0NfTK5qZM0COm+8
# zX8cP2uBepWzTl6NfUFB0N1ImcXRCfzu29q0H3WuU3pWIImG9tz8TYdITdqK/mpa
# cDNzfpxgBHx0/gHa+tH8Utg4A7rOy1432WtLERgop2WcfTxnvpsjjAvFfVxBNccM
# HMxI7vtRgm59wwjd2hQIl9np3Fs4FdMTldUlWX4YwTQ8T28Dh5NZYG4NKUV3a8o+
# PpDAi7k/V/tjqwJCwZnQWfrosTAnfAvkGt7ulMPWO8o2rE5IU7mEv6cr5yODdWDS
# VO9y4nmdR42f6zF1UksWPCE9OKO9A/IqYezut8+PyJiwdfjE1KnoVG7Io/7oJ3dG
# 4cun/9df/2MIOvuqrwtjS+Lvy5/AeyY+opaSO/6+0A5xvzMXK674aHSpLej8DE2G
# geS/uOF3GZO7s2v/HagbevS7q8ov5UyYZcHeotQIpKra4LIZ96zV
# SIG # End signature block
