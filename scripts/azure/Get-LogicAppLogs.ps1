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
    12.07.2021 Konrad Brunner       Initial Version
    25.01.2023 Konrad Brunner       Action inputs and outputs

#>


[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$logicAppName,
    [Parameter(Mandatory = $false)]
    [string]$exportInputsAndOutputs = $false,
    [string[]]$skipExportInputsAndOutputsForActions = @()
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Get-LogicAppLogs-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.LogicApp"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Automation | Get-LogicAppLogs | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Exporting all logic app runs
Write-Host "Exporting all logic app runs" -ForegroundColor $CommandInfo
$LogicApp = Get-AzLogicApp -Name $logicAppName
$ResGrp = $LogicApp.Id.Split("/")[4]
$Runs = Get-AzLogicAppRunHistory -Name $logicAppName -ResourceGroupName $ResGrp -FollowNextPageLink

# Exporting all logic app triggers
Write-Host "Exporting all logic app triggers" -ForegroundColor $CommandInfo
$Trigg = Get-AzLogicAppTrigger -Name $logicAppName -ResourceGroupName $ResGrp
$TriggHistsAll = Get-AzLogicAppTriggerHistory -Name $logicAppName -ResourceGroupName $ResGrp -TriggerName $Trigg.Name -FollowNextPageLink #-MaximumFollowNextPageLink 2000
$TriggHists = $TriggHistsAll | Where-Object {$_.Status -ne "Skipped" -and $_.Fired -eq $true}

# Fired logic app trigger outputs
Write-Host "`n==============================================" -ForegroundColor $CommandInfo
Write-Host "Fired logic app trigger outputs" -ForegroundColor $CommandInfo
$TriggHistOutps = @()
foreach($TriggHist in $TriggHists)
{
    $TriggOutp = Invoke-RestMethod -Uri $TriggHist.OutputsLink.Uri
    $obj = $TriggOutp.Body
    Add-Member -InputObject $obj -MemberType NoteProperty -Name "Run" -Value $TriggHist.Run.Name
    Add-Member -InputObject $obj -MemberType NoteProperty -Name "StartTime" -Value $TriggHist.StartTime
    $TriggHistOutps += $obj
}
$TriggHistOutps | Select-Object Run, Name, StartTime, LastModified | Format-Table | Out-String | % {Write-Host $_}

# Logic app runs
Write-Host "`n==============================================" -ForegroundColor $CommandInfo
Write-Host "Logic apps runs" -ForegroundColor $CommandInfo
$Runs | Select-Object Name, StartTime, EndTime, Status, Code | Format-Table | Out-String | % {Write-Host $_}

# Logic app runs with status Succeeded
Write-Host "`n==============================================" -ForegroundColor $CommandInfo
Write-Host "Logic apps runs with status Succeeded" -ForegroundColor $CommandInfo
$SRuns = $Runs | Where-Object {$_.Status -eq "Succeeded"}
$SRuns | Select-Object Name, StartTime, EndTime, Status, Code | Format-Table | Out-String | % {Write-Host $_}

# Actions from succeeded logic app runs
Write-Host "`nActions from succeeded logic app runs" -ForegroundColor $CommandInfo
$regexOpts = [Text.RegularExpressions.RegexOptions]::None
$regexOpts = $regexOpts -bor [Text.RegularExpressions.RegexOptions]::IgnoreCase
$regexOpts = $regexOpts -bor [Text.RegularExpressions.RegexOptions]::Multiline
$regexOpts = $regexOpts -bor [Text.RegularExpressions.RegexOptions]::Compiled
foreach($Run in $SRuns)
{
    Write-Host "`nSucceeded run: $($Run.Name) $($Run.StartTime) $($Run.EndTime)"
    Write-Host "`nActions:"
    $Acts = Get-AzLogicAppRunAction -Name $logicAppName -ResourceGroupName $ResGrp -RunName $Run.Name | Sort-Object -Property EndTime -Descending
    $Acts | Select-Object Status, Name, EndTime, Code, StartTime | Format-Table | Out-String | % {Write-Host $_}
    if ($exportInputsAndOutputs)
    {
        Write-Host "`nInputs and Outputs:"
        foreach($Act in $Acts)
        {
            Start-Sleep -Milliseconds 500 #{"error":{"code":"WorkflowRequestsThrottled","message":"Number of read requests for workflow 'XXXXX' exceeded the limit of '1086' over time window of '00:05:00'."}}
            Write-Host "Action $($Act.Status), $($Act.Name), $($Act.EndTime), $($Act.Code), $($Act.StartTime):"
            if ($skipExportInputsAndOutputsForActions -contains $Act.Name) { continue }
            if ($Act.InputsLink)
            {
                $ActInp = Invoke-RestMethod -Method Get -Uri $Act.InputsLink.Uri -UseBasicParsing
                $Inp = $ActInp | ConvertTo-Json -Depth 2 -Compress
                Write-Host "  Inputs: $([Regex]::Replace($Inp, '"\$content":"[^"]*"', '"$content":"TRUNCATED"', $regexOpts))"
            }
            if ($Act.OutputsLink)
            {
                $ActOut = Invoke-RestMethod -Method Get -Uri $Act.OutputsLink.Uri -UseBasicParsing
                $Out = $ActOut | ConvertTo-Json -Depth 2 -Compress
                Write-Host "  Outputs: $([Regex]::Replace($Out, '"\$content":"[^"]*"', '"$content":"TRUNCATED"', $regexOpts))"
            }
        }
    }
}

# Logic app runs with status Cancelled
Write-Host "`n==============================================" -ForegroundColor $CommandInfo
Write-Host "Logic apps runs with status Cancelled" -ForegroundColor $CommandInfo
$SRuns = $Runs | Where-Object {$_.Status -eq "Cancelled"}
$SRuns | Select-Object Name, StartTime, EndTime, Status, Code | Format-Table | Out-String | % {Write-Host $_}

# Actions from cancelled logic app runs
Write-Host "`nActions from cancelled logic app runs" -ForegroundColor $CommandInfo
foreach($Run in $SRuns)
{
    #$Err = $Errs[0]
    Write-Host "`nCancelled run: $($Run.Name) $($Run.StartTime) $($Run.EndTime)"
    Write-Host "Actions:"
    $Acts = Get-AzLogicAppRunAction -Name $logicAppName -ResourceGroupName $ResGrp -RunName $Run.Name | Sort-Object -Property EndTime -Descending
    $Acts | Select-Object Status, Name, EndTime, Code, StartTime | Format-Table | Out-String | % {Write-Host $_}
    if ($exportInputsAndOutputs)
    {
        Write-Host "`nInputs and Outputs:"
        foreach($Act in $Acts)
        {
            Write-Host "Action $($Act.Status), $($Act.Name), $($Act.EndTime), $($Act.Code), $($Act.StartTime):"
            Start-Sleep -Milliseconds 500 #{"error":{"code":"WorkflowRequestsThrottled","message":"Number of read requests for workflow 'XXXXX' exceeded the limit of '1086' over time window of '00:05:00'."}}
            if ($skipExportInputsAndOutputsForActions -contains $Act.Name) { continue }
            if ($Act.InputsLink)
            {
                $ActInp = Invoke-RestMethod -Method Get -Uri $Act.InputsLink.Uri -UseBasicParsing
                $Inp = $ActInp | ConvertTo-Json -Depth 2 -Compress
                Write-Host "  Inputs: $([Regex]::Replace($Inp, '"\$content":"[^"]*"', '"$content":"TRUNCATED"', $regexOpts))"
            }
            if ($Act.OutputsLink)
            {
                $ActOut = Invoke-RestMethod -Method Get -Uri $Act.OutputsLink.Uri -UseBasicParsing
                $Out = $ActOut | ConvertTo-Json -Depth 2 -Compress
                Write-Host "  Outputs: $([Regex]::Replace($Out, '"\$content":"[^"]*"', '"$content":"TRUNCATED"', $regexOpts))"
            }
        }
    }
}

# Logic app runs with status Failed
Write-Host "`n==============================================" -ForegroundColor $CommandInfo
Write-Host "Logic apps runs with status Failed" -ForegroundColor $CommandInfo
$SRuns = $Runs | Where-Object {$_.Status -eq "Failed"}
$SRuns | Select-Object Name, StartTime, EndTime, Status, Code | Format-Table | Out-String | % {Write-Host $_}

# Actions from failed logic app runs
Write-Host "`nActions from failed logic app runs" -ForegroundColor $CommandInfo
foreach($Run in $SRuns)
{
    #$Err = $Errs[0]
    Write-Host "`nFailed run: $($Run.Name) $($Run.StartTime) $($Run.EndTime)"
    Write-Host "Actions:"
    $Acts = Get-AzLogicAppRunAction -Name $logicAppName -ResourceGroupName $ResGrp -RunName $Run.Name | Sort-Object -Property EndTime -Descending
    $Acts | Select-Object Status, Name, EndTime, Code, StartTime | Format-Table | Out-String | % {Write-Host $_}
    if ($exportInputsAndOutputs)
    {
        Write-Host "`nInputs and Outputs:"
        foreach($Act in $Acts)
        {
            Write-Host "Action $($Act.Status), $($Act.Name), $($Act.EndTime), $($Act.Code), $($Act.StartTime):"
            Start-Sleep -Milliseconds 500 #{"error":{"code":"WorkflowRequestsThrottled","message":"Number of read requests for workflow 'XXXXX' exceeded the limit of '1086' over time window of '00:05:00'."}}
            if ($skipExportInputsAndOutputsForActions -contains $Act.Name) { continue }
            if ($Act.InputsLink)
            {
                $ActInp = Invoke-RestMethod -Method Get -Uri $Act.InputsLink.Uri -UseBasicParsing
                $Inp = $ActInp | ConvertTo-Json -Depth 2 -Compress
                Write-Host "  Inputs: $([Regex]::Replace($Inp, '"\$content":"[^"]*"', '"$content":"TRUNCATED"', $regexOpts))"
            }
            if ($Act.OutputsLink)
            {
                $ActOut = Invoke-RestMethod -Method Get -Uri $Act.OutputsLink.Uri -UseBasicParsing
                $Out = $ActOut | ConvertTo-Json -Depth 2 -Compress
                Write-Host "  Outputs: $([Regex]::Replace($Out, '"\$content":"[^"]*"', '"$content":"TRUNCATED"', $regexOpts))"
            }
        }
    }
}

#Stopping Transscript
Stop-Transcript
