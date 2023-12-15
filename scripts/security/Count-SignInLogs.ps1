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
    08.03.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$outputFile = $null, #Defaults to "$AlyaData\security\SignInCounts.xlsx"
    [Parameter(Mandatory= $true)]
    [string]$countByCountry
)


#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Count-SignInLogs-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $outputFile)
{
    $outputFile = "$AlyaData\security\SignInCounts.xlsx"
}
$outputDirectory = Split-Path $outputFile -Parent
if (-Not (Test-Path $outputDirectory))
{
    New-Item -Path $outputDirectory -ItemType Directory -Force
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ImportExcel"
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "AzureAdPreview"
    
# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Count-SignInLogs | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Getting users
Write-Host "Getting users" -ForegroundColor $CommandInfo
$users = Get-AzureADUser -All $true

# Getting sign-in logs from all users
Write-Host "Getting sign-in logs from all users" -ForegroundColor $CommandInfo
$allLogs = [System.Collections.ArrayList]@()
foreach($user in $users)
{
    Write-Host " - $($user.UserPrincipalName)"
    $lastDay = (Get-Date).AddDays(-1)
    $lastWeek = (Get-Date).AddDays(-7)
   do
    {
        try
        {
            $logs = Get-AzureADAuditSignInLogs -Filter "startsWith(userPrincipalName,'$($user.UserPrincipalName)')" -All $true
            $min,$max = [DateTime[]]@($logs | Select-Object CreatedDateTime | Sort CreatedDateTime)[0,-1].CreatedDateTime
            $allLogs += [PSCustomObject]@{
                "UPN" = $user.UserPrincipalName
                "Name" = $user.DisplayName
                "Count" = ($logs | Where-Object { $_.IsInteractive -eq $true }).Count
                "Count$countByCountry" = ($logs | Where-Object { $_.IsInteractive -eq $true -and $_.Location.CountryOrRegion -eq $countByCountry }).Count
                "CountNot$countByCountry" = ($logs | Where-Object { $_.IsInteractive -eq $true -and $_.Location.CountryOrRegion -ne $countByCountry }).Count
                "LastDayCount" = ($logs | Where-Object { $_.IsInteractive -eq $true -and ([DateTime]$_.CreatedDateTime) -gt $lastDay }).Count
                "LastDayCount$countByCountry" = ($logs | Where-Object { $_.IsInteractive -eq $true -and ([DateTime]$_.CreatedDateTime) -gt $lastDay -and $_.Location.CountryOrRegion -eq $countByCountry }).Count
                "LastDayCountNot$countByCountry" = ($logs | Where-Object { $_.IsInteractive -eq $true -and ([DateTime]$_.CreatedDateTime) -gt $lastDay -and $_.Location.CountryOrRegion -ne $countByCountry }).Count
                "LastWeekCount" = ($logs | Where-Object { $_.IsInteractive -eq $true -and ([DateTime]$_.CreatedDateTime) -gt $lastWeek }).Count
                "LastWeekCount$countByCountry" = ($logs | Where-Object { $_.IsInteractive -eq $true -and ([DateTime]$_.CreatedDateTime) -gt $lastWeek -and $_.Location.CountryOrRegion -eq $countByCountry }).Count
                "LastWeekCountNot$countByCountry" = ($logs | Where-Object { $_.IsInteractive -eq $true -and ([DateTime]$_.CreatedDateTime) -gt $lastWeek -and $_.Location.CountryOrRegion -ne $countByCountry }).Count
                "FailureCount" = ($logs | Where-Object { $_.Status.ErrorCode -gt 0 -and $_.IsInteractive -eq $true }).Count
                "FailureCount$countByCountry" = ($logs | Where-Object { $_.Status.ErrorCode -gt 0 -and $_.IsInteractive -eq $true -and $_.Location.CountryOrRegion -eq $countByCountry }).Count
                "FailureCountNot$countByCountry" = ($logs | Where-Object { $_.Status.ErrorCode -gt 0 -and $_.IsInteractive -eq $true -and $_.Location.CountryOrRegion -ne $countByCountry }).Count
                "FailureLastDayCount" = ($logs | Where-Object { $_.Status.ErrorCode -gt 0 -and $_.IsInteractive -eq $true -and ([DateTime]$_.CreatedDateTime) -gt $lastDay }).Count
                "FailureLastDayCount$countByCountry" = ($logs | Where-Object { $_.Status.ErrorCode -gt 0 -and $_.IsInteractive -eq $true -and ([DateTime]$_.CreatedDateTime) -gt $lastDay -and $_.Location.CountryOrRegion -eq $countByCountry }).Count
                "FailureLastDayCountNot$countByCountry" = ($logs | Where-Object { $_.Status.ErrorCode -gt 0 -and $_.IsInteractive -eq $true -and ([DateTime]$_.CreatedDateTime) -gt $lastDay -and $_.Location.CountryOrRegion -ne $countByCountry }).Count
                "FailureLastWeekCount" = ($logs | Where-Object { $_.Status.ErrorCode -gt 0 -and $_.IsInteractive -eq $true -and ([DateTime]$_.CreatedDateTime) -gt $lastWeek }).Count
                "FailureLastWeekCount$countByCountry" = ($logs | Where-Object { $_.Status.ErrorCode -gt 0 -and $_.IsInteractive -eq $true -and ([DateTime]$_.CreatedDateTime) -gt $lastWeek -and $_.Location.CountryOrRegion -eq $countByCountry }).Count
                "FailureLastWeekCountNot$countByCountry" = ($logs | Where-Object { $_.Status.ErrorCode -gt 0 -and $_.IsInteractive -eq $true -and ([DateTime]$_.CreatedDateTime) -gt $lastWeek -and $_.Location.CountryOrRegion -ne $countByCountry }).Count
                #NonInteractiveCount = ($logs | Where-Object { $_.IsInteractive -eq $false }).Count
                "RiskCount" = ($logs | Where-Object { $_.RiskState -ne "none" }).Count
                "MinDate" = $min
                "MaxDate" = $max
            }
            Start-Sleep -Seconds 1
            break
        }
        catch
        {
            if ($_.Exception.Message -notlike "*too many*")
            {
                throw
            }
            else
            {
                #Write-Host "  Throttled"
            }
        }
    } while ($true)
}

$allLogs | Format-Table

do
{
    try
    {
        $excel = $allLogs | Export-Excel -Path $outputFile -WorksheetName "LogCounts" -TableName "LogCounts" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru
        Close-ExcelPackage $excel -Show
        break
    } catch
    {
        if ($_.Exception.Message.Contains("Could not open Excel Package"))
        {
            Write-Host "Please close excel sheet $outputFile"
            pause
        }
        else
        {
            throw
        }
    }
} while ($true)

#Stopping Transscript
Stop-Transcript
