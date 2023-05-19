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
    24.11.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$haveibeenpwnedApiKey,
    [string]$outputFile = $null #Defaults to "$AlyaData\aad\Users.xlsx"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Check-PwnedUsers-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $outputFile)
{
    $outputFile = "$AlyaData\security\PwnedUsersReport.xlsx"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ImportExcel"
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Users"
Add-Type -AssemblyName System.Web

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MgGraph -Scopes "Directory.Read.All"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Security | Check-PwnedUsers | Az" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting breaches
$Uri = "https://haveibeenpwned.com/api/v3/breaches"
$breaches = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method "GET" -ContentType "application/json"
$breaches | ConvertTo-Json | Set-Content -Path "$outputFile.Breaches.json" -Encoding UTF8

# Checking users
Write-Host "Checking users" -ForegroundColor $CommandInfo
$users = Get-MgUser -All -Property "id,mail,userPrincipalName,ProxyAddresses"

$HeaderParams = @{
    "hibp-api-key"  = $haveibeenpwnedApiKey
    "user-agent" = "AlyaConsultingHibp"
}
$hacks = @()
$accounts = @()
foreach($user in $users)
{
    $mailsToTest = @()

    if (![string]::IsNullOrEmpty($user.Mail))
    {
        $mailsToTest += $user.Mail
    }
    if (![string]::IsNullOrEmpty($user.UserPrincipalName))
    {
        if ($mailsToTest -notcontains $user.UserPrincipalName)
        {
            $mailsToTest += $user.UserPrincipalName
        }
    }
    if ($user.ProxyAddresses)
    {
        foreach($prxy in $user.ProxyAddresses)
        {
            if (-Not $prxy.Contains(":")) { continue }
            $mail = $prxy.Split(":")[1]
            if ($mailsToTest -notcontains $mail)
            {
                $mailsToTest += $mail
            }
        }
    }
    if ($mailsToTest.Count -eq 0) { continue }
    foreach($mail in $mailsToTest)
    {
        Write-Host $mail -ForegroundColor $MenuColor
        $Uri = "https://haveibeenpwned.com/api/v3/breachedaccount/$([System.Web.HttpUtility]::UrlEncode($mail))?truncateResponse=false"
        try
        {
            Start-Sleep -Seconds 10
            $Results = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -UseBasicParsing -Method "GET" -ContentType "application/json"
            if ($Results.Count -gt 0)
            {
                foreach($breache in $Results)
                {
                    Write-Host "Found in breache '$($breache.Name)'"
                    $breache | Format-List
                    $hack = [PSCustomObject]@{
                        Mail = $mail
                        BreacheName = $breache.Name
                        BreacheDomain = $breache.Domain
                        BreacheDate = $breache.ModifiedDate
                        BreacheIsVerified = $breache.IsVerified
                        BreacheIsMalware = $breache.IsMalware
                        BreacheDataClasses = $breache.DataClasses -join ","
                    }
                    $hacks += $hack
                }
                $account = [PSCustomObject]@{
                    Mail = $mail
                    GivenName = $user.GivenName
                    Surname = $user.Surname
                    LastSignIn = $user.ApproximateLastSignInDateTime
                    BusinessPhone = $user.BusinessPhone -join ","
                    MobilePhone = $user.MobilePhone
                }
                $accounts += $account
            }
        } catch {
            if (-Not $_.Exception.Message.Contains("(404)"))
            {
                Write-Error $_.Exception
            }
        }
    }
}

do
{
    try
    {
        $excel = $accounts | Select-Object -Property $propNames | Export-Excel -Path $outputFile -WorksheetName "Accounts" -TableName "Accounts" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru
        Close-ExcelPackage $excel
        $excel = $hacks | Select-Object -Property $propNames | Export-Excel -Path $outputFile -WorksheetName "Hacks" -TableName "Hacks" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru
        Close-ExcelPackage $excel -Show
        break
    } catch
    {
        if ($_.Exception.Message.Contains("Could not open Excel Package"))
        {
            Write-Host "Please close excel sheet"
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

Copy-Item "$($AlyaLogs)\scripts\security\Check-PwnedUsers-$($AlyaTimeString).log" "$outputFile.log"
