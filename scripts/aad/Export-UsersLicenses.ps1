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
    13.10.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$outputFile = $null #Defaults to "$AlyaData\aad\UsersLicenses.xlsx"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Export-UsersLicenses-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $outputFile)
{
    $outputFile = "$AlyaData\aad\UsersLicenses.xlsx"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ImportExcel"
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "MSOnline"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MSOL

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Export-UsersLicenses | MSOL" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting token
$apiToken = Get-AzAccessToken

# Getting licenses
Write-Host "Getting licenses" -ForegroundColor $CommandInfo
$header = @{'Authorization'='Bearer '+$apiToken;'Content-Type'='application/json';'X-Requested-With'='XMLHttpRequest';'x-ms-client-request-id'=[guid]::NewGuid();'x-ms-correlation-id'=[guid]::NewGuid();}
$url = "https://main.iam.ad.ext.azure.com/api/AccountSkus"
$response = Invoke-WebRequest -Uri $url -Headers $header -Method GET -ErrorAction Stop
$availableLics = $response | ConvertFrom-Json

$licNames = @()
foreach($availableLic in $availableLics)
{
    $licNames += $availableLic.accountSkuId.Split(":")[1]
}

# Getting users
Write-Host "Getting users" -ForegroundColor $CommandInfo
$users = Get-MsolUser -All

# Getting user licenses
Write-Host "Getting user licenses" -ForegroundColor $CommandInfo
$psusers = @()
foreach($user in $users)
{
    Write-Host "  Exporting $($user.UserPrincipalName)"
    $psuser = New-Object PSObject
    Add-Member -InputObject $psuser -MemberType NoteProperty -Name "UserPrincipalName" -Value $user.UserPrincipalName
    foreach($licName in $licNames)
    {
        if ($user.Licenses | where { $_.accountSkuId -like "*$licName" })
        {
            Add-Member -InputObject $psuser -MemberType NoteProperty -Name $licName -Value "1"
        }
        else
        {
            Add-Member -InputObject $psuser -MemberType NoteProperty -Name $licName -Value ""
        }
    }
    $psusers += $psuser
}

# Writing excel
Write-Host "Writing excel" -ForegroundColor $CommandInfo
do
{
    try
    {
        $excel = $psusers | Select-Object -Property $propNames | Export-Excel -Path $outputFile -WorksheetName "Users" -TableName "Users" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru
        #$ws = $excel.Workbook.Worksheets['Users']
        #Set-Format -Worksheet $ws -Range "A:BZ" -
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
