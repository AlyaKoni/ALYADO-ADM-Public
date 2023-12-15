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
    13.10.2022 Konrad Brunner       Initial Version
    21.04.2023 Konrad Brunner       Switched to Graph

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
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "Directory.Read.All"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Export-UsersLicenses | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting available licenses
Write-Host "Getting available licenses" -ForegroundColor $CommandInfo
$Skus = Get-MgBetaSubscribedSku

# Getting users
Write-Host "Getting users" -ForegroundColor $CommandInfo
$users = Get-MgBetaUser -All

# Getting user licenses
Write-Host "Getting user licenses" -ForegroundColor $CommandInfo
$psusers = @()
foreach($user in $users)
{
    Write-Host "  Exporting $($user.UserPrincipalName)"
    $psuser = New-Object PSObject
    Add-Member -InputObject $psuser -MemberType NoteProperty -Name "UserPrincipalName" -Value $user.UserPrincipalName
    foreach($Sku in $Skus)
    {
        $assignedLicense = $user.AssignedLicenses | Where-Object { $_.SkuId -like $Sku.SkuId }
        if ($assignedLicense)
        {
            $DisabledPlans = ""
            foreach($plan in $assignedLicense.DisabledPlans)
            {
                $planName = ($Sku.ServicePlans | Where-Object { $_.ServicePlanId -eq $plan }).ServicePlanName
                $DisabledPlans += $planName + ","
            }
            $DisabledPlans = $DisabledPlans.TrimEnd(",")
            Add-Member -InputObject $psuser -MemberType NoteProperty -Name $Sku.SkuPartNumber -Value "1"
            Add-Member -InputObject $psuser -MemberType NoteProperty -Name ($Sku.SkuPartNumber+"-DisabledPlans") -Value $DisabledPlans
        }
        else
        {
            Add-Member -InputObject $psuser -MemberType NoteProperty -Name $Sku.SkuPartNumber -Value ""
            Add-Member -InputObject $psuser -MemberType NoteProperty -Name ($Sku.SkuPartNumber+"-DisabledPlans") -Value ""
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
