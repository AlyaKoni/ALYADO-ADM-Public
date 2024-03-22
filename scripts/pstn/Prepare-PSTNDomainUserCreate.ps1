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
    14.03.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\pstn\Prepare-PSTNDomainUserCreate-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "PSTN | Prepare-PSTNDomainUserCreate | Teams" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
Write-Host "Checking PSTN DeleteMe user pstndeleteme@$AlyaPstnGateway" -ForegroundColor $CommandInfo
$user = $null
try {
    $user = Get-AzADUser -UserPrincipalName "pstndeleteme@$AlyaPstnGateway"
} catch { }
if (-Not $user)
{
    Write-Warning "User does not exist. Creating it now."
    $user = $pwd = ConvertTo-SecureString -String "Just.Delete-After1Usage" -AsPlainText -Force
    New-AzADUser -DisplayName "PSTN DeleteMe" -MailNickname "pstndeleteme" -UserPrincipalName "pstndeleteme@$AlyaPstnGateway" -Password $pwd -AccountEnabled $true -ShowInAddressList:$false -UsageLocation $AlyaDefaultUsageLocation -ForceChangePasswordNextLogin:$false
    $user = Get-AzADUser -UserPrincipalName "pstndeleteme@$AlyaPstnGateway"
}

Write-Host "Checking users license" -ForegroundColor $CommandInfo
$user = Get-MgBetaUser -UserId "pstndeleteme@$AlyaPstnGateway"
$lics = Get-MgBetaUserLicenseDetail -UserId $user.Id
$hasLic = $lics.ServicePlans.ServicePlanName -contains "MCOEV" -or `
          $lics.ServicePlans.SkuPartNumber -contains "MCOEV"
if (-Not $hasLic)
{
    Write-Warning "Please assign now a phone license to the user pstndeleteme@$AlyaPstnGateway"
}
while (-Not $hasLic)
{
    Write-Host "Waiting for license assignment ..."
    Start-Sleep -Seconds 10
    $lics = Get-MgBetaUserLicenseDetail -UserId $user.Id
    $hasLic = $lics.ServicePlans.ServicePlanName -contains "MCOEV" -or `
              $lics.ServicePlans.SkuPartNumber -contains "MCOEV"
}

#Stopping Transscript
Stop-Transcript
