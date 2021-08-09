#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2021

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
    22.06.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$newDomainName
)

#Input check
if (-Not $newDomainName.EndsWith(".onmicrosoft.com"))
{
    throw "newDomainName has to end with onmicrosoft.com"
}
if ($newDomainName.IndexOf("-") -gt -1)
{
    throw "Hyphens (-) are not supported in newDomainName"
}

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Rename-SharePointDomainName-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "AzureAdPreview"
Install-ModuleIfNotInstalled "Microsoft.Online.Sharepoint.PowerShell"
    
# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad
LoginTo-SPO

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Rename-SharePointDomainName | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking domain availability
Write-Host "Checking domain availability" -ForegroundColor $CommandInfo
$domainName = $newDomainName.Replace(".onmicrosoft.com", "")
$sharePointDomainName = "$($domainName).sharepoint.com"
$exists = $true
try
{
    $chk = Invoke-WebRequest -Uri "https://$($sharePointDomainName)" -Method Get -UseBasicParsing
    if ($chk.StatusCode -ne "200")
    {
        $exists = $false
    }
}
catch {
    $exists = $false
}
if ($exists)
{
    throw "Looks like the domain $($sharePointDomainName) already exists"
}

# Checking existing domains
Write-Host "Checking existing domains" -ForegroundColor $CommandInfo
$existingDomain = Get-AzureADDomain | where { $_.Name -eq $newDomainName }
if (-Not $existingDomain)
{
    Write-Warning "Domain $($newDomainName) does not exists, adding it now"
    New-AzureADDomain -Name $newDomainName
    $existingDomain = Get-AzureADDomain | where { $_.Name -eq $newDomainName }
}
#Defaults ?
#IsDefault                     : False
#IsDefaultForCloudRedirections : False
#IsInitial                     : False
#IsRoot                        : False
if (-Not $existingDomain.IsVerified)
{
    Write-Warning "Domain $($newDomainName) not yet verified, verifying it now"
    $verCodes = Get-AzureADDomainVerificationDnsRecord -Name $newDomainName
    Write-Warning "Please add one of the following records to your dns"
    $verCodes | fl
    pause
    Confirm-AzureADDomain -Name $newDomainName
}

# Changing domain name
$state = Get-SPOTenantRenameStatus -DomainName $newDomainName
if ($state -eq "TODO") #cmdlet was not yet ready: Error Code: -773,Nicht implementiert!
{
    $scheduleDateTime = (Get-Date).AddDays(6-(Get-Date).DayOfWeek.value__).AddHours(-(Get-Date).Hour).AddMinutes(-(Get-Date).Minute)
    Write-Warning "SPO Tenant Rename will start at $scheduleDateTime"
    pause
    Start-SPOTenantRename -DomainName $newDomainName -ScheduleDateTime $scheduleDateTime
}
else
{
    $state | fl
}

#Stopping Transscript
Stop-Transcript
