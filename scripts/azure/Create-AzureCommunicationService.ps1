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
    29.11.2024 Konrad Brunner       Initial version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Create-AzureCommunicationService-$($AlyaTimeString).log" | Out-Null

# Constants
if (-Not $AlyaResIdCommunicationService)
{
    Write-Warning "Please configure `$AlyaResIdCommunicationService in ConfigureEnv.ps1 an rerun this script"
    Pause
    Exit 1
}
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$CommServiceName = "$($AlyaNamingPrefix)coms$($AlyaResIdCommunicationService)"
$DataLocation = "europe"
switch($AlyaLocation)
{
    "westeurope" { $DataLocation = "europe" }
    "switzerlandnorth" { $DataLocation = "switzerland" }
    default { 
        Write-Error "Please update in this script the location mapping for $AlyaLocation. Possible dat locations are: unitedstates, europe, uk, australia, asiapacific, brazil, canada, germany, france, africa, india, japan, korea, uae, switzerland, norway" -ErrorAction Continue
        Exit 1
    }
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Communication"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Azure | Create-AzureCommunicationService | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking resource provider registration
Write-Host "Checking resource provider registration Microsoft.Communication" -ForegroundColor $CommandInfo
$resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Communication" -Location $AlyaLocation
if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
{
    Write-Warning "Resource provider Microsoft.Communication not registered. Registering now resource provider Microsoft.Communication"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Communication" | Out-Null
    do
    {
        Start-Sleep -Seconds 5
        $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Communication" -Location $AlyaLocation
    } while ($resProv[0].RegistrationState -ne "Registered")
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ResourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $ResourceGroupName -Location $AlyaLocation -Tag @{displayName="Main Infrastructure Services";ownerEmail=$Context.Account.Id}
}

# Checking communication service
Write-Host "Checking communication service" -ForegroundColor $CommandInfo
$CommService = Get-AzCommunicationService -ResourceGroupName $ResourceGroupName -Name $CommServiceName -ErrorAction SilentlyContinue
if (-Not $CommService)
{
    Write-Warning "Communication service not found. Creating communication service $CommServiceName"
    $CommService = New-AzCommunicationService -Name $CommServiceName -ResourceGroupName $ResourceGroupName -Location Global -DataLocation $DataLocation -Tag @{displayName="Communication Service"}
    if (-Not $CommService)
    {
        Write-Error "Communication service $CommServiceName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}
else
{
    Write-Host "Updating"
    $CommService = Update-AzCommunicationService -Name $CommServiceName -ResourceGroupName $ResourceGroupName -Tag @{displayName="Communication Service"}
}

#Stopping Transscript
Stop-Transcript
