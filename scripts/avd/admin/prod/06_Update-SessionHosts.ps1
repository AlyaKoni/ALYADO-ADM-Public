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
    16.11.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [ValidateSet("AD","AAD")]
    [String]
    $JoinOption = "AD",
    [ValidateSet("Image","Gallery")]
    [String]
    $ImageOption = "Gallery"
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\prod\06_Update-SessionHosts-$($AlyaTimeString).log" | Out-Null

# Constants
$ShResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdSessionHostsResGrp)"
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdManagementResGrp)"
$HostPoolName = "$($AlyaNamingPrefix)avdh$($AlyaResIdAvdHostpool)"
$WorkspaceName = "$($AlyaNamingPrefix)avdw$($AlyaResIdAvdWorkspace)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.DesktopVirtualization"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AVD | 06_Update-SessionHosts | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Asking update
$title    = "HostPool Update"
$question = "Do you like to update host pool $($HostPoolName) with latest image version?"
$choices  = "&Yes", "&No"
$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
if ($decision -ne 0) {
    exit
}

# Checking HostPool
Write-Host "Checking HostPool $($HostPoolName)" -ForegroundColor $CommandInfo
$HstPl = Get-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $HstPl)
{
    throw "HostPool not found. Please create the HostPool $($HostPoolName) with the script 02_Create-HostPool.ps1"
}

# Checking workspace
Write-Host "Checking workspace" -ForegroundColor $CommandInfo
$WrkSpc = Get-AzWvdWorkspace -Name $WorkspaceName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $WrkSpc)
{
    throw "Workspace not found. Please create the workspace $($WorkspaceName) with the script Create-Workspace.ps1"
}

# Removing session hosts
Write-Host "Removing session hosts" -ForegroundColor $CommandInfo
$sessionHosts = Get-AzVM -ResourceGroupName $ShResourceGroupName
foreach($sessionHost in $sessionHosts)
{
    $VMName = $sessionHost.Name
    Write-Host "Removing session host $VMName" -ForegroundColor $CommandInfo
    $shost = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName | Where-Object { $_.Name -like "*$VMName*"}
    if ($shost)
    {
        $sHostName = $shost.Name.Replace($HostPoolName, "").Trim("/")
        Remove-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -Name $sHostName -SubscriptionId $Context.Subscription.Id -Force
    }
}

# Checking ressource group
Write-Host "Checking ressource group $($ShResourceGroupName)" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ShResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Host "    Does not exist. Nothing to do" -ForegroundColor $CommandWarning
}
else
{
    Write-Warning "Deleting ressource group $($ShResourceGroupName)"
    $ResGrp = Remove-AzResourceGroup -Name $ShResourceGroupName -ErrorAction SilentlyContinue
    do
    {
        $ResGrp = Get-AzResourceGroup -Name $ShResourceGroupName -ErrorAction SilentlyContinue
        if ($ResGrp) { Start-Sleep -Seconds 10 }
    }
    while ($ResGrp)
}

# Starting session host creation
& "$PSScriptRoot\06_Create-SessionHosts.ps1" -JoinOption $JoinOption -ImageOption $ImageOption

#Stopping Transscript
Stop-Transcript
