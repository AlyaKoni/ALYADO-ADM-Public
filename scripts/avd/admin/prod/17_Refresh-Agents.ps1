#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2023

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
    06.03.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\prod\17_Refresh-Agents-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdManagementResGrp)"
$HostPoolName = "$($AlyaNamingPrefix)avdh$($AlyaResIdAvdHostpool)"
$ShResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdSessionHostsResGrp)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AVD | 17_Refresh-Agents | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking Management Ressource Group
Write-Host "Checking Management Ressource Group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    throw "Management Ressource Group not found. Please create the Management Ressource Group $ResourceGroupName"
}

# Checking HostPool
Write-Host "Checking HostPool" -ForegroundColor $CommandInfo
$HstPl = Get-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $HstPl)
{
    throw "HostPool not found. Please create the HostPool $HostPoolName with the script Create-HostPool.ps1"
}

# Checking avd agent registration token
Write-Host "Checking avd agent registration token"
$HstPlRegInf = Get-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName
if ($HstPlRegInf.ExpirationTime -lt (Get-Date).AddHours(1))
{
    Write-Warning "Registration token has expired. Creating a new one."
    $HstPlRegInf = New-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
        -ExpirationTime $((get-date).ToUniversalTime().AddDays(1).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))
}

# Removing session hosts
<#
Write-Host "Removing session hosts" -ForegroundColor $CommandInfo
$sessionHosts = Get-AzVM -ResourceGroupName $ShResourceGroupName
foreach($sessionHost in $sessionHosts)
{
    $VMName = $sessionHost.Name
    Write-Host "Removing session host $VMName" -ForegroundColor $CommandInfo
    $shost = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName | where { $_.Name -like "*$VMName*"}
    if ($shost)
    {
        $sHostName = $shost.Name.Replace($HostPoolName, "").Trim("/")
        Remove-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -Name $sHostName -SubscriptionId $Context.Subscription.Id -Force
    }
}
#>

# Refresh agents on VMs
Write-Host "Refresh agents on VMs" -ForegroundColor $CommandSuccess
$installScript = @'
# Azure Virtual Desktop Agent install
Write-Host "Azure Virtual Desktop Agent installation"
$downloadUrl = "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv"
Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -Method Get -OutFile "AVDAgent.msi"
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i AVDAgent.msi", "/quiet", "/qn", "/norestart", "/passive", "REGISTRATIONTOKEN=<TOKEN>", "/l* C:\Users\AgentInstall.txt" -Wait -Passthru

Start-Sleep -Seconds 30

# Azure Virtual Desktop Bootloader install
Write-Host "Azure Virtual Desktop Bootloader installation"
$downloadUrl = "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH"
Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -Method Get -OutFile "AVDBootloader.msi"
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i AVDBootloader.msi", "/quiet", "/qn", "/norestart", "/passive", "/l* C:\Users\AgentBootLoaderInstall.txt" -Wait -Passthru

Start-Sleep -Seconds 30

Restart-Computer
'@
$installScript = $installScript.Replace('<TOKEN>', $HstPlRegInf.Token)

Write-Host " - Launch following script in admin powershell" -ForegroundColor $CommandSuccess
Write-Host $installScript -ForegroundColor $CommandSuccess

#Stopping Transscript
Stop-Transcript
