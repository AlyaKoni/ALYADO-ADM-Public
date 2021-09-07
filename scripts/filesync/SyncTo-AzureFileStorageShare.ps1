#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2021

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
    08.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    $FromLocalDir = "E:\shares\DatenALYACONSULTING",
    $ToStorageShareName = "datenalyaconsulting",
    $UseLocalTempDriveLetter = "Z",
    $StorageAccountName = $null # Private Storage by default
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\filesync\SyncTo-AzureFileStorageShare-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
if (-Not $StorageAccountName)
{
    $StorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdPrivateStorage)"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "FileSync | SyncTo-AzureFileStorageShare | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking temp drive letter
Write-Host "Checking temp drive letter" -ForegroundColor $CommandInfo
if ((Test-Path "$($UseLocalTempDriveLetter):\"))
{
    Write-Error "Local drive $($UseLocalTempDriveLetter) already exists. Please unattach drive or use drive letter parameter." -ErrorAction Continue
    exit
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    throw "Ressource Group not found. Please create the Ressource Group $ResourceGroupName"
}

# Checking storage account
Write-Host "Checking storage account" -ForegroundColor $CommandInfo
$StrgAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-Not $StrgAccount)
{
    throw "Storage account not found. Please create the storage account $StorageAccountName"
}

# Checking alyaconsulting share
Write-Host "Checking alyaconsulting share" -ForegroundColor $CommandInfo
$Share = Get-AzRmStorageShare -StorageAccount $StrgAccount -Name $ToStorageShareName -ErrorAction SilentlyContinue
if (-Not $Share)
{
    throw "Share not found. Please create the share '$ToStorageShareName'"
}

# Checking drive
Write-Host "Checking drive" -ForegroundColor $CommandInfo
$PSDrive = Get-PSDrive -Name Z -PSProvider FileSystem -ErrorAction SilentlyContinue
$FileServerName = $StrgAccount.PrimaryEndpoints.File.Replace("https://","").TrimEnd("/")
if (-Not $PSDrive)
{
    Write-Warning "Connecting drive Z to $FileServerName"
    $ConnectTestResult = Test-NetConnection -ComputerName $FileServerName -Port 445
    if ($ConnectTestResult.TcpTestSucceeded)
    {
        $StorageKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).Value[0]
        $AccountKey = ConvertTo-SecureString -String $StorageKey -AsPlainText -Force
		Clear-Variable -Name "StorageKey" -Force -ErrorAction SilentlyContinue
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential `
                         -ArgumentList "Azure\$($StorageAccountName)", $AccountKey
        $PSDrive = New-PSDrive -Name $UseLocalTempDriveLetter `
            -PSProvider FileSystem `
            -Root "\\$($FileServerName)\$($ToStorageShareName)" `
            -Credential $Credential -Persist
    }
    else
    {
        throw "Unable to reach the Azure storage account via port 445. Check to make sure your organization or ISP is not blocking port 445, or use Azure P2S VPN, Azure S2S VPN, or Express Route to tunnel SMB traffic over a different port."
    }
}
Start-Sleep -Seconds 30

# Syncing drive
Write-Host "Syncing drive" -ForegroundColor $CommandInfo
robocopy /R:10 /W:10 /MT:4 /MIR /COPYALL /DCOPY:DAT /SECFIX /TIMFIX /XJ $FromLocalDir "$($UseLocalTempDriveLetter):\"

# Removing drive
Write-Host "Removing drive" -ForegroundColor $CommandInfo
Remove-PSDrive -Name $UseLocalTempDriveLetter

#Stopping Transscript
Stop-Transcript