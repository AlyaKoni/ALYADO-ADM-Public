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
    12.12.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$SearchForOperationName = $null,
    [string]$SearchForTargetUpn = $null,
    [string]$SearchForSourceUpn = $null
)


#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Find-AuditLogsInStorage-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$StorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdAuditStorage)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Storage"
    
# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Find-AuditLogsInStorage | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    throw "Ressource Group not found $ResourceGroupName"
}

# Checking storage account
Write-Host "Checking storage account" -ForegroundColor $CommandInfo
$StrgAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-Not $StrgAccount)
{
    throw "Storage account not found $StorageAccountName"
}

# Checking container
Write-Host "Checking container" -ForegroundColor $CommandInfo
$ctx = $StrgAccount.Context
$container = Get-AzStorageContainer -Context $ctx -Name "insights-logs-auditlogs"
if (-Not $container)
{
    throw "Container not found insights-logs-auditlogs"
}

# Getting blobs
Write-Host "Getting blobs" -ForegroundColor $CommandInfo
$blobs = Get-AzStorageBlob -Context $ctx -Container $container.Name
foreach($blob in $blobs)
{
    #Write-Host "$($blob.Name)"
    $blobContent = $blob.ICloudBlob.DownloadText()
    foreach($logStr in $blobContent.Split("`n"))
    {
        if (-Not [string]::IsNullOrEmpty($logStr))
        {
            $log = $logStr | ConvertFrom-Json
            if (-Not [string]::IsNullOrEmpty($SearchForOperationName))
            {
                if ($log.operationName -ne $SearchForOperationName)
                {
                    $log = $null
                }
            }
            if ($log -and -Not [string]::IsNullOrEmpty($SearchForTargetUpn))
            {
                if ($log.properties.targetResources.userPrincipalName -ne $SearchForTargetUpn)
                {
                    $log = $null
                }
            }
            if ($log -and -Not [string]::IsNullOrEmpty($SearchForSourceUpn))
            {
                if ($log.properties.initiatedBy.user.userPrincipalName -ne $SearchForSourceUpn)
                {
                    $log = $null
                }
            }
            if ($log)
            {
                $log | ConvertTo-Json -Compress -Depth 5
            }
        }
    }
}

#Stopping Transscript
Stop-Transcript
