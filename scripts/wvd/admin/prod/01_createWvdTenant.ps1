#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

    This unpublished material is proprietary to Alya Consulting.
    All rights reserved. The methods and techniques described
    herein are considered trade secrets and/or confidential. 
    Reproduction or distribution, in whole or in part, is 
    forbidden except by express written permission of Alya Consulting.

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    10.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\prod\01_createWvdTenant-$($AlyaTimeString).log" | Out-Null

# Constants

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
#LoginTo-Wvd
if (-Not $Global:RdsContext)
{
    Write-Host "Login to WVD" -ForegroundColor $CommandInfo
    $Global:RdsContext = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker
}

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 01_createWvdTenant | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error -Message "Can't get Az context! Not logged in?"
    Exit 1
}

#Members
$SubscriptionId = (Get-AzSubscription).Id

#Checking wvd context
Write-Host "Checking wvd context" -ForegroundColor $CommandInfo
if ( (Get-RdsContext).TenantGroupName -ne $AlyaWvdTenantGroupName)
{
    Set-RdsContext -TenantGroupName $AlyaWvdTenantGroupName -ErrorAction Stop
}

#Checking tenant
Write-Host "Checking tenant" -ForegroundColor $CommandInfo
$WvdTenant = Get-RdsTenant -Name $AlyaWvdTenantNameProd -ErrorAction SilentlyContinue
if (-Not $WvdTenant)
{
    Write-Warning -Message "WVD tenant not found. Creating the WVD tenant $WvdTenant"
    $WvdTenant = New-RdsTenant -Name $AlyaWvdTenantNameProd -AadTenantId $AlyaTenantId -AzureSubscriptionId $SubscriptionId
}

Get-RdsTenant -Name $AlyaWvdTenantNameProd -ErrorAction Stop | fl

#Get-RdsDiagnosticActivities -Detailed
#Remove-RdsTenant -Name $AlyaWvdTenantNameProd

#Stopping Transscript
Stop-Transcript
