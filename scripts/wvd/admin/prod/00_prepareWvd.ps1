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
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\prod\00_prepareWvd-$($AlyaTimeString).log" | Out-Null

# =============================================================
# WVD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 00_prepareWvd | WVD" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Please process first all prerequisites:" -ForegroundColor Red
Write-Host " - Admin Consent for Server and client (https://rdweb.wvd.microsoft.com)" -ForegroundColor Red
Write-Host "   Login with a global admin from $($AlyaTenantName)" -ForegroundColor Red
Write-Host "   Use tenant guid $($AlyaTenantId)" -ForegroundColor Red
Write-Host " - Assign the TenantCreator application role to a user in your Azure Active Directory tenant:" -ForegroundColor Red
Write-Host "   Enterprise applications->AllApplications->Srch: Windows Virtual Desktop->Windows Virtual Desktop (not client)->Users and groups" -ForegroundColor Red
Write-Host "   Assign WVD Tenant Admins (Remove first existing one)" -ForegroundColor Red

#Stopping Transscript
Stop-Transcript
