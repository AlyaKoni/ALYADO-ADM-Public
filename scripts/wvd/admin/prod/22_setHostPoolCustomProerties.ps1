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
    17.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$HostPoolName = "alyainfphpol003"
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\prod\22_setHostPoolCustomProerties-$($AlyaTimeString).log" | Out-Null

# Constants
$ErrorActionPreference = "Stop"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

$AllowAudioCapturing = $true
$AllowPlayingSound = $true
$AllowCamera = $true
$AllowDevices = $true
$AllowDrives = $null # to be tested
$AllowClipboard = $null # to be tested
$AllowPrinters = $null # to be tested
$AllowMultiMonitor = $null # to be tested

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 22_setHostPoolCustomProerties | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error -Message "Can't get Az context! Not logged in?"
    Exit 1
}

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$AzureAdApplication = Get-AzADApplication -DisplayName $AlyaWvdServicePrincipalNameProd -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    throw "Azure AD Application not found. Please create the Azure AD Application $AlyaWvdServicePrincipalNameProd"
}
$AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdServicePrincipalNameProd

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$AlyaWvdServicePrincipalAssetName = "$($AlyaWvdServicePrincipalNameProd)Key"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AlyaWvdServicePrincipalAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    throw "Key Vault secret not found. Please create the secret $AlyaWvdServicePrincipalAssetName"
}
$AlyaWvdServicePrincipalPassword = $AzureKeyVaultSecret.SecretValueText
$AlyaWvdServicePrincipalPasswordSave = ConvertTo-SecureString $AlyaWvdServicePrincipalPassword -AsPlainText -Force

# Login to WVD
if (-Not $Global:RdsContext)
{
	Write-Host "Logging in to wvd" -ForegroundColor $CommandInfo
	$rdsCreds = New-Object System.Management.Automation.PSCredential($AzureAdServicePrincipal.ApplicationId, $AlyaWvdServicePrincipalPasswordSave)
	$Global:RdsContext = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $rdsCreds -ServicePrincipal -AadTenantId $AlyaTenantId
	#LoginTo-Wvd -AppId $AzureAdServicePrincipal.ApplicationId -SecPwd $AlyaWvdServicePrincipalPasswordSave
}

# Main
# Supported Properties: https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files
# Default: empty
$Dirty = $false
$properties = (Get-RdsHostPool -TenantName $AlyaWvdTenantNameProd -Name $HostPoolName).CustomRdpProperty
if (-Not $properties)
{
    $properties = ""
}

# Configurations
if ($AllowPlayingSound -ne $null)
{
    if (-Not $AllowPlayingSound)
    {
        if ($properties.IndexOf("audiomode:i:") -eq -1)
        {
            $properties += "audiomode:i:1;"
            $Dirty = $true
        }
        if ($properties.IndexOf("audiomode:i:0") -gt -1)
        {
            $properties = $properties.Replace("audiomode:i:0","audiomode:i:1")
            $Dirty = $true
        }
    }
    else
    {
        if ($properties.IndexOf("audiomode:i:") -eq -1)
        {
            $properties += "audiomode:i:0;"
            $Dirty = $true
        }
        if ($properties.IndexOf("audiomode:i:1") -gt -1)
        {
            $properties = $properties.Replace("audiomode:i:1","audiomode:i:0")
            $Dirty = $true
        }
    }
}

if ($AllowAudioCapturing -ne $null)
{
    if ($AllowAudioCapturing)
    {
        if ($properties.IndexOf("audiocapturemode:i:") -eq -1)
        {
            $properties += "audiocapturemode:i:1;"
            $Dirty = $true
        }
        if ($properties.IndexOf("audiocapturemode:i:0") -gt -1)
        {
            $properties = $properties.Replace("audiocapturemode:i:0","audiocapturemode:i:1")
            $Dirty = $true
        }
    }
    else
    {
        if ($properties.IndexOf("audiocapturemode:i:") -eq -1)
        {
            $properties += "audiocapturemode:i:0;"
            $Dirty = $true
        }
        if ($properties.IndexOf("audiocapturemode:i:1") -gt -1)
        {
            $properties = $properties.Replace("audiocapturemode:i:1","audiocapturemode:i:0")
            $Dirty = $true
        }
    }
}

if ($AllowCamera -ne $null)
{
    if ($AllowCamera)
    {
        if ($properties.IndexOf("camerastoredirect:s:") -eq -1)
        {
            $properties += "camerastoredirect:s:*;"
            $Dirty = $true
        }
    }
    else
    {
        if ($properties.IndexOf("camerastoredirect:s:*") -gt -1)
        {
            $properties = $properties.Replace("camerastoredirect:s:*;","")
            $Dirty = $true
        }
    }
}

if ($AllowDevices -ne $null)
{
    if ($AllowDevices)
    {
        if ($properties.IndexOf("devicestoredirect:s:") -eq -1)
        {
            $properties += "devicestoredirect:s:*;"
            $Dirty = $true
        }
    }
    else
    {
        if ($properties.IndexOf("devicestoredirect:s:*") -gt -1)
        {
            $properties = $properties.Replace("devicestoredirect:s:*;","")
            $Dirty = $true
        }
    }
}

if ($AllowDrives -ne $null)
{
    if ($AllowDrives)
    {
        if ($properties.IndexOf("drivestoredirect:s:") -eq -1)
        {
            $properties += "drivestoredirect:s:*;"
            $Dirty = $true
        }
    }
    else
    {
        if ($properties.IndexOf("drivestoredirect:s:*") -gt -1)
        {
            $properties = $properties.Replace("drivestoredirect:s:*;","")
            $Dirty = $true
        }
    }
}

if ($AllowClipboard -ne $null)
{
    if ($AllowClipboard)
    {
        if ($properties.IndexOf("redirectclipboard:i:") -eq -1)
        {
            $properties += "redirectclipboard:i:1;"
            $Dirty = $true
        }
        if ($properties.IndexOf("redirectclipboard:i:0") -gt -1)
        {
            $properties = $properties.Replace("redirectclipboard:i:0","redirectclipboard:i:1")
            $Dirty = $true
        }
    }
    else
    {
        if ($properties.IndexOf("redirectclipboard:i:") -eq -1)
        {
            $properties += "redirectclipboard:i:0;"
            $Dirty = $true
        }
        if ($properties.IndexOf("redirectclipboard:i:1") -gt -1)
        {
            $properties = $properties.Replace("redirectclipboard:i:1","redirectclipboard:i:0")
            $Dirty = $true
        }
    }
}

if ($AllowPrinters -ne $null)
{
    if ($AllowPrinters)
    {
        if ($properties.IndexOf("redirectprinters:i:") -eq -1)
        {
            $properties += "redirectprinters:i:1;"
            $Dirty = $true
        }
        if ($properties.IndexOf("redirectprinters:i:0") -gt -1)
        {
            $properties = $properties.Replace("redirectprinters:i:0","redirectprinters:i:1")
            $Dirty = $true
        }
    }
    else
    {
        if ($properties.IndexOf("redirectprinters:i:") -eq -1)
        {
            $properties += "redirectprinters:i:0;"
            $Dirty = $true
        }
        if ($properties.IndexOf("redirectprinters:i:1") -gt -1)
        {
            $properties = $properties.Replace("redirectprinters:i:1","redirectprinters:i:0")
            $Dirty = $true
        }
    }
}

if ($AllowMultiMonitor -ne $null)
{
    if ($AllowMultiMonitor)
    {
        if ($properties.IndexOf("use multimon:i:") -eq -1)
        {
            $properties += "use multimon:i:1;"
            $Dirty = $true
        }
        if ($properties.IndexOf("use multimon:i:0") -gt -1)
        {
            $properties = $properties.Replace("use multimon:i:0","use multimon:i:1")
            $Dirty = $true
        }
    }
    else
    {
        if ($properties.IndexOf("use multimon:i:") -eq -1)
        {
            $properties += "use multimon:i:0;"
            $Dirty = $true
        }
        if ($properties.IndexOf("use multimon:i:1") -gt -1)
        {
            $properties = $properties.Replace("use multimon:i:1","use multimon:i:0")
            $Dirty = $true
        }
    }
}

if ($Dirty){
    $properties = $properties.TrimEnd(";")
    #                                                                                          audiomode:i:0;audiocapturemode:i:1;camerastoredirect:s:*;devicestoredirect:s:*;drivestoredirect:s:*;redirectclipboard:i:1;redirectprinters:i:1;use multimon:i:1
    Set-RdsHostPool -TenantName $AlyaWvdTenantNameProd -Name $HostPoolName -CustomRdpProperty $properties
}

#Stopping Transscript
Stop-Transcript