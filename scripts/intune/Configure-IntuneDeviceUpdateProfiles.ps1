#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2023

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
    20.10.2020 Konrad Brunner       Initial Version
    24.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
    [string]$ProfileFile = $null #defaults to $($AlyaData)\intune\deviceUpdateProfiles.json
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-IntuneDeviceUpdateProfiles-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
if (-Not $ProfileFile)
{
    $ProfileFile = "$($AlyaData)\intune\deviceUpdateProfiles.json"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "DeviceManagementServiceConfig.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.Read.All",
    "Directory.Read.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Configure-IntuneDeviceUpdateProfiles | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$profiles = Get-Content -Path $ProfileFile -Raw -Encoding UTF8 | ConvertFrom-Json

# Functions
function Replace-AlyaString($str)
{
    $str =  $str.Replace("##AlyaDomainName##", $AlyaDomainName)
    $str =  $str.Replace("##AlyaDesktopBackgroundUrl##", $AlyaDesktopBackgroundUrl)
    $str =  $str.Replace("##AlyaLockScreenBackgroundUrl##", $AlyaLockScreenBackgroundUrl)
    $str =  $str.Replace("##AlyaWelcomeScreenBackgroundUrl##", $AlyaWelcomeScreenBackgroundUrl)
    $str =  $str.Replace("##AlyaWebPage##", $AlyaWebPage)
    $str =  $str.Replace("##AlyaCompanyNameShort##", $AlyaCompanyNameShort)
    $str =  $str.Replace("##AlyaCompanyName##", $AlyaCompanyName)
    $str =  $str.Replace("##AlyaTenantId##", $AlyaTenantId)
    $domPrts = $AlyaWebPage.Split("./")
    $AlyaLocalDomains = "https://*." + $domPrts[$domPrts.Length-2] + "." + $domPrts[$domPrts.Length-1]
    $str =  $str.Replace("##AlyaLocalDomains##", $AlyaLocalDomains)
    return $str
}

function Replace-AlyaStrings($obj, $depth)
{
    if ($depth -gt 3) { return }
    foreach($prop in $obj.PSObject.Properties)
    {
        if ($prop.Value)
        {
            if ($prop.Value.GetType().Name -eq "String")
            {
                if ($prop.Value.Contains("##Alya"))
                {
                    $prop.Value = Replace-AlyaString -str $prop.Value
                }
            }
            else
            {
                if (-Not ($prop.Value.GetType().IsValueType))
                {
                    $cnt = 1
                    $cntMem = Get-Member -InputObject $prop.Value -Name Count
                    if ($cntMem)
                    {
                        $cnt = $prop.Value.Count
                    }
                    else
                    {
                        $cntMem = Get-Member -InputObject $prop.Value -Name Length
                        if ($cntMem)
                        {
                            $cnt = $prop.Value.Length
                        }
                        else
                        {
                            $cnt = ($prop.Value | Measure-Object | Select-Object Count).Count
                        }
                    }
                    if ($cnt -gt 1)
                    {
                        foreach($sobj in $prop.Value)
                        {
                            if ($sobj.GetType().Name -eq "String")
                            {
                                if ($sobj.Contains("##Alya"))
                                {
                                    #TODO will this work?
                                    $sobj = Replace-AlyaString -str $sobj
                                }
                            }
                            elseif (-Not ($sobj.GetType().IsValueType))
                            {
                                Replace-AlyaStrings -obj $sobj -depth ($depth+1)
                            }
                        }
                    }
                    else
                    {
                        Replace-AlyaStrings -obj $prop.Value -depth ($depth+1)
                    }
                }
            }
        }
    }
}

# Getting iOS configuration
Write-Host "Getting iOS configuration" -ForegroundColor $CommandInfo
$appleConfigured = $false
$uri = "/beta/devicemanagement/applePushNotificationCertificate"
$appleConfiguration = Get-MsGraphObject -Uri $uri
$appleConfigured = $false
if ($appleConfiguration -and $appleConfiguration.certificateSerialNumber)
{
    Write-Host "  Apple token is configured"
    $appleConfigured = $true
}
else
{
    $appleConfiguration = $appleConfiguration.value
    if ($appleConfiguration -and $appleConfiguration.certificateSerialNumber)
    {
        Write-Host "  Apple token is configured"
        $appleConfigured = $true
    }
}

# Getting Android configuration
Write-Host "Getting Android configuration" -ForegroundColor $CommandInfo
$androidConfigured = $false
$uri = "/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings"
$androidConfiguration = Get-MsGraphObject -Uri $uri
$androidConfigured = $false
if ($androidConfiguration -and $androidConfiguration.deviceOwnerManagementEnabled)
{
    Write-Host "  Android token is configured"
    $androidConfigured = $true
}
else
{
    Write-Host "  Android token is configured"
    $androidConfigured = $androidConfigured.Value
    if ($androidConfiguration -and $androidConfiguration.deviceOwnerManagementEnabled)
    {
        $androidConfigured = $true
    }
}

# Processing defined profiles
$hadError = $false
foreach($profile in $profiles)
{
    if ($profile.Comment1 -and $profile.Comment2 -and $profile.Comment3) { continue }
    if ($profile.displayName.EndsWith("_unused")) { continue }
    Write-Host "Configuring profile '$($profile.displayName)'" -ForegroundColor $CommandInfo

    # Checking if poliy is applicable
    Write-Host "  Checking if profile is applicable"
    if ($profile."@odata.type" -eq "#microsoft.graph.iosConfigurationProfile" -and -not $appleConfigured)
    {
        Write-Warning "iosConfigurationProfile is not applicable"
        continue
    }
    if ($profile."@odata.type" -eq "#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration" -and -not $androidConfigured)
    {
        Write-Warning "androidConfigurationProfile is not applicable"
        continue
    }

    # Replacing constants
    Replace-AlyaStrings -obj $profile -depth 1
    if (($profile | ConvertTo-Json -Depth 50).IndexOf("##Alya") -gt -1)
    {
        ($profile | ConvertTo-Json -Depth 50)
        throw "Some replacement did not work!"
    }

    try {
        
        # Checking if profile exists
        Write-Host "  Checking if profile exists"
        $searchValue = [System.Web.HttpUtility]::UrlEncode($profile.displayName)
        $uri = "/beta/deviceManagement/deviceConfigurations?`$filter=displayName eq '$searchValue'"
        $actProfile = (Get-MsGraphObject -Uri $uri).value
        if (-Not $actProfile.id)
        {
            # Creating the profile
            Write-Host "    Profile does not exist, creating"
            Add-Member -InputObject $profile -MemberType NoteProperty -Name "id" -Value "00000000-0000-0000-0000-000000000000"
            $uri = "/beta/deviceManagement/deviceConfigurations"
            $actProfile = Post-MsGraph -Uri $uri -Body ($profile | ConvertTo-Json -Depth 50)
        }

        # Updating the profile
        Write-Host "    Updating the profile"
        $uri = "/beta/deviceManagement/deviceConfigurations/$($actProfile.id)"
        $actProfile = Patch-MsGraph -Uri $uri -Body ($profile | ConvertTo-Json -Depth 50)
    }
    catch {
        $hadError = $true
    }

}
if ($hadError)
{
    Write-Host "There was an error. Please see above." -ForegroundColor $CommandError
}

#Stopping Transscript
Stop-Transcript
