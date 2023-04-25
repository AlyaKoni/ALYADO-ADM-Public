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
    05.10.2020 Konrad Brunner       Initial Version
    24.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
    [string]$UploadOnlyAppWithName = $null,
    [string]$ContinueAtAppWithName = $null
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Upload-IntuneWebApps-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$DataRoot = Join-Path (Join-Path $AlyaData "intune") "WebApps"
if (-Not (Test-Path $DataRoot))
{
    $tmp = New-Item -Path $DataRoot -ItemType Directory -Force
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "Directory.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementApps.ReadWrite.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Upload-IntuneWebApps | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

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
    $str =  $str.Replace("##AlyaKeyVaultName##", $KeyVaultName)
    $str =  $str.Replace("##AlyaSupportTitle##", $AlyaSupportTitle)
    $str =  $str.Replace("##AlyaSupportTel##", $AlyaSupportTel)
    $str =  $str.Replace("##AlyaSupportMail##", $AlyaSupportMail)
    $str =  $str.Replace("##AlyaSupportUrl##", $AlyaSupportUrl)
    $domPrts = $AlyaWebPage.Split("./")
    $AlyaWebDomains = "https://*." + $domPrts[$domPrts.Length-2] + "." + $domPrts[$domPrts.Length-1]
    $str =  $str.Replace("##AlyaWebDomains##", $AlyaWebDomains)
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
                        $sobj = $prop.Value | select -First 1
                        if ($sobj.GetType().Name -eq "String")
                        {
                            if ($sobj.Contains("##Alya"))
                            {
                                $prop.Value[0] = Replace-AlyaString -str $sobj
                            }
                        }
                        else
                        {
                            if (-Not ($sobj.GetType().IsValueType))
                            {   
                                Replace-AlyaStrings -obj $sobj -depth ($depth+1)
                            }
                        }
                    }
                }
            }
        }
    }
}

# Main
$packages = Get-ChildItem -Path $DataRoot -Directory
$continue = $true
$hadError = $false
foreach($packageDir in $packages)
{
    if ($ContinueAtAppWithName -and $packageDir.Name -eq $ContinueAtAppWithName) { $continue = $false }
    if ($ContinueAtAppWithName -and $continue) { continue }
    if ($UploadOnlyAppWithName -and $packageDir.Name -ne $UploadOnlyAppWithName) { continue }
    if ($packageDir.Name -like "*unused*" -or $packageDir.Name -like "*donotuse*") { continue }

    Write-Host "Uploading web app '$($packageDir.Name)'" -ForegroundColor $CommandInfo
    $configPath = Join-Path $packageDir.FullName "config.json"

    # Reading and preparing app configuration
    Write-Host "  Reading and preparing app configuration"
    $appConfig = Get-Content -Path $configPath -Raw -Encoding UTF8
    $appConfig = $appConfig | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty isAssigned,dependentAppCount,supersedingAppCount,supersededAppCount,committedContentVersion,size,id,createdDateTime,lastModifiedDateTime,version,'@odata.context',uploadState,packageId,appIdentifier,publishingState,usedLicenseCount,totalLicenseCount,productKey,licenseType,packageIdentityName

    # Replacing constants
    Replace-AlyaStrings -obj $appConfig -depth 1
    if (($appConfig | ConvertTo-Json -Depth 50).IndexOf("##Alya") -gt -1)
    {
        ($appConfig | ConvertTo-Json -Depth 50)
        throw "Some replacement did not work!"
    }

    $logo = Get-ChildItem -Path $packageDir.FullName -Filter "Logo.*"
    if ($logo)
    {
        $iconResponse = [System.IO.File]::ReadAllBytes("$($logo.FullName)")
        $base64icon = [System.Convert]::ToBase64String($iconResponse)
        $iconExt = ([System.IO.Path]::GetExtension($logo.FullName)).replace(".","")
        $iconType = "image/$iconExt"
        $appConfig.largeIcon = @{ "@odata.type" = "#microsoft.graph.mimeContent" }
        $appConfig.largeIcon.type = "$iconType"
        $appConfig.largeIcon.value = "$base64icon"
    }

    $appConfigJson = $appConfig | ConvertTo-Json -Depth 50
    $appConfigJson | Set-Content -Path $configPath -Encoding UTF8

    try {
        
        # Checking if app exists
        Write-Host "  Checking if app exists"
        $searchValue = [System.Web.HttpUtility]::UrlEncode($appConfig.displayName)
        $uri = "/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$searchValue'"
        $app = (Get-MsGraphObject -Uri $uri).value
        if (-Not $app.id)
        {
            # Creating app
            Write-Host "  Creating app"
            $uri = "/beta/deviceAppManagement/mobileApps"
            $app = Post-MsGraph -Uri $uri -Body $appConfigJson
        }

        # Committing the app
        Write-Host "  Committing the app"
        $appConfig.PSObject.Properties.Remove('appUrl')
        $uri = "/beta/deviceAppManagement/mobileApps/$($app.id)"
        $appP = Patch-MsGraph -Uri $uri -Body ($appConfig | ConvertTo-Json)
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
