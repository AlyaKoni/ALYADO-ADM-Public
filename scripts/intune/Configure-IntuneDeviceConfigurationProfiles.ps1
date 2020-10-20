#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2019, 2020

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
    20.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$ProfileFile = $null #defaults to $($AlyaData)\intune\deviceConfigurationProfiles.json
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-IntunedeviceConfigurations-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$DataRoot = Join-Path $AlyaData "intune"
if (-Not $ProfileFile)
{
    $ProfileFile = "$($AlyaData)\intune\deviceConfigurationProfiles.json"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
$token = Get-AdalAccessToken

# Getting context and token
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}
$token = Get-AdalAccessToken

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

#$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
#$actProfile = Get-MsGraphCollection -AccessToken $token -Uri $uri
#$actProfile | ConvertTo-Json -Depth 50 | Set-Content -Path ($ProfileFile+".txt") -Encoding UTF8

# Getting iOS configuration
Write-Host "Getting iOS configuration" -ForegroundColor $CommandInfo
$appleConfigured = $false
$uri = "https://graph.microsoft.com/beta/devicemanagement/applePushNotificationCertificate"
$appleConfiguration = Get-MsGraphObject -AccessToken $token -Uri $uri
$appleConfigured = $false
if ($appleConfiguration -and $appleConfiguration.certificateSerialNumber)
{
    $appleConfigured = $true
}
else
{
    $appleConfiguration = $appleConfiguration.value
    if ($appleConfiguration -and $appleConfiguration.certificateSerialNumber)
    {
        $appleConfigured = $true
    }
}

# Getting Android configuration
Write-Host "Getting Android configuration" -ForegroundColor $CommandInfo
$androidConfigured = $false
$uri = "https://graph.microsoft.com/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings"
$androidConfiguration = Get-MsGraphObject -AccessToken $token -Uri $uri
$androidConfigured = $false
if ($androidConfiguration -and $androidConfiguration.deviceOwnerManagementEnabled)
{
    $androidConfigured = $true
}
else
{
    $androidConfigured = $androidConfigured.Value
    if ($androidConfiguration -and $androidConfiguration.deviceOwnerManagementEnabled)
    {
        $androidConfigured = $true
    }
}

# Processing defined profiles
foreach($profile in $profiles)
{
    if ($profile.Comment1 -and $profile.Comment2 -and $profile.Comment3) { continue }
    if ($profile.displayName.EndsWith("_unused")) { continue }
    Write-Host "Configuring profile $($profile.displayName)" -ForegroundColor $CommandInfo

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

    # Special handling per profile
    if ($profile.displayName.Contains("PIN Reset"))
    {
        $AzureAdServicePrincipalC = Get-AzADServicePrincipal -DisplayName "Microsoft Pin Reset Client Production" -ErrorAction SilentlyContinue
        $AzureAdServicePrincipalS = Get-AzADServicePrincipal -DisplayName "Microsoft Pin Reset Service Production" -ErrorAction SilentlyContinue
        if ((-Not $AzureAdServicePrincipalC) -or (-Not $AzureAdServicePrincipalS))
        {
            #TODO script admin consent
            Write-Warning "The profile $($profile.displayName) requires admin consent. Please give admin consent with following two urls:"
            Write-Warning "https://login.windows.net/common/oauth2/authorize?response_type=code&client_id=b8456c59-1230-44c7-a4a2-99b085333e84&resource=https%3A%2F%2Fgraph.windows.net&redirect_uri=https%3A%2F%2Fcred.microsoft.com&state=e9191523-6c2f-4f1d-a4f9-c36f26f89df0&prompt=admin_consent"
            Write-Warning "https://login.windows.net/common/oauth2/authorize?response_type=code&client_id=9115dd05-fad5-4f9c-acc7-305d08b1b04e&resource=https%3A%2F%2Fcred.microsoft.com%2F&redirect_uri=ms-appx-web%3A%2F%2FMicrosoft.AAD.BrokerPlugin%2F9115dd05-fad5-4f9c-acc7-305d08b1b04e&state=6765f8c5-f4a7-4029-b667-46a6776ad611&prompt=admin_consent"
            Write-Warning "Rerun this script after consent done!"
            Exit 80
        }
    }
    if ($profile.displayName.Contains("Local Group Configuration"))
    {
        #https://docs.microsoft.com/en-us/azure/active-directory/devices/assign-local-admin
        $AlyaDeviceAdminsGroupSid = $null
        if ($AlyaDeviceAdminsGroupName -and -Not [string]::IsNullOrEmpty($AlyaDeviceAdminsGroupName))
        {
            $Uri = "https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$AlyaDeviceAdminsGroupName'"
            $GrpRslt = Get-MsGraph -AccessToken $token -Uri $Uri
            $AlyaDeviceAdminsGroupSid = $GrpRslt.securityIdentifier
        }
        $accessgroup = [xml]$profile.omaSettings[0].value.Trim("#")
        foreach ($elem in $accessgroup.SelectNodes("//member"))
        {
            if ($elem.name -eq "`$AlyaDeviceAdminsGroupSid")
            {
                if (-Not $AlyaDeviceAdminsGroupSid)
                {
                    $elem.ParentNode.RemoveChild($elem)
                }
                else
                {
                    $elem.SetAttribute("name", $AlyaDeviceAdminsGroupSid)
                }
            }
        }
        $profile.omaSettings[0].value = [System.Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($accessgroup.OuterXml.ToString()))
    }
    
    # Checking if profile exists
    Write-Host "  Checking if profile exists"
    $searchValue = [System.Web.HttpUtility]::UrlEncode($profile.displayName)
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=displayName eq '$searchValue'"
    $actProfile = (Get-MsGraphObject -AccessToken $token -Uri $uri).value
    if (-Not $actProfile.id)
    {
        # Creating the profile
        Write-Host "    Profile does not exist, creating"
        Add-Member -InputObject $profile -MemberType NoteProperty -Name "id" -Value "00000000-0000-0000-0000-000000000000"
        $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
        $actProfile = Post-MsGraph -AccessToken $token -Uri $uri -Body ($profile | ConvertTo-Json -Depth 50)
    }

    # Updating the profile
    Write-Host "    Updating the profile"
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($actProfile.id)"
    $actProfile = Patch-MsGraph -AccessToken $token -Uri $uri -Body ($profile | ConvertTo-Json -Depth 50)
}

#Stopping Transscript
Stop-Transcript