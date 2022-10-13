#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2021

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
    23.11.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$definedProfileFile = $null #defaults to $($AlyaData)\intune\deviceGroupPolicyProfiles.json
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-IntuneDeviceGroupPolicyProfiles-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
if (-Not $definedProfileFile)
{
    $definedProfileFile = "$($AlyaData)\intune\deviceGroupPolicyProfiles.json"
}
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
$token = Get-AdalAccessToken

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Configure-IntuneDeviceGroupPolicyProfiles | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context and token
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}
$token = Get-AdalAccessToken

# Main
$definedProfilesStr = Get-Content -Path $definedProfileFile -Raw -Encoding UTF8
$definedProfilesStr =  $definedProfilesStr.Replace("##AlyaDomainName##", $AlyaDomainName)
$definedProfilesStr =  $definedProfilesStr.Replace("##AlyaDesktopBackgroundUrl##", $AlyaDesktopBackgroundUrl)
$definedProfilesStr =  $definedProfilesStr.Replace("##AlyaLockScreenBackgroundUrl##", $AlyaLockScreenBackgroundUrl)
$definedProfilesStr =  $definedProfilesStr.Replace("##AlyaWelcomeScreenBackgroundUrl##", $AlyaWelcomeScreenBackgroundUrl)
$definedProfilesStr =  $definedProfilesStr.Replace("##AlyaWebPage##", $AlyaWebPage)
$definedProfilesStr =  $definedProfilesStr.Replace("##AlyaCompanyNameShort##", $AlyaCompanyNameShort)
$definedProfilesStr =  $definedProfilesStr.Replace("##AlyaCompanyName##", $AlyaCompanyName)
$definedProfilesStr =  $definedProfilesStr.Replace("##AlyaTenantId##", $AlyaTenantId)
$definedProfilesStr =  $definedProfilesStr.Replace("##AlyaKeyVaultName##", $KeyVaultName)
$domPrts = $AlyaWebPage.Split("./")
$AlyaWebDomains = "https://*." + $domPrts[$domPrts.Length-2] + "." + $domPrts[$domPrts.Length-1]
$definedProfilesStr =  $definedProfilesStr.Replace("##AlyaWebDomains##", $AlyaWebDomains)
if ($definedProfilesStr.IndexOf("##Alya") -gt -1)
{
    throw "Some replacement did not work!"
}
$definedProfiles = $definedProfilesStr | ConvertFrom-Json

# Processing defined profiles
foreach($definedProfile in $definedProfiles)
{
    if ($definedProfile.Comment1 -and $definedProfile.Comment2 -and $definedProfile.Comment3) { continue }
    if ($definedProfile.displayName.EndsWith("_unused")) { continue }
    Write-Host "GroupPolicy profile $($definedProfile.displayName)" -ForegroundColor $CommandInfo

    # Checking if profile exists
    Write-Host "  Checking if profile exists"
    $searchValue = [System.Web.HttpUtility]::UrlEncode($definedProfile.displayName)
    $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?`$filter=displayName eq '$searchValue'"
    $extProfile = (Get-MsGraphObject -AccessToken $token -Uri $uri).value
    $mprofile = $definedProfile | ConvertTo-Json -Depth 50 -Compress | ConvertFrom-Json
    $mprofile.PSObject.properties.remove("definitionValues")
    if (-Not $extProfile.id)
    {
        # Creating the profile
        Write-Host "    Profile does not exist, creating"
        $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
        $extProfile = Post-MsGraph -AccessToken $token -Uri $uri -Body ($mprofile | ConvertTo-Json -Depth 50)
    }

    # Updating the profile
    Write-Host "    Updating the profile"
    $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($extProfile.id)"
    $extProfile = Patch-MsGraph -AccessToken $token -Uri $uri -Body ($mprofile | ConvertTo-Json -Depth 50)

    # Updating profile values
    Write-Host "    Updating profile values"
    $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions"
    $groupPolicyDefinitions = Get-MsGraphCollection -AccessToken $token -Uri $uri
    $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($extProfile.id)/definitionValues?`$expand=definition"
    $extDefinitionValues = Get-MsGraphCollection -AccessToken $token -Uri $uri
    foreach ($definedDefinitionValue in $definedProfile.definitionValues)
    {
        #$definedDefinitionValue = $definedProfile.definitionValues[0]
        Write-Host "      $($definedDefinitionValue.definition.displayName)"
        $extDefinitionValue = $extDefinitionValues | where { $_.definition.classType -eq $definedDefinitionValue.definition.classType -and $_.definition.groupPolicyCategoryId -eq $definedDefinitionValue.definition.groupPolicyCategoryId -and $_.definition.displayName -eq $definedDefinitionValue.definition.displayName }
        if (-Not $extDefinitionValue)
        {
            $groupPolicyDefinition = $groupPolicyDefinitions | where { $_.classType -eq $definedDefinitionValue.definition.classType -and $_.groupPolicyCategoryId -eq $definedDefinitionValue.definition.groupPolicyCategoryId -and $_.displayName -eq $definedDefinitionValue.definition.displayName } 
            if (-Not $groupPolicyDefinition)
            {
                throw "Was not able to find the right definition"
            }
            $mvalue = $definedDefinitionValue | ConvertTo-Json -Depth 50 -Compress | ConvertFrom-Json
            $mvalue.PSObject.properties.remove("definition")
            $mvalue.PSObject.properties.remove("definition@odata.bind")
            $mvalue | Add-Member -MemberType NoteProperty -Name "definition@odata.bind" -Value "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($groupPolicyDefinition.id)')" -Force
            $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($groupPolicyDefinition.id)')/presentations"
            $presentations = Get-MsGraphCollection -AccessToken $token -Uri $uri -DontThrowIfStatusEquals 400 -ErrorAction SilentlyContinue
            foreach($pvalue in $mvalue.presentationValues)
            {
                $presentation = $presentations | where { $_.label -eq $pvalue.presentation.label } 
                $pvalue | Add-Member -MemberType NoteProperty -Name "presentation@odata.bind" -Value "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($groupPolicyDefinition.id)')/presentations('$($presentation.id)')" -Force
                $pvalue.PSObject.properties.remove("definition")
                $pvalue.PSObject.properties.remove("definitionNext")
                $pvalue.PSObject.properties.remove("definitionPrev")
                $pvalue.PSObject.properties.remove("categories")
                $pvalue.PSObject.properties.remove("files")
                $pvalue.PSObject.properties.remove("presentations")
                $pvalue.PSObject.properties.remove("presentation")
            }
            if (-Not $mvalue.presentationValues) { $mvalue.PSObject.properties.remove("presentationValues") }
            $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($extProfile.id)/definitionValues"
            $extDefinitionValue = Post-MsGraph -AccessToken $token -Uri $uri -Body ($mvalue | ConvertTo-Json -Depth 50)
        }
        if ($definedDefinitionValue.presentationValues -and $definedDefinitionValue.presentationValues.Count -gt 0)
        {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($extProfile.id)/definitionValues/$($extDefinitionValue.id)/presentationValues?`$expand=presentation"
            $presentationValues = Get-MsGraphCollection -AccessToken $token -Uri $uri -DontThrowIfStatusEquals 400 -ErrorAction SilentlyContinue
            $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($groupPolicyDefinition.id)')/presentations"
            $presentations = Get-MsGraphCollection -AccessToken $token -Uri $uri -DontThrowIfStatusEquals 400 -ErrorAction SilentlyContinue
            foreach ($pvalue in $definedDefinitionValue.presentationValues)
            {
                #$pvalue = $definedDefinitionValue.presentationValues[0]
                $mvalue = $pvalue | ConvertTo-Json -Depth 50 -Compress | ConvertFrom-Json
                $mvalue.PSObject.properties.remove("definition")
                $mvalue.PSObject.properties.remove("definitionNext")
                $mvalue.PSObject.properties.remove("definitionPrev")
                $mvalue.PSObject.properties.remove("categories")
                $mvalue.PSObject.properties.remove("files")
                $mvalue.PSObject.properties.remove("presentations")
                $mvalue.PSObject.properties.remove("presentation")
                $mvalue.PSObject.properties.remove("presentation@odata.bind")
                $presentation = $presentations | where { $_.label -eq $pvalue.presentation.label } 
                $mvalue | Add-Member -MemberType NoteProperty -Name "presentation@odata.bind" -Value "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($groupPolicyDefinition.id)')/presentations('$($presentation.id)')" -Force
                $presentationValue = $presentationValues | where { $_.presentation.label -eq $pvalue.presentation.label }
                if (-Not $presentationValue)
                {
                    $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($extProfile.id)/definitionValues/$($extDefinitionValue.id)/presentationValues"
                    $presentationValue = Post-MsGraph -AccessToken $token -Uri $uri -Body ($mvalue | ConvertTo-Json -Depth 50)
                }
                else
                {
                    $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($extProfile.id)/definitionValues/$($extDefinitionValue.id)/presentationValues/$($presentationValue.id)"
                    $presentationValue = Patch-MsGraph -AccessToken $token -Uri $uri -Body ($mvalue | ConvertTo-Json -Depth 50)
                }
            }
        }
    }

}

#Stopping Transscript
Stop-Transcript
