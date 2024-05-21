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
    18.11.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$definedPolicyFile = $null #defaults to $($AlyaData)\intune\deviceConfigurationPolicies.json
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Configure-IntuneDeviceConfigurationPolicies-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
if (-Not $definedPolicyFile)
{
    $definedPolicyFile = "$($AlyaData)\intune\deviceConfigurationPolicies.json"
}
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"

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
Write-Host "Intune | Configure-IntuneDeviceConfigurationPolicies | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$definedPoliciesStr = Get-Content -Path $definedPolicyFile -Raw -Encoding $AlyaUtf8Encoding
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaDomainName##", $AlyaDomainName)
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaDesktopBackgroundUrl##", $AlyaDesktopBackgroundUrl)
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaLockScreenBackgroundUrl##", $AlyaLockScreenBackgroundUrl)
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaWelcomeScreenBackgroundUrl##", $AlyaWelcomeScreenBackgroundUrl)
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaWebPage##", $AlyaWebPage)
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaPrivacyUrl##", $AlyaPrivacyUrl)
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaCompanyNameShort##", $AlyaCompanyNameShort)
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaCompanyName##", $AlyaCompanyName)
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaTenantId##", $AlyaTenantId)
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaKeyVaultName##", $KeyVaultName)
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaSupportTitle##", $AlyaSupportTitle)
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaSupportTel##", $AlyaSupportTel)
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaSupportMail##", $AlyaSupportMail)
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaSupportUrl##", $AlyaSupportUrl)
$domPrts = $AlyaWebPage.Split("./")
$AlyaLocalDomains = "https://*." + $domPrts[$domPrts.Length-2] + "." + $domPrts[$domPrts.Length-1]
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaWebDomains##", $AlyaLocalDomains)
$definedPoliciesStr =  $definedPoliciesStr.Replace("##AlyaLocalDomains##", $AlyaLocalDomains)
if ($definedPoliciesStr.IndexOf("##Alya") -gt -1)
{
    throw "Some replacement did not work!"
}
$definedPolicies = $definedPoliciesStr | ConvertFrom-Json

# Processing defined policies
$hadError = $false
foreach($definedPolicy in $definedPolicies)
{
    if ($definedPolicy.Comment1 -and $definedPolicy.Comment2 -and $definedPolicy.Comment3) { continue }
    if ($definedPolicy.name.EndsWith("_unused")) { continue }
    Write-Host "ConfigurationPolicy '$($definedPolicy.name)'" -ForegroundColor $CommandInfo

    try {
        
        # Checking if policy exists
        Write-Host "  Checking if policy exists"
        $searchValue = [System.Web.HttpUtility]::UrlEncode($definedPolicy.name)
        $uri = "/beta/deviceManagement/configurationPolicies?`$filter=name eq '$searchValue'"
        $extPolicy = (Get-MsGraphObject -Uri $uri).value
        $mpolicy = $definedPolicy | ConvertTo-Json -Depth 50 -Compress | ConvertFrom-Json
        $mpolicySettings = $mpolicy.settings

        if ($mpolicy.templateReference.templateId)
        {
            $uri = "/beta/deviceManagement/configurationPolicyTemplates?`$filter=id eq '$($mpolicy.templateReference.templateId)'"
            $policyTemplate = Get-MsGraphCollection -Uri $uri
            if (-Not $policyTemplate.id)
            {
                $searchValue = [System.Web.HttpUtility]::UrlEncode($mpolicy.templateReference.templateDisplayName)
                $uri = "/beta/deviceManagement/configurationPolicyTemplates?`$filter=displayName eq '$searchValue'"
                $policyTemplate = Get-MsGraphCollection -Uri $uri
                if (-Not $policyTemplate.id)
                {
                    $searchValue = [System.Web.HttpUtility]::UrlEncode($mpolicy.templateReference.templateFamily)
                    $uri = "/beta/deviceManagement/configurationPolicyTemplates?`$filter=templateFamily eq '$searchValue'"
                    $policyTemplate = Get-MsGraphCollection -Uri $uri
                }
            }
            $mpolicy.templateReference.templateId = $policyTemplate.id
            $mpolicy.templateReference.templateDisplayName = $policyTemplate.displayName
            $mpolicy.templateReference.templateFamily = $policyTemplate.templateFamily
            $mpolicy.templateReference.templateDisplayVersion = $policyTemplate.displayVersion
        }

        if (-Not $extPolicy.id)
        {
            # Creating the policy
            Write-Host "    Policy does not exist, creating"
            $uri = "/beta/deviceManagement/configurationPolicies"
            $extPolicy = Post-MsGraph -Uri $uri -Body ($mpolicy | ConvertTo-Json -Depth 50)
        }

        # Updating the policy
        Write-Host "    Updating the policy"
        $uri = "/beta/deviceManagement/configurationPolicies/$($extPolicy.id)"
        $mpolicy.PSObject.properties.remove("technologies")
        $mpolicy.PSObject.properties.remove("creationSource")
        $mpolicy.PSObject.properties.remove("priorityMetaData")
        $mpolicy.PSObject.properties.remove("platforms")
        $mpolicy.PSObject.properties.remove("templateReference")
        $mpolicy.PSObject.properties.remove("settings")
        $null = Patch-MsGraph -Uri $uri -Body ($mpolicy | ConvertTo-Json -Depth 50)

        # Updating policy values
        #TODO not working!!!
        # Write-Host "    Updating policy values"
        # $uri = "/beta/deviceManagement/configurationPolicies/$($extPolicy.Id)/settings"
        # $extPolicySettings = Get-MsGraphCollection -Uri $uri
        # $nextId = ($extPolicySettings.id | Measure-Object -Maximum).Maximum
        # foreach($extPolicySetting in $extPolicySettings)
        # {
        #     $mpolicySetting = $mpolicySettings | Where-Object {`
        #         $_.settingInstance.'@odata.type' -eq $extPolicySetting.settingInstance.'@odata.type' -and `
        #         $_.settingInstance.settingDefinitionId -eq $extPolicySetting.settingInstance.settingDefinitionId }
        #     if ($mpolicySetting)
        #     {
        #         Write-Host "Found, updating"
        #         $uri = "/beta/deviceManagement/configurationPolicies/$($extPolicy.Id)/settings/$($extPolicySetting.id)"
        #         #if ($mpolicySetting.id) { $mpolicySetting.PSObject.properties.remove("id") }
        #         $null = Patch-MsGraph -Uri $uri -Body ($mpolicySetting | ConvertTo-Json -Depth 50)
        #     }
        #     else
        #     {
        #         Write-Host "Not found, creating"
        #         $uri = "/beta/deviceManagement/configurationPolicies/$($extPolicy.Id)/settings"
        #         $mpolicySetting.id = $nextId++
        #         $null = Post-MsGraph -Uri $uri -Body ($mpolicySetting | ConvertTo-Json -Depth 50)
        #     }
        # }
        # $uri = "/beta/deviceManagement/configurationPolicies/$($extPolicy.Id)/settings"
        # $extPolicySettings = Get-MsGraphCollection -Uri $uri
        # foreach($mpolicySetting in $mpolicySettings)
        # {
        #     $extPolicySetting = $extPolicySettings | Where-Object {`
        #         $_.settingInstance.'@odata.type' -eq $mpolicySetting.settingInstance.'@odata.type' -and `
        #         $_.settingInstance.settingDefinitionId -eq $mpolicySetting.settingInstance.settingDefinitionId }
        #     if (-Not $extPolicySetting)
        #     {
        #         Write-Host "Not found, deleting"
        #         $uri = "/beta/deviceManagement/configurationPolicies/$($extPolicy.Id)/settings/$($extPolicySetting.id)"
        #         $null = Delete-MsGraph -Uri $uri
        #     }
        # }
    }
    catch {
        $hadError = $true
    }

}
if ($hadError)
{
    Write-Host "There was an error. Please see above." -ForegroundColor $CommandError
}

# Assigning defined policys
foreach($policy in $definedPolicies)
{
    if ($policy.Comment1 -and $policy.Comment2 -and $policy.Comment3) { continue }
    if ($policy.name.EndsWith("_unused")) { continue }
    Write-Host "Assigning ConfigurationPolicy policy '$($policy.name)'" -ForegroundColor $CommandInfo

    try {
        
        # Checking if policy exists
        Write-Host "  Checking if policy exists"
        $searchValue = [System.Web.HttpUtility]::UrlEncode($definedPolicy.name)
        $uri = "/beta/deviceManagement/configurationPolicies?`$filter=name eq '$searchValue'"
        $actPolicy = (Get-MsGraphObject -Uri $uri).value
        if ($actPolicy.id)
        {

            $tGroups = @()
            if ($policy.name.StartsWith("WIN"))
            {
                $sGroup = Get-MgBetaGroup -Filter "displayName eq '$($AlyaCompanyNameShortM365)SG-DEV-WINMDM'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-WINMDM not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
                $sGroup = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaCompanyNameShortM365)SG-DEV-WIN365MDM'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-WIN365MDM not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }
            if ($policy.name.StartsWith("WIN10"))
            {
                $sGroup = Get-MgBetaGroup -Filter "displayName eq '$($AlyaCompanyNameShortM365)SG-DEV-WINMDM10'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-WINMDM10 not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }
            if ($policy.name.StartsWith("WIN11"))
            {
                $sGroup = Get-MgBetaGroup -Filter "displayName eq '$($AlyaCompanyNameShortM365)SG-DEV-WINMDM11'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-WINMDM11 not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
                $sGroup = Get-MgBetaGroup -Filter "DisplayName eq '$($AlyaCompanyNameShortM365)SG-DEV-WIN365MDM11'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-WIN365MDM11 not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }
            if ($policy.name.StartsWith("AND") -and $policy.name -like "*Personal*")
            {
                $sGroup = Get-MgBetaGroup -Filter "displayName eq '$($AlyaCompanyNameShortM365)SG-DEV-ANDROIDMDMPERSONAL'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-ANDROIDMDMPERSONAL not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }
            if ($policy.name.StartsWith("AND") -and $policy.name -like "*Owned*")
            {
                $sGroup = Get-MgBetaGroup -Filter "displayName eq '$($AlyaCompanyNameShortM365)SG-DEV-ANDROIDMDMOWNED'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-ANDROIDMDMOWNED not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }
            if ($policy.name.StartsWith("IOS"))
            {
                $sGroup = Get-MgBetaGroup -Filter "displayName eq '$($AlyaCompanyNameShortM365)SG-DEV-IOSMDM'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-IOSMDM not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }
            if ($policy.name.StartsWith("MAC"))
            {
                $sGroup = Get-MgBetaGroup -Filter "displayName eq '$($AlyaCompanyNameShortM365)SG-DEV-MACMDM'"
                if (-Not $sGroup) {
                    Write-Warning "Group $($AlyaCompanyNameShortM365)SG-DEV-MACMDM not found. Can't create assignment."
                } else {
                    $tGroups += $sGroup
                }
            }

            if ($tGroups.Count -gt 0) {
                $uri = "/beta/deviceManagement/configurationPolicies/$($actPolicy.id)/assignments"
                $asses = (Get-MsGraphObject -Uri $uri).value
                $Targets = @()
                foreach($tGroup in $tGroups) {
                    $GroupAssignment = New-Object -TypeName PSObject -Property @{
                        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                        "groupId" = $tGroup.Id
                    }
                    $Target = New-Object -TypeName PSObject -Property @{
                        "target" = $GroupAssignment
                    }
                    $Targets += $Target
                }
                foreach($ass in $asses) {
                    if ($ass.target.groupId -notin $tGroups.Id)
                    {
                        $Target = New-Object -TypeName PSObject -Property @{
                            "target" = $ass.target
                        }
                        $Targets += $Target
                    }
                }
                $Assignment = New-Object -TypeName PSObject -Property @{
                    "assignments" = $Targets
                }
                $body = ConvertTo-Json -InputObject $Assignment -Depth 10
                $uri = "/beta/deviceManagement/configurationPolicies/$($actPolicy.id)/assign"
                Post-MsGraph -Uri $uri -Body $body
            }
        } else {
            Write-Host "Not found!" -ForegroundColor $CommandError
        }
    }
    catch {
        Write-Error $_.Exception -ErrorAction Continue
        $hadError = $true
    }

}

#Stopping Transscript
Stop-Transcript
