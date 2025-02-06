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
    [string]$definedPolicyFile = $null, #defaults to $($AlyaData)\intune\deviceConfigurationPolicies.json
    [string]$onlyPolicy = $null
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
    if (-Not [string]::IsNullOrEmpty($onlyPolicy) -and $definedPolicy.name -ne $onlyPolicy) { continue }
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
        $mpolicy.PSObject.properties.remove("settingCount")
        $null = Patch-MsGraph -Uri $uri -Body ($mpolicy | ConvertTo-Json -Depth 50)

        # Updating policy values
        Write-Warning "    Updating policy values not yet working"
        #TODO not working!!!
        # Write-Host "    Updating policy values"
        # $uri = "/beta/deviceManagement/configurationPolicies/$($extPolicy.Id)/settings"
        # $extPolicySettings = Get-MsGraphCollection -Uri $uri
        # $nextId = ($extPolicySettings.id | Measure-Object -Maximum).Maximum
        # foreach($extPolicySetting in $extPolicySettings)
        # {
        #     #$extPolicySetting = $extPolicySettings[0]
        #     $mpolicySetting = $mpolicySettings | Where-Object {`
        #         $_.settingInstance.'@odata.type' -eq $extPolicySetting.settingInstance.'@odata.type' -and `
        #         $_.settingInstance.settingDefinitionId -eq $extPolicySetting.settingInstance.settingDefinitionId }
        #     if ($mpolicySetting)
        #     {
        #         Write-Host "Found, updating"
        #         #$uri = "/beta/deviceManagement/configurationPolicies/$($extPolicy.Id)"
        #         #$null = Patch-MsGraph -Uri $uri -Body (@{Settings=@($mpolicySetting)} | ConvertTo-Json -Depth 50)

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
    if (-Not [string]::IsNullOrEmpty($onlyPolicy) -and $definedPolicy.name -ne $onlyPolicy) { continue }
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

# SIG # Begin signature block
# MIIvGwYJKoZIhvcNAQcCoIIvDDCCLwgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD3Vg3TRbwnTgjO
# kP57GAN4ECEBX5cu2IqkBpEL6OSwpaCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxghnmMIIZ4gIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJ17tyli
# bmD5d62Z+twHbaecln9JL6wOu8w+3at4BDt3MA0GCSqGSIb3DQEBAQUABIICAHZb
# i5HRvPD7AbyUXfddse8cLGIHhxeD7g+Seg/DQjjyTmyFSM5S170ftwdF4gGVRKu/
# Zf192rfWOzew1YyA41FfaawA3QTYP8omyEkjw+FHoUu8iIsgFt5yxUUtdbyRUQfp
# Jg1Mxi9vaGeHPiRQQMfNgH2XHEDZzj1VtL0hv3XsMk8L0/iI3mt2rFC/Dv16ihx3
# VKZuqQOt/vOTaCIzL7UNprPIc1Lli4uCH+5HDIpUtrv9WhouKMaDzar3UlXIcWN+
# Syof7b3Gt9jtNHVfzI3RYK4JdheMEa852QNg34N8EaHjTYsqq/Ti7pszahrilFXu
# b0KH9hMzrPtThEylv53+7X6bn0/NTTuvTiukCh48x6GJSFMIKVf5dOrWbf+3tHsC
# PtYrcLSaODHF32uanA9nhTFl2ffS2Tv7vljD1Gfxfv97Fnqo8/mRWZPnwp/Cq5pg
# ONlw9fFAeR/7bWhLGPpBSpxgkORSB4OBxYnpDlOgxvDbu+08Uu8q6GVGoHxjkipn
# ty/DTV6Nt8HSBsNyQn0mCY7CM8odrN7dE9zYacea4oCwnCZnGolumnT818nbulxE
# MZBfmWWBxvJdxTK7DNEUZfYawIakmbAWzjvinJdMVWjz7FNcXwqaar/KMDWN1DZn
# Yg4lUN7aCTi4flHVLuTT+MH0DeQY9b6kcsgI/gPwoYIWzTCCFskGCisGAQQBgjcD
# AwExgha5MIIWtQYJKoZIhvcNAQcCoIIWpjCCFqICAQMxDTALBglghkgBZQMEAgEw
# gegGCyqGSIb3DQEJEAEEoIHYBIHVMIHSAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCALIZDDSJxuvzSDEM1ksz4iik71iBkRYqc840rsmNG5kAIUKUL1
# vQqP/Jw2oAVBwJWl3QbQN6gYDzIwMjUwMjA2MTkyMTI2WjADAgEBoGGkXzBdMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwq
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2IC0gMjAyMzExoIISVDCC
# BmwwggRUoAMCAQICEAGb6t7ITWuP92w6ny4BJBYwDQYJKoZIhvcNAQELBQAwWzEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMT
# KEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjMx
# MTA3MTcxMzQwWhcNMzQxMjA5MTcxMzQwWjBdMQswCQYDVQQGEwJCRTEZMBcGA1UE
# CgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwqR2xvYmFsc2lnbiBUU0EgZm9y
# IENvZGVTaWduMSAtIFI2IC0gMjAyMzExMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A
# MIIBigKCAYEA6oQ3UGg8lYW1SFRxl/OEcsmdgNMI3Fm7v8tNkGlHieUs2PGoan5g
# N0lzm7iYsxTg74yTcCC19SvXZgV1P3qEUKlSD+DW52/UHDUu4C8pJKOOdyUn4Ljz
# fWR1DJpC5cad4tiHc4vvoI2XfhagxLJGz2DGzw+BUIDdT+nkRqI0pz4Yx2u0tvu+
# 2qlWfn+cXTY9YzQhS8jSoxMaPi9RaHX5f/xwhBFlMxKzRmUohKAzwJKd7bgfiWPQ
# HnssW7AE9L1yY86wMSEBAmpysiIs7+sqOxDV8Zr0JqIs/FMBBHkjaVHTXb5zhMub
# g4htINIgzoGraiJLeZBC5oJCrwPr1NDag3rDLUjxzUWRtxFB3RfvQPwSorLAWapU
# l05tw3rdhobUOzdHOOgDPDG/TDN7Q+zw0P9lpp+YPdLGulkibBBYEcUEzOiimLAd
# M9DzlR347XG0C0HVZHmivGAuw3rJ3nA3EhY+Ao9dOBGwBIlni6UtINu41vWc9Q+8
# iL8nLMP5IKLBAgMBAAGjggGoMIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFPlOq764+Fv/wscD9EHunPjWdH0/MFYG
# A1UdIARPME0wCAYGZ4EMAQQCMEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8E
# AjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3Au
# Z2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdo
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0
# ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6
# MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNo
# YTM4NGc0LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAlfRnz5OaQ5KDF3bWIFW8if/k
# X7LlFRq3lxFALgBBvsU/JKAbRwczBEy0tGL/xu7TDMI0oJRcN5jrRPhf+CcKAr4e
# 0SQdI8svHKsnerOpxS8M5OWQ8BUkHqMVGfjvg+hPu2ieI299PQ1xcGEyfEZu8o/R
# nOhDTfqD4f/E4D7+3lffBmvzagaBaKsMfCr3j0L/wHNp2xynFk8mGVhz7ZRe5Bqi
# EIIHMjvKnr/dOXXUvItUP35QlTSfkjkkUxiDUNRbL2a0e/5bKesexQX9oz37obDz
# K3kPsUusw6PZo9wsnCsjlvZ6KrutxVe2hLZjs2CYEezG1mZvIoMcilgD9I/snE7Q
# 3+7OYSHTtZVUSTshUT2hI4WSwlvyepSEmAqPJFYiigT6tJqJSDX4b+uBhhFTwJN7
# OrTUNMxi1jVhjqZQ+4h0HtcxNSEeEb+ro2RTjlTic2ak+2Zj4TfJxGv7KzOLEcN0
# kIGDyE+Gyt1Kl9t+kFAloWHshps2UgfLPmJV7DOm5bga+t0kLgz5MokxajWV/vbR
# /xeKriMJKyGuYu737jfnsMmzFe12mrf95/7haN5EwQp04ZXIV/sU6x5a35Z1xWUZ
# 9/TVjSGvY7br9OIXRp+31wduap0r/unScU7Svk9i00nWYF9A43aZIETYSlyzXRrZ
# 4qq/TVkAF55gZzpHEqAwggZZMIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqG
# SIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMw
# EQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYy
# MDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDwAuIwI/rgG+GadLOvdYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64H
# iifuV6PENe2zNMeswwzrgGZt0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//
# NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe
# 9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirU
# IceU/kKWO/ELsX9/RpgOhz16ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0Kvq
# WsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50
# xHAotIB7vSqbu4ThDqxvDbm19m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU
# 2EESwVX9bpHFu7FMCEue1EIGbxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE
# 6giunUlnEYuC5a1ahqdm/TMDAd6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3s
# qSbldwKsDlcMCdFhniaI/MiyTdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac
# 0zd0hNkdZqs0c48efXxeltY9GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCC
# ASUwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3Ay
# Lmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8v
# Y3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0g
# ADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBv
# c2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZM
# v9sbB3DG+wsJrQA6YDMfOcYWaxlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7A
# I4zGhf5LFST5GETsH8KkrNCyz+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG
# 0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0
# +X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3Wd
# rG9KyC5qucqIwxIwTrIIc59eodaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXa
# jR63Wy+ILj198fKRMAWcznt8oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpI
# iScseeI85Zse46qEgok+wEr1If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ
# 7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx
# 773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZq
# HcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV
# 5yBZtnjGpGqqIpswggWDMIIDa6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG
# 9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEG
# A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAw
# MDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9v
# dCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxT
# aWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns8
# 9w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0b
# WsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZ
# gQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ
# 3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2M
# sonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI5
# 5KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPF
# OJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4Py
# XhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYF
# AJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWV
# ZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlw
# g3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4IC
# AQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/A
# VJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6x
# CCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc
# 053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6q
# TFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvd
# OxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJd
# w+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ
# 4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4Z
# sRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3
# nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZ
# xRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8w
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb
# 6t7ITWuP92w6ny4BJBYwCwYJYIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZI
# hvcNAQELBQAwLwYJKoZIhvcNAQkEMSIEIEcOtTChE9iZ994JxgLHXnjkSJGVsTda
# NhLnDlTnXXNOMIGwBgsqhkiG9w0BCRACLzGBoDCBnTCBmjCBlwQgOoh6lRteuSpe
# 4U9su3aCN6VF0BBb8EURveJfgqkW0egwczBfpF0wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwDQYJ
# KoZIhvcNAQELBQAEggGABEjVGSNOQX4vSu7RrY5cEcoUe4zJGPqtb16cskQx1Huv
# +RvEDnwrTdIPtGm0ii+zNtqHyMqNMosEMniycCw8uAkbXQoKSHdudUADxIWSnPlz
# HSTQn6PW6nj2EUFiW/ZZz+W1qH1wufKu1sHG34UkC+kaI4sQOCNmp7cTfOZK36El
# DesZyirqPDsBjNDjlvk8g9cHrVKyTtXV1yRPBlbjrn6OIiVf7YU0A6CUPhTkOwYn
# W1SFqSn4D8D4v6YhO/WGvfym1kR+kuvbcCUcMU3eqyB/ovHLJeiGXYe6fZcXdr1N
# m4yF6aKPMX2EMhw4BukZN3v4UngNrtkGFKoIoMo6hF5Fz6GJyJzMLWGrE8+xkjyC
# rDx+JS7r8s1Ka3rV1NIzh6zrLkA9P6Stl760fY/JXQEYRp02LRTbGgnronK8k8YW
# e3RnnpKX+cGXbNNeeUfM0dB9wM5aczDpANOBnvCsaQmJcmEh/OFrAfIdzDUfLBPH
# t81kRogyFpftWuIblCIN
# SIG # End signature block
