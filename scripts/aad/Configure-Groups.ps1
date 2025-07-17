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
    04.03.2020 Konrad Brunner       Initial Version
    25.10.2020 Konrad Brunner       Changed from service user to new ExchangeOnline module
    21.04.2023 Konrad Brunner       Switched to Graph and added guest access
    04.08.2023 Konrad Brunner       Dynamic membership check
    11.07.2025 Konrad Brunner       Group license handling

#>

[CmdletBinding()]
Param(
    [string]$inputFile = $null, #Defaults to "$AlyaData\aad\Gruppen.xlsx"
    [bool]$dynamicMembershipDisabled = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Configure-Groups-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $inputFile)
{
    $inputFile = "$AlyaData\aad\Gruppen.xlsx"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"
Install-ModuleIfNotInstalled "ImportExcel"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All","RoleManagement.ReadWrite.Directory"

# =============================================================
# AAD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Configure-Groups | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Reading input file
Write-Host "Reading input file from '$inputFile" -ForegroundColor $CommandInfo
if (-Not (Test-Path $inputFile))
{
    throw "Input file '$inputFile' not found!"
}
$AllGroups = Import-Excel $inputFile -WorksheetName "Gruppen" -ErrorAction Stop

Write-Host "Configured groups" -ForegroundColor $CommandInfo
$AllGroups | Select-Object -Property Type, Name, Description | Format-Table -AutoSize
$GroupsToDisable = $AllGroups | Where-Object { $_.Activ -ne "yes" }

Write-Host "Groups to create" -ForegroundColor $CommandInfo
$AllGroups = $AllGroups | Where-Object { $_.Activ.ToLower() -eq "yes" }
$AllGroups | Select-Object -Property Type, Name, Description | Format-Table -AutoSize

Write-Host "Checking groups" -ForegroundColor $CommandInfo
$Skus = Get-MgBetaSubscribedSku
foreach ($group in $AllGroups)
{
    Write-Host "  Group '$($group.DisplayName)'"
    try {
        
        # Group
        $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($group.DisplayName)'"
        $groupTypes = @()
        $ruleProcessingState = "On"
        if ($group.Type -eq "M365Group" -or $group.Type -eq "O365Group")
        {
            $groupTypes = @("Unified")
            $ruleProcessingState = "Paused"
        }
        if ($group.Type -eq "ADGroup")
        {
            $groupTypes = @("AD")
        }
        if ($exGrp)
        {
            if ($group.Type -eq "ADGroup") {
                Write-Host "   - AD group. Skipping update."
                
            } else {
                Write-Host "   - Group already exists! Updating."
                if ([string]::IsNullOrEmpty($group.DanymicRule))
                {
                    if ([string]::IsNullOrEmpty($group.Alias))
                    {
                        $exGrp = Update-MgBetaGroup -GroupId $exGrp.Id -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MailNickname $group.DisplayName -MailEnabled:$false -Visibility $group.Visibility
                    }
                    else
                    {
                        $exGrp = Update-MgBetaGroup -GroupId $exGrp.Id -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MailNickname $group.Alias -MailEnabled:$true -Visibility $group.Visibility
                    }
                }
                else
                {
                    if ($dynamicMembershipDisabled) { throw "Dynamic membership is disabled. Please update sheet!" }
                    $groupTypes += "DynamicMembership"
                    if ([string]::IsNullOrEmpty($group.Alias))
                    {
                        $exGrp = Update-MgBetaGroup -GroupId $exGrp.Id -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MembershipRule $group.DanymicRule -MembershipRuleProcessingState $ruleProcessingState -MailNickname $group.DisplayName -MailEnabled:$false -Visibility $group.Visibility
                    }
                    else
                    {
                        $exGrp = Update-MgBetaGroup -GroupId $exGrp.Id -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MembershipRule $group.DanymicRule -MembershipRuleProcessingState $ruleProcessingState -MailNickname $group.Alias -MailEnabled:$true -Visibility $group.Visibility
                    }
                }
            }
        }
        else
        {
            if ($group.Type -eq "ADGroup") {
                Write-Warning "   - AD group is missing. Please create this group in AD."
            } else {
                Write-Host "   - Group doesn't exists! Creating." -ForegroundColor $CommandSuccess
                $isAssignableToRole = $false
                if ($null -ne $group.AllowAzureAdRoles)
                {
                    $isAssignableToRole = $group.AllowAzureAdRoles
                }
                if ([string]::IsNullOrEmpty($group.DanymicRule))
                {
                    if ([string]::IsNullOrEmpty($group.Alias))
                    {
                        $exGrp = New-MgBetaGroup -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MailNickname $group.DisplayName -MailEnabled:$false -SecurityEnabled:$true -Visibility $group.Visibility -IsAssignableToRole:$isAssignableToRole
                    }
                    else
                    {
                        # TODO this will not work as of documentation
                        $exGrp = New-MgBetaGroup -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MailNickname $group.Alias -MailEnabled:$true -SecurityEnabled:$true -Visibility $group.Visibility -IsAssignableToRole:$isAssignableToRole
                    }
                }
                else
                {
                    if ($dynamicMembershipDisabled) { throw "Dynamic membership is disabled. Please update sheet!" }
                    $groupTypes += @("DynamicMembership")
                    if ([string]::IsNullOrEmpty($group.Alias))
                    {
                        $exGrp = New-MgBetaGroup -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MembershipRule $group.DanymicRule -MembershipRuleProcessingState $ruleProcessingState -MailNickname $group.DisplayName -MailEnabled:$false -SecurityEnabled:$true -Visibility $group.Visibility -IsAssignableToRole:$isAssignableToRole
                    }
                    else
                    {
                        # TODO this will not work as of documentation
                        $exGrp = New-MgBetaGroup -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MembershipRule $group.DanymicRule -MembershipRuleProcessingState $ruleProcessingState -MailNickname $group.Alias -MailEnabled:$true -SecurityEnabled:$true -Visibility $group.Visibility -IsAssignableToRole:$isAssignableToRole
                    }
                }
            }
        }

        # Memberships
        $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($group.DisplayName)'"
        if (-Not [string]::IsNullOrEmpty($group.ParentGroup))
        {
            $groupsToAssignTo = $group.ParentGroup.Split(",")
            foreach($groupToAssignTo in $groupsToAssignTo)
            {
                $aGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($groupToAssignTo)'"
                if ($aGrp)
                {
                    Write-Host "   - Assigning to '$($groupToAssignTo)'"
                    $members = Get-MgBetaGroupMember -GroupId $aGrp.Id -All
                    $fnd = $false
                    foreach ($member in $members)
                    {
                        if ($member.Id -eq $exGrp.Id)
                        {
                            $fnd = $true
                            break
                        }
                    }
                    if (-Not $fnd)
                    {
                        Write-Warning "Adding group '$($group.DisplayName)' as member to group '$groupToAssignTo'"
                        New-MgBetaGroupMember -GroupId $aGrp.Id -DirectoryObjectId $exGrp.Id
                    }
                }
                else
                {
                    Write-Warning "Not able to assign group '$($group.DisplayName)' to '$($groupToAssignTo)'"
                    Write-Warning "Reason: '$($groupToAssignTo)' does not exist"
                    pause
                }
            }
        }

        if (-Not $dynamicMembershipDisabled)
        {

            # License
            if (-Not [string]::IsNullOrEmpty($group.Licenses))
            {
                Write-Host "   - Configuring license."
                $licGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($group.DisplayName)'" -Property "Id","AssignedLicenses"
                foreach($license in $group.Licenses.Split(","))
                {
                    $plans = $null
                    if ($license.Contains("("))
                    {
                        $plans = $license.SubString($license.IndexOf("(")).Replace("(","").Replace(")","").Split(";")
                        $license = $license.SubString(0,$license.IndexOf("("))
                    }
                    # License
                    $licSku = $Skus | Where-Object { $_.SkuPartNumber -eq $license }
                    if (-Not $licSku)
                    {
                        Write-Warning "Can't find license '$($license)' in your list of available licenses!"
                        continue
                    }
                    $licPresent = $licGrp.AssignedLicenses | Where-Object { $_.SkuId -eq $licSku.SkuId }
                    $disabledPlans = @()
                    if ($null -ne $plans)
                    {
                        foreach($plan in $licSku.ServicePlans)
                        {
                            if ($plan.ServicePlanName -notin $plans)
                            {
                                $disabledPlans += $plan.ServicePlanId
                            }
                        }
                    }
                    if (-Not $licPresent)
                    {
                        Write-Warning "Adding license '$($license)'"
                        $licenseOption = @{SkuId = $licSku.SkuId; DisabledPlans = $disabledPlans}
                        Set-MgBetaGroupLicense -GroupId $licGrp.Id -AddLicenses $licenseOption -RemoveLicenses @()
                    }
                    else
                    {
                        Write-Warning "Updating license '$($license)'"
                        $licenseOption = @{SkuId = $licSku.SkuId; DisabledPlans = $disabledPlans}
                        Set-MgBetaGroupLicense -GroupId $licGrp.Id -AddLicenses $licenseOption -RemoveLicenses @()
                    }
                }
            }

        }

        # Guest access
        if ($null -ne $group.AllowGuests)
        {
            $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($group.DisplayName)'"
            $SettingTemplate = Get-MgBetaDirectorySettingTemplate | Where-Object { $_.DisplayName -eq "Group.Unified.Guest" }
            $Setting = Get-MgBetaGroupSetting -GroupId $exGrp.Id | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
            if (-Not $Setting)
            {
                Write-Warning "Setting not yet created. Creating one based on template."
                $Values = @()
                foreach($dval in $SettingTemplate.Values) {
                    $Values += @{Name = $dval.Name; Value = $dval.DefaultValue}
                }
                $Setting = New-MgBetaGroupSetting -GroupId $exGrp.Id -DisplayName "Group.Unified.Guest" -TemplateId $SettingTemplate.Id -Values $Values
                $Setting = Get-MgBetaGroupSetting -GroupId $exGrp.Id | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
            }
            if ($group.AllowGuests) {
                $Value = $Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }
                if ($Value.Value -eq $true) {
                    Write-Host "Setting 'AllowToAddGuests' was already set to '$true'"
                } 
                else {
                    Write-Warning "Setting 'AllowToAddGuests' was set to '$($Value.Value)' updating to '$true'"
                    ($Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }).Value = $true
                }
            }
            else {
                $Value = $Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }
                if ($Value.Value -eq $false) {
                    Write-Host "Setting 'AllowToAddGuests' was already set to '$false'"
                } 
                else {
                    Write-Warning "Setting 'AllowToAddGuests' was set to '$($Value.Value)' updating to '$false'"
                    ($Setting.Values | Where-Object { $_.Name -eq "AllowToAddGuests" }).Value = $false
                }
            }
            Update-MgBetaGroupSetting -GroupId $exGrp.Id -DirectorySettingId $Setting.Id -Values $Setting.Values
        }


    }
    catch {
        Write-Error $_.Exception -ErrorAction Continue
    }
}

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Configure-Groups | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Configuring M365 group settings in exchange online" -ForegroundColor $CommandInfo
try
{
    try {
        LoginTo-EXO
    }
    catch {
        Write-Error $_.Exception -ErrorAction Continue
        LogoutFrom-EXOandIPPS
        LoginTo-EXO
    }

    Write-Host "Checking M365 groups" -ForegroundColor $CommandInfo
    foreach ($group in $AllGroups)
    {
        if ($group.Type -ne "M365Group" -and $group.Type -ne "O365Group") { continue }
        Write-Host "  Group '$($group.DisplayName)'"
        $Global:retryCount = 5
        do
        {
            $uGrp = Get-UnifiedGroup -Identity $group.DisplayName -ErrorAction SilentlyContinue
            if ($uGrp)
            {
                Write-Host "   - Group found! Updating."
                $HiddenFromAddressListsEnabled = $true
                $CalendarMemberReadOnly = $true
                $RejectMessagesFromSendersOrMembers = $true
                $UnifiedGroupWelcomeMessageEnabled = $false
                $SubscriptionEnabled = $false
                $ModerationEnabled = $false
                $HiddenFromExchangeClientsEnabled = $true
                if ($null -ne $group.O365GrpHiddenFromAddressListsEnabled) { $HiddenFromAddressListsEnabled = $group.O365GrpHiddenFromAddressListsEnabled }
                if ($null -ne $group.O365GrpCalendarMemberReadOnly) { $CalendarMemberReadOnly = $group.O365GrpCalendarMemberReadOnly }
                if ($null -ne $group.O365GrpRejectMessagesFromSendersOrMembers) { $RejectMessagesFromSendersOrMembers = $group.O365GrpRejectMessagesFromSendersOrMembers }
                if ($null -ne $group.O365GrpUnifiedGroupWelcomeMessageEnabled) { $UnifiedGroupWelcomeMessageEnabled = $group.O365GrpUnifiedGroupWelcomeMessageEnabled }
                if ($null -ne $group.O365GrpSubscriptionEnabled) { $SubscriptionEnabled = $group.O365GrpSubscriptionEnabled }
                if ($null -ne $group.O365GrpModerationEnabled) { $ModerationEnabled = $group.O365GrpModerationEnabled }
                if ($null -ne $group.O365GrpHiddenFromExchangeClientsEnabled) { $HiddenFromExchangeClientsEnabled = $group.O365GrpHiddenFromExchangeClientsEnabled }

                Set-UnifiedGroup -Identity $uGrp.Id -Alias $group.Alias `
                        -HiddenFromAddressListsEnabled:$HiddenFromAddressListsEnabled `
                        -RejectMessagesFromSendersOrMembers:$RejectMessagesFromSendersOrMembers `
                        -UnifiedGroupWelcomeMessageEnabled:$UnifiedGroupWelcomeMessageEnabled `
                        -SubscriptionEnabled:$SubscriptionEnabled `
                        -ModerationEnabled:$ModerationEnabled `
                        -HiddenFromExchangeClientsEnabled:$HiddenFromExchangeClientsEnabled
                $Global:retryCount = -1
            }
            else
            {
                Write-Host "Group $($group.DisplayName) not found! Waiting 30 seconds and retrying"
                Start-Sleep -Seconds 30
                $Global:retryCount--
            }
        } while ($Global:retryCount -ge 0)
    }
}
catch
{
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
    Write-Error ($_.Exception) -ErrorAction Continue
    Write-Error "Please delete created groups by hand. Clean them from recycle bin. Start over again after fixing the issue." -ErrorAction Continue
}

Write-Host "Setting ProcessingState" -ForegroundColor $CommandInfo
foreach ($group in $AllGroups)
{
    if ($group.Type -ne "M365Group" -and $group.Type -ne "O365Group") { continue }
    $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($group.DisplayName)'"
    if ($exGrp)
    {
        if (-Not [string]::IsNullOrEmpty($group.DanymicRule))
        {
            Write-Host "  Group '$($group.DisplayName)'"
            Write-Host "   - Setting processing state to On"
            $exGrp = Update-MgBetaGroup -GroupId $exGrp.Id -MembershipRuleProcessingState "On"
        }
    }

}

Write-Host "Checking disabled groups" -ForegroundColor $CommandInfo
foreach ($group in $GroupsToDisable)
{
    if ($group.Type -eq "ADGroup") { continue }
    $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($group.DisplayName)'"
    if ($exGrp)
    {
        Write-Host "  Group '$($group.DisplayName)'"
        Write-Host "    disabling"
        $exGrp = Update-MgBetaGroup -GroupId $exGrp.Id -MailEnabled:$false -SecurityEnabled:$false
    }
}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIvCQYJKoZIhvcNAQcCoIIu+jCCLvYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAvXR9BxrUU0tyw
# mtcjSwYtB4EsaRfmIVprOTgWl1/tHaCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDk5R5vs
# Z4c8hrR1bwQzWE60GLwkzR1nSUrL/tNcs69VMA0GCSqGSIb3DQEBAQUABIICADHO
# sM6JJBpu+sCMFwievY1cn3gY3xLnqcqiXwxHefvK1nXyyPramsX/k5I5nQbABB1/
# fuhVyOAy6ITNO915T3iAg8QnjvWRF8VJsBEWUgHVFYC6TLorhKQLVJEOvZIJH1QG
# hPKMSGWpqNTsoim5CmksmdQDKXAEsoG+dSpbGgUYl2X3uuI9ji6mYzDfBF6OCRS3
# KkqXsVKNYqdRAgvbDf3QPkY/I/1m5GhMzQGL9TXD+WN7dKA+9T/Ox5Enw8JOeZY4
# SJAzUvWV8p42dnUxTk8k6oMeBrW3RdstvYD0hjk7oLdmswnASMVq9REfVEM4Tjk4
# hgKJrHi8OTjBjzsu9F+yjOTL8RiIVcwqIGg5uGoiH81DoLi6J1aFCFMyc1OP8Qhz
# S94eCU8bNAs/FQ1Kk9ykqopyd2rHDubgaVn1Ve3hcUxVxkIe2wWED8hJuP4CGYaj
# dL/VjffR7bMq7Eo+l7NHDMr8q21U+lejmNsBjGagJuu7sKmB9pSwGt5kXxTHu2oq
# b2snqjRevvwk/d7VcN0RCaqPSSUEI3RGV6Zb8JZHsNhfgEK7XZXd7BL8r5Q1NoDY
# tzpi1xHefPqhrmv1Ld+SSsCxAFTg3I46pWw56P5vxGxJ8dX8ovJ3mTfzsqCfoVPD
# VKe6TLrj9Fx/N912nxXpfsacnGZvZfgav/T4mfRXoYIWuzCCFrcGCisGAQQBgjcD
# AwExghanMIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEw
# gd8GCyqGSIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCDcpaMQP4naWPDRTX6L08XE9DHX/LtsG1UjVy2IXay0eAIUJpkF
# 5A/TYa6mDg2kInB5ifNSFQ0YDzIwMjUwNzExMjEzMTA0WjADAgEBoFikVjBUMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwh
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMC
# AQICEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNp
# Z24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5
# WhcNMzQxMjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFs
# U2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWdu
# MSAtIFI2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4
# PuCF6+aqCj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb
# 5gk0Xydy3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJSc
# RV1W6/6efi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy
# 5RJY+o1NWhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY
# 0Lie04DuKbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2Z
# wbI6yiFHaS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYh
# KUlrMH9+2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5s
# WtX1qvCzk6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGo
# MIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYD
# VR0OBBYEFIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQC
# MEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSB
# gzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2Ev
# Z3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2Jh
# bHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaA
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9j
# cmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG
# 9w0BAQwFAAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26
# IFq7fQMIrN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76Tkv
# L+v2f4mHolGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftP
# ttS+G/MhNUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIl
# S3Ki74CU15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt
# 8DT4RQj9LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5
# lgJkgXEc1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD
# 9hQchjiGkyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71
# yzGKWnbAWQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGL
# ZtJFJzGJD7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVA
# GXCqHsh62QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZ
# MIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAw
# MDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOv
# dYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt
# 0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHP
# vIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFU
# UweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16
# ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS
# 2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm1
# 9m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIG
# bxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMD
# Ad6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/Miy
# Tdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9
# GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGG
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDD
# vWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEB
# BDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jv
# b3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29t
# L3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0B
# AQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYW
# axlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCy
# z+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQ
# cXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0
# Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59e
# odaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8
# oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1
# If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbcl
# IA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2M
# tnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB
# +SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIID
# a6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQL
# ExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjET
# MBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAw
# MDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQK
# EwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4
# QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTe
# c5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWy
# ZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7tt
# U+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrK
# otudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKF
# t3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTfl
# puwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2Fm
# CWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5
# paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4O
# hxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwo
# TK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki
# 5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnm
# XNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJE
# lrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMp
# mY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6
# JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG
# 7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/
# gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324G
# abbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5
# MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO7
# 7oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4st
# Q1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjx
# guhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJ
# YIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZI
# hvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcN
# AQkEMSIEIDDGHz2xKlxVkSgqVnrk9cv6UY7W/EKw/QusaVTtrNWIMIGwBgsqhkiG
# 9w0BCRACLzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1or
# d69gXP0wczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hB
# Mzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAgBjF
# G6QqLNcs8cmarvA9zCWeT+bo/n8PW4HfBNTcg5FMKRgVXygezJ7B5TN6CQ2TrJGk
# ceL2wtezXWNclMeFb23czzpB0R96HeyjIaNPFhZqVMb45iIiwDkKGDsI1MiKCmGr
# qep4UgUWOWe3lOUTOHDxvGBuzA1kxD1udTFklJKi3d2GFwb7F9teDYVzaGZiLaxK
# 3PgtUSCJ6cCCleHsGW84Mah56cvi7twxtLYj12nbnZsCUfkAfob9ln/2pz8I6pzo
# auG6Ce+uppqzaJHvah7amjE7YPSa4zlZNaUwbhSltAWXWAvgQfQCXlMyJvGpXLXD
# CMUnt96D6q4vlJWWEIZ/c84kR7uo6D67OqBwj8fnPCdwPVHl+5qeNNJc2v8ovgxh
# KJ+JXPW+16bRQ+dI81ukTlgAplhMJQ8syfP8PYwi3AHB9g242RD7UDpncUEdenGM
# e2YWafUYGcHYRJ37ks1tY5yS6/HVtkLPbtnunyCM5V/NgBIZy3gwlZ0r9C/v
# SIG # End signature block
