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
    04.03.2020 Konrad Brunner       Initial Version
    25.10.2020 Konrad Brunner       Changed from service user to new ExchangeOnline module
    21.04.2023 Konrad Brunner       Switched to Graph and added guest access
    04.08.2023 Konrad Brunner       Dynamic membership check

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
                    $groupTypes += @("DynamicMembership")
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
            $groupsToAssign = $group.ParentGroup.Split(",")
            foreach($groupToAssign in $groupsToAssign)
            {
                $aGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($groupToAssign)'"
                if ($aGrp)
                {
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
                        Write-Warning "Adding group '$($group.DisplayName)' as member to group '$groupToAssign'"
                        New-MgBetaGroupMember -GroupId $aGrp.Id -DirectoryObjectId $exGrp.Id
                    }
                }
                else
                {
                    Write-Warning "Not able to assign group '$($groupToAssign)' to '$($group.DisplayName)'"
                    Write-Warning "Reason: '$($group.DisplayName)' does not exist"
                    pause
                }
            }
        }

        # License
        if (-Not [string]::IsNullOrEmpty($group.Licenses))
        {
            Write-Host "   - Configuring license." -ForegroundColor $CommandSuccess
            $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$($group.DisplayName)'"
            foreach($license in $group.Licenses.Split(","))
            {
                $licPresent = $exGrp.AssignedLicenses | Where-Object { $_.SkuPartNumber -like "*$($license)" }
                $licSku = $Skus | Where-Object { $_.SkuPartNumber -eq $license }
                if (-Not $licSku)
                {
                    Write-Warning "Can't find license '$($license)' in your list of available licenses!"
                    continue
                }
                if (-Not $licPresent)
                {
                    Write-Host "       Adding license '$($license)'"
                    $licenseOption = @{SkuId = $licSku.SkuId <# TODO ; DisabledPlans = @()#>}
                    Set-MgBetaGroupLicense -GroupId $exGrp.Id -AddLicenses $licenseOption -RemoveLicenses @()
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
    LoginTo-EXO

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
finally
{
    DisconnectFrom-EXOandIPPS
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
