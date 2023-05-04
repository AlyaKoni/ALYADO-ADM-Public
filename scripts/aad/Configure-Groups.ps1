#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2023

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
    04.03.2020 Konrad Brunner       Initial Version
    25.10.2020 Konrad Brunner       Changed from service user to new ExchangeOnline module
    21.04.2023 Konrad Brunner       Switched to Graph and added guest access

#>

[CmdletBinding()]
Param(
    [string]$inputFile = $null #Defaults to "$AlyaData\aad\Gruppen.xlsx"
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
Install-ModuleIfNotInstalled "Microsoft.Graph.Groups"
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
$AllGroups = $AllGroups | Where-Object { $_.Activ -eq "yes" }
$AllGroups | Select-Object -Property Type, Name, Description | Format-Table -AutoSize

Write-Host "Checking groups" -ForegroundColor $CommandInfo
$Skus = Get-MgSubscribedSku
foreach ($group in $AllGroups)
{
    Write-Host "  Group '$($group.DisplayName)'"
    try {
        
        # Group
        $exGrp = Get-MgGroup -Filter "DisplayName eq '$($group.DisplayName)'"
        $groupTypes = @()
        $ruleProcessingState = "On"
        if ($group.Type -eq "M365Group" -or $group.Type -eq "O365Group")
        {
            $groupTypes = @("Unified")
            $ruleProcessingState = "Paused"
        }
        if ($exGrp)
        {
            Write-Host "   - Group already exists! Updating."
            if ([string]::IsNullOrEmpty($group.DanymicRule))
            {
                if ([string]::IsNullOrEmpty($group.Alias))
                {
                    $exGrp = Update-MgGroup -GroupId $exGrp.Id -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MailNickname $group.DisplayName -MailEnabled:$false -Visibility $group.Visibility
                }
                else
                {
                    $exGrp = Update-MgGroup -GroupId $exGrp.Id -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MailNickname $group.Alias -MailEnabled:$true -Visibility $group.Visibility
                }
            }
            else
            {
                $groupTypes += @("DynamicMembership")
                if ([string]::IsNullOrEmpty($group.Alias))
                {
                    $exGrp = Update-MgGroup -GroupId $exGrp.Id -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MembershipRule $group.DanymicRule -MembershipRuleProcessingState $ruleProcessingState -MailNickname $group.DisplayName -MailEnabled:$false -Visibility $group.Visibility
                }
                else
                {
                    $exGrp = Update-MgGroup -GroupId $exGrp.Id -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MembershipRule $group.DanymicRule -MembershipRuleProcessingState $ruleProcessingState -MailNickname $group.Alias -MailEnabled:$true -Visibility $group.Visibility
                }
            }
        }
        else
        {
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
                    $exGrp = New-MgGroup -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MailNickname $group.DisplayName -MailEnabled:$false -SecurityEnabled:$true -Visibility $group.Visibility -IsAssignableToRole:$isAssignableToRole
                }
                else
                {
                    # TODO this will not work as of documentation
                    $exGrp = New-MgGroup -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MailNickname $group.Alias -MailEnabled:$true -SecurityEnabled:$true -Visibility $group.Visibility -IsAssignableToRole:$isAssignableToRole
                }
            }
            else
            {
                $groupTypes += @("DynamicMembership")
                if ([string]::IsNullOrEmpty($group.Alias))
                {
                    $exGrp = New-MgGroup -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MembershipRule $group.DanymicRule -MembershipRuleProcessingState $ruleProcessingState -MailNickname $group.DisplayName -MailEnabled:$false -SecurityEnabled:$true -Visibility $group.Visibility -IsAssignableToRole:$isAssignableToRole
                }
                else
                {
                    # TODO this will not work as of documentation
                    $exGrp = New-MgGroup -Description $group.Description -DisplayName $group.DisplayName -GroupTypes $groupTypes -MembershipRule $group.DanymicRule -MembershipRuleProcessingState $ruleProcessingState -MailNickname $group.Alias -MailEnabled:$true -SecurityEnabled:$true -Visibility $group.Visibility -IsAssignableToRole:$isAssignableToRole
                }
            }
        }

        # License
        if (-Not [string]::IsNullOrEmpty($group.Licenses))
        {
            Write-Host "   - Configuring license." -ForegroundColor $CommandSuccess
            $exGrp = Get-MgGroup -Filter "DisplayName eq '$($group.DisplayName)'"
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
                    Set-MgGroupLicense -GroupId $exGrp.Id -AddLicenses $licenseOption -RemoveLicenses @()
                }
            }
        }

        # Guest access
        if ($null -ne $group.AllowGuests)
        {
            $exGrp = Get-MgGroup -Filter "DisplayName eq '$($group.DisplayName)'"
            $SettingTemplate = Get-MgDirectorySettingTemplate | Where-Object { $_.DisplayName -eq "Group.Unified.Guest" }
            $Setting = Get-MgGroupSetting -GroupId $exGrp.Id | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
            if (-Not $Setting)
            {
                Write-Warning "Setting not yet created. Creating one based on template."
                $Values = @()
                foreach($dval in $SettingTemplate.Values) {
                    $Values += @{Name = $dval.Name; Value = $dval.DefaultValue}
                }
                $Setting = New-MgGroupSetting -GroupId $exGrp.Id -DisplayName "Group.Unified.Guest" -TemplateId $SettingTemplate.Id -Values $Values
                $Setting = Get-MgGroupSetting -GroupId $exGrp.Id | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
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
            Update-MgGroupSetting -GroupId $exGrp.Id -DirectorySettingId $Setting.Id -Values $Setting.Values
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
                if ($null -ne $group.O365HiddenFromAddressListsEnabled) { $HiddenFromAddressListsEnabled = $group.O365HiddenFromAddressListsEnabled }
                if ($null -ne $group.O365CalendarMemberReadOnly) { $CalendarMemberReadOnly = $group.O365CalendarMemberReadOnly }
                if ($null -ne $group.O365RejectMessagesFromSendersOrMembers) { $RejectMessagesFromSendersOrMembers = $group.O365RejectMessagesFromSendersOrMembers }
                if ($null -ne $group.O365UnifiedGroupWelcomeMessageEnabled) { $UnifiedGroupWelcomeMessageEnabled = $group.O365UnifiedGroupWelcomeMessageEnabled }
                if ($null -ne $group.O365SubscriptionEnabled) { $SubscriptionEnabled = $group.O365SubscriptionEnabled }
                if ($null -ne $group.O365ModerationEnabled) { $ModerationEnabled = $group.O365ModerationEnabled }
                if ($null -ne $group.O365HiddenFromExchangeClientsEnabled) { $HiddenFromExchangeClientsEnabled = $group.O365HiddenFromExchangeClientsEnabled }
                Set-UnifiedGroup -Identity $group.DisplayName -Alias $group.Alias `
                        -HiddenFromAddressListsEnabled:$HiddenFromAddressListsEnabled `
                        -CalendarMemberReadOnly:$CalendarMemberReadOnly `
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
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 3) -ErrorAction Continue } catch {}
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
    $exGrp = Get-MgGroup -Filter "DisplayName eq '$($group.DisplayName)'"
    if ($exGrp)
    {
        if (-Not [string]::IsNullOrEmpty($group.DanymicRule))
        {
            Write-Host "  Group '$($group.DisplayName)'"
            Write-Host "   - Setting processing state to On"
            $exGrp = Update-MgGroup -GroupId $exGrp.Id -MembershipRuleProcessingState "On"
        }
    }

}

Write-Host "Checking disabled groups" -ForegroundColor $CommandInfo
foreach ($group in $GroupsToDisable)
{
    $exGrp = Get-MgGroup -Filter "DisplayName eq '$($group.DisplayName)'"
    if ($exGrp)
    {
        Write-Host "  Group '$($group.DisplayName)'"
        Write-Host "    disabling"
        $exGrp = Update-MgGroup -GroupId $exGrp.Id -MailEnabled:$false -SecurityEnabled:$false -MailEnabled:$false
    }
}

#Stopping Transscript
Stop-Transcript
