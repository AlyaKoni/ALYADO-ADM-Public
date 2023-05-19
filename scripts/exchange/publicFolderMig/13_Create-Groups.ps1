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
    24.10.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

. $PSScriptRoot\00_Configuration.ps1

Connect-AzureAD

Write-Host "Checking o365 groups"
foreach($migMap in $migMapping)
{
    $groupName = $migMap.m365Group
    Write-Host "Group '$($groupName)'"
    $exGrp = Get-AzureADMSGroup -SearchString $groupName
    if ($exGrp.Count -gt 1)
    {
        foreach($grp in $exGrp)
        {
            if ($groupName -eq $groupName)
            {
                $exGrp = $grp
                break
            }
        }
    }
    if ($exGrp)
    {
        Write-Host "   - Group already exists! Updating."
        $tmp = Set-AzureADMSGroup -Id $exGrp.Id -Description $secGroup.Description -DisplayName $groupName -MailNickname $groupName -Visibility $migMap.access
    }
    else
    {
        Write-Host "   - Group doesn't exists! Creating."
        $exGrp = New-AzureADMSGroup -DisplayName $groupName -Description $secGroup.Description -MailEnabled $true -MailNickname $groupName -SecurityEnabled $True -GroupTypes "Unified" -Visibility $migMap.access
    }
}

Write-Host "Checking o365 groups exchange settings"
Connect-ExchangeOnline -ShowProgress $true
foreach($migMap in $migMapping)
{
    $groupName = $migMap.m365Group
    Write-Host "Group '$($groupName)'"
    $Global:retryCount = 5
    do
    {
        $uGrp = Get-UnifiedGroup -Identity $groupName
        if ($uGrp)
        {
            if ($uGrp.PrimarySmtpAddress -ne $migMap.m365GroupAddress)
            {
                Write-Warning "Please change group email in 00_Configuration.ps1 to $($uGrp.PrimarySmtpAddress)"
            }
            Write-Host "   - Group found! Updating."
            $HiddenFromAddressListsEnabled = $false
            $CalendarMemberReadOnly = $false
            $RejectMessagesFromSendersOrMembers = $false
            $AlwaysSubscribeMembersToCalendarEvents = $false
            $UnifiedGroupWelcomeMessageEnabled = $false
            $AutoSubscribeNewMembers = $false
            $CalendarMemberReadOnly = $true
            $SubscriptionEnabled = $false
            $ModerationEnabled = $false
            $HiddenFromExchangeClientsEnabled = $false
            $Language = "de-CH"
            $RequireSenderAuthenticationEnabled = $true
            Set-UnifiedGroup -Identity $groupName -Alias $groupName `
                    -HiddenFromAddressListsEnabled:$HiddenFromAddressListsEnabled `
                    -CalendarMemberReadOnly:$CalendarMemberReadOnly `
                    -RejectMessagesFromSendersOrMembers:$RejectMessagesFromSendersOrMembers `
                    -AlwaysSubscribeMembersToCalendarEvents:$AlwaysSubscribeMembersToCalendarEvents `
                    -AutoSubscribeNewMembers:$AutoSubscribeNewMembers `
                    -UnifiedGroupWelcomeMessageEnabled:$UnifiedGroupWelcomeMessageEnabled `
                    -CalendarMemberReadOnly:$CalendarMemberReadOnly `
                    -SubscriptionEnabled:$SubscriptionEnabled `
                    -ModerationEnabled:$ModerationEnabled `
                    -HiddenFromExchangeClientsEnabled:$HiddenFromExchangeClientsEnabled `
                    -Language $Language `
                    -RequireSenderAuthenticationEnabled:$RequireSenderAuthenticationEnabled
            $Global:retryCount = -1
        }
        else
        {
            Write-Host "Group $($groupName) not found! Waiting 30 seconds and retrying"
            Start-Sleep -Seconds 30
            $Global:retryCount--
        }
    } while ($Global:retryCount -ge 0)
}

Disconnect-ExchangeOnline -Confirm:$false
