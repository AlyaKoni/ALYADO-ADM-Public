#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    03.04.2022 Konrad Brunner       Initial Version
    16.08.2022 Konrad Brunner       External redirect and options
    06.02.2026 Konrad Brunner       Added powershell documentation
    05.08.2026 Konrad Brunner       Auto license assigment for resource accounts
    20.09.2026 Konrad Brunner       Module isolation: EXO, Graph and Teams run in separate isolated runspaces
    20.09.2026 Konrad Brunner       Switched to IsolatedProcess: assembly conflicts (Microsoft.Identity.Client/Azure.Identity) verified between EXO, Graph and Teams in one process
    20.09.2026 Konrad Brunner       callGroupUserUpns typed string[] and normalized for pwsh -File mode (wrapper/pipeline) compatibility

#>

<#
.SYNOPSIS
Creates and configures an auto responder in Microsoft Teams, including associated application instances, call queues, distribution groups, and call handling rules.

.DESCRIPTION
The Create-AutoResponder.ps1 script automates the setup of a Teams Auto Attendant and related components in a Microsoft 365 environment. It creates or updates application instances, distribution groups, and call queues, assigns phone numbers and licenses, configures call routing, shared voicemail, menus, and audio prompts, and defines call handling rules for working and after-hours. The script supports optional redirection to external numbers and flexible prompt and schedule customizations.

.PARAMETER attendantName
Specifies the display name for the auto attendant, queue, and group.

.PARAMETER attendantUpn
Defines the User Principal Name for the auto attendant resource account.

.PARAMETER attendantNumber
Specifies the phone number to assign to the auto attendant resource account.

.PARAMETER callGroupUserUpns
Provides an array of user UPNs to be members of the associated distribution group.

.PARAMETER redirectToExternalNumber
Indicates an external phone number to which calls are redirected during busy or timeout conditions.

.PARAMETER redirectToExternalNumberByMenu
Defines an external number to which calls can be redirected via menu options after hours.

.PARAMETER setCallerIdToAutoResponder
If set to true, modifies the global calling line identity to display the auto responder’s name.

.PARAMETER noCallHandlingAtAll
If set to true, disables all call routing and handling logic.

.PARAMETER officeHourMorningStart
Specifies the morning start time for standard office hours.

.PARAMETER officeHourMorningEnd
Specifies the morning end time for standard office hours.

.PARAMETER officeHourAfternoonStart
Specifies the afternoon start time for standard office hours.

.PARAMETER officeHourAfternoonEnd
Specifies the afternoon end time for standard office hours.

.PARAMETER redirectToNextAgentAfterSeconds
Defines the number of seconds before redirecting a call to the next available agent.

.PARAMETER keepCallInQueueForSeconds
Determines how long a call can remain in the queue before timing out.

.PARAMETER presenceBasedRouting
If true, uses agent presence status for routing calls.

.PARAMETER allLinesBusyTextToSpeechPrompt
Sets the text-to-speech message used when all lines are busy.

.PARAMETER pleaseWaitTextToSpeechPrompt
Defines the welcome text prompt played to callers before answering.

.PARAMETER outOfOfficeTimeTextToSpeechPrompt
Provides the message played during after-hours periods.

.PARAMETER afterHoursMenuTextToSpeechPrompt
Defines the text-to-speech message prompting users during after-hours menu navigation.

.PARAMETER allLinesBusyTextToSpeechPromptAudioFile
Path to an audio file used instead of the text prompt when all lines are busy.

.PARAMETER pleaseWaitTextToSpeechPromptAudioFile
Path to an audio file used for the welcome message prompt.

.PARAMETER outOfOfficeTimeTextToSpeechPromptAudioFile
Path to an audio file used for the out-of-office greeting.

.PARAMETER afterHoursMenuTextToSpeechPromptAudioFile
Path to an audio file used for the after-hours menu prompt.

.PARAMETER musicOnHoldAudioFile
Specifies a custom audio file for music on hold.

.PARAMETER allowSharedVoicemail
Enables the use of shared voicemail for overflow and timeout actions.

.PARAMETER languageId
Specifies the language code (e.g., "de-DE") used for prompts and voice.

.PARAMETER timeZoneId
Specifies the Microsoft timezone identifier for scheduling.

.PARAMETER voiceId
Sets the voice gender for text-to-speech prompts.

.PARAMETER allowOptOut
If true, allows agents to opt out of call queues.

.PARAMETER redirectAlways
If true, all calls are always redirected rather than processed by a menu.

.PARAMETER phoneNumberType
Specifies the phone number assignment type, e.g., "DirectRouting".

.INPUTS
None. All configuration parameters are provided through the Param() block.

.OUTPUTS
Creates or updates Teams Auto Attendant, Call Queue, and related configuration objects.

.EXAMPLE
PS> .\Create-AutoResponder.ps1 -attendantName "Alya Zentrale" -attendantUpn "Alya.Zentrale@alyaconsulting.ch" -attendantNumber "+41625620462" -callGroupUserUpns @("konrad.brunner@alyaconsulting.ch")

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [ValidateNotNullOrEmpty()]
    $attendantName = "Alya Zentrale",
    [ValidateNotNullOrEmpty()]
    $attendantUpn = "Alya.Zentrale@alyaconsulting.ch",
    [ValidateNotNullOrEmpty()]
    $attendantNumber = "+41625620462",
    [ValidateNotNullOrEmpty()]
    [string[]]$callGroupUserUpns = @("konrad.brunner@alyaconsulting.ch"),
    $redirectToExternalNumber = $null,
    $redirectToExternalNumberByMenu = $null,
    $setCallerIdToAutoResponder = $false,
    $noCallHandlingAtAll = $false,
    [ValidateNotNullOrEmpty()]
    $officeHourMorningStart = "08:00",
    [ValidateNotNullOrEmpty()]
    $officeHourMorningEnd = "12:00",
    [ValidateNotNullOrEmpty()]
    $officeHourAfternoonStart = "13:00",
    [ValidateNotNullOrEmpty()]
    $officeHourAfternoonEnd = "17:00",
    $redirectToNextAgentAfterSeconds = 60,
    $keepCallInQueueForSeconds = 120,
    $presenceBasedRouting = $true,
    $allLinesBusyTextToSpeechPrompt = "Leider sind aktuell alle unsere Leitung besetzt. Bitte hinterlassen Sie uns eine Nachricht oder versuchen Sie es später noch einmal.", #Only used if $redirectToExternalNumber $null
    $pleaseWaitTextToSpeechPrompt = "Willkommen bei Alya Consulting! Der nächste freie Mitarbeiter kümmert sich gleich um Ihr Anliegen. Bitte haben Sie einen Moment Geduld.",
    $outOfOfficeTimeTextToSpeechPrompt = "Willkommen bei Alya Consulting! Leider erreichen Sie uns ausserhalb unserer Öffnungszeiten. Bitte hinterlassen Sie uns eine Nachricht oder rufen Sie uns von Montag bis Freitag von 8 bis 12 Uhr oder von 13 bis 17 Uhr an.",
    $afterHoursMenuTextToSpeechPrompt = "Drücken Sie 1 um uns eine Nachricht zu hinterlassen.",
    $allLinesBusyTextToSpeechPromptAudioFile = $null,
    $pleaseWaitTextToSpeechPromptAudioFile = $null,
    $outOfOfficeTimeTextToSpeechPromptAudioFile = $null,
    $afterHoursMenuTextToSpeechPromptAudioFile = $null,
    $musicOnHoldAudioFile = $null,
    $allowSharedVoicemail = $true,
    $languageId = "de-DE",
    $timeZoneId = "W. Europe Standard Time",
    [ValidateSet("Female","Male")]
    $voiceId = "Female",
    $allowOptOut = $true,
    $redirectAlways = $false,
    $phoneNumberType = "DirectRouting"
)
# Normalize callGroupUserUpns: in pwsh -File mode (wrapper/DevOps pipeline) a comma
# separated single token arrives as ONE string element instead of an array, and
# multiple space separated tokens would bind positionally to the wrong parameters.
$callGroupUserUpns = @($callGroupUserUpns | ForEach-Object { $_ -split "," } | ForEach-Object { $_.Trim() } | Where-Object { -Not [string]::IsNullOrEmpty($_) })
if ($attendantNumber.StartsWith("tel:"))
{
    Write-Error "The attendantNumber must not start with 'tel:'" -ErrorAction Continue
    exit
}
if ($redirectToExternalNumber -ne $null -and $redirectToExternalNumber.StartsWith("tel:"))
{
    Write-Error "The redirectToExternalNumber must not start with 'tel:'" -ErrorAction Continue
    exit
}
if ($redirectToExternalNumberByMenu -ne $null -and $redirectToExternalNumberByMenu.StartsWith("tel:"))
{
    Write-Error "The redirectToExternalNumberByMenu must not start with 'tel:'" -ErrorAction Continue
    exit
}
if (($redirectToExternalNumber -ne $null -or $redirectToExternalNumber -ne $null) -and $allowSharedVoicemail)
{
    Write-Warning "If you redirectToExternalNumber the allowSharedVoicemail will be ignored!" -ErrorAction Continue
}
if ($redirectToNextAgentAfterSeconds -lt 15 -or $redirectToNextAgentAfterSeconds -gt 180)
{
    Write-Error "redirectToNextAgentAfterSeconds needs to be between 15 and 180" -ErrorAction Continue
    exit
}
if ($keepCallInQueueForSeconds -lt 0 -or $keepCallInQueueForSeconds -gt 2700)
{
    Write-Error "keepCallInQueueForSeconds needs to be between 0 and 2700" -ErrorAction Continue
    exit
}

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
$transcriptPath = "$($AlyaLogs)\scripts\pstn\Create-AutoResponder-$($AlyaTimeString).log"
Start-Transcript -Path $transcriptPath | Out-Null

try
{
    # Interactive check, the only pause, before the isolated scopes are opened
    Write-Host "Exchange Online, Microsoft Graph and Microsoft Teams are used in separate isolated pwsh child processes (IsolatedProcess)." -ForegroundColor $CommandInfo
    Write-Host "Please make sure a phone resource account license (PHONESYSTEM_VIRTUALUSER) is available in the tenant. The script waits for the license assignment later on." -ForegroundColor $CommandInfo
    # pause only in interactive sessions: under -NonInteractive (wrapper/DevOps pipeline)
    # Read-Host throws a terminating error which would kill the whole script
    if (-Not [Console]::IsInputRedirected)
    {
        pause
    }

    # Members
    $callQueueName = "$attendantName Queue"
    $callQueueUpn = $attendantUpn -replace "@", ".queue@"
    $callGroupName = "$attendantName Group"
    $callGroupUpn = $attendantUpn -replace "@", ".group@"

    # Checking modules, each module family gets its own isolated process.
    # Every process loads 01_ConfigureEnv.ps1, installs only its own modules,
    # performs its own login and writes its own transcript next to the parent one.
    # Note: IsolatedProcess (not IsolatedScope) is required here - EXO, Graph and Teams
    # conflict on assembly level (Microsoft.Identity.Client / Azure.Identity) which
    # runspaces cannot isolate (verified 2026-09-20 against the DUBS tenant).
    Write-Host "Checking modules" -ForegroundColor $CommandInfo
    Start-IsolatedProcess -Name "Exo" -Modules @("ExchangeOnlineManagement") -ParentTranscriptPath $transcriptPath -Login {
        try { LoginTo-EXO } catch { LogoutFrom-EXOandIPPS; LoginTo-EXO }
    }
    Start-IsolatedProcess -Name "Graph" -ParentTranscriptPath $transcriptPath -Modules @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Beta.Identity.DirectoryManagement",
        "Microsoft.Graph.Beta.Users",
        "Microsoft.Graph.Beta.Users.Actions"
    ) -Login {
        LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"
    }
    Start-IsolatedProcess -Name "Teams" -Modules @("MicrosoftTeams") -ParentTranscriptPath $transcriptPath -Login {
        LoginTo-Teams
    }

    # =============================================================
    # EXO scope: distribution group
    # =============================================================

    $dGrpExternalDirectoryObjectId = $null
    try
    {
        $exoResult = Invoke-IsolatedProcess -Name "Exo" -Arguments @{
            callGroupName = $callGroupName
            callGroupUpn = $callGroupUpn
            callGroupUserUpns = $callGroupUserUpns
        } -ScriptBlock {
            $dGrp = Get-DistributionGroup -Identity $callGroupName -ErrorAction SilentlyContinue
            if (-Not $dGrp)
            {
                $grpAlias = $callGroupUpn.Replace("@$AlyaDomainName", "")
                Write-Warning "  Distribution group '$callGroupName' does not exist. Creating it now"
                $dGrp = New-DistributionGroup -Name $callGroupName -Alias $grpAlias -PrimarySmtpAddress $callGroupUpn -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false -ModerationEnabled $false
            }
            $null = Set-DistributionGroup -Identity $dGrp.Identity -MemberJoinRestriction Closed -MemberDepartRestriction Closed -PrimarySmtpAddress $callGroupUpn -ModerationEnabled $false -RequireSenderAuthenticationEnabled $false

            Write-Host "  checking members"
            $membs = Get-DistributionGroupMember -Identity $callGroupName
            foreach($callGroupUserUpn in $callGroupUserUpns)
            {
                $memb = $membs | Where-Object { $_.PrimarySmtpAddress -eq $callGroupUserUpn }
                if (-Not $memb)
                {
                    Write-Host "  adding member $callGroupUserUpn"
                    $memb = Add-DistributionGroupMember -Identity $callGroupName -Member $callGroupUserUpn
                }
            }
            #TODO remove not listed once
            $dGrpResult = Get-DistributionGroup -Identity $callGroupName
            return [PSCustomObject]@{
                ExternalDirectoryObjectId = $dGrpResult.ExternalDirectoryObjectId.ToString()
            }
        }
        $dGrpExternalDirectoryObjectId = $exoResult.ExternalDirectoryObjectId
    }
    catch
    {
        try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
        Write-Error ($_.Exception) -ErrorAction Continue
    }

    # =============================================================
    # Teams scope: application instances
    # =============================================================

    $instanceResult = Invoke-IsolatedProcess -Name "Teams" -Arguments @{
        attendantUpn = $attendantUpn
        attendantName = $attendantName
        callQueueUpn = $callQueueUpn
        callQueueName = $callQueueName
    } -ScriptBlock {
        Write-Host "Checking Application Instance $attendantUpn" -ForegroundColor $CommandInfo
        $appInstance = Find-CsOnlineApplicationInstance -SearchQuery $attendantUpn
        if (-Not $appInstance)
        {
            Write-Warning "Application Instance $attendantUpn not found! Creating it now."
            $appinstanceAppId = "ce933385-9390-45d1-9512-c8d228074e07"
            $appInstance = New-CsOnlineApplicationInstance -UserPrincipalName $attendantUpn -ApplicationId $appinstanceAppId -DisplayName $attendantName
        }
        do
        {
            try {
                $appInstance = Get-CsOnlineApplicationInstance -Identity $attendantUpn
            }
            catch {
                Write-Host "ApplicationInstance not yet found. Waiting..."
                Start-Sleep -Seconds 10
            }
        } while (-Not $appInstance)

        Write-Host "Checking Application Instance $callQueueUpn" -ForegroundColor $CommandInfo
        $queueInstance = Find-CsOnlineApplicationInstance -SearchQuery $callQueueUpn
        if (-Not $queueInstance)
        {
            Write-Warning "Application Instance $callQueueUpn not found! Creating it now."
            $queueInstanceAppId = "11cd3e2e-fccb-42ad-ad00-878b93575e07"
            $queueInstance = New-CsOnlineApplicationInstance -UserPrincipalName $callQueueUpn -ApplicationId $queueInstanceAppId -DisplayName $callQueueName
        }
        do
        {
            try {
                $queueInstance = Get-CsOnlineApplicationInstance -Identity $callQueueUpn
            }
            catch {
                Write-Host "ApplicationInstance not yet found. Waiting..."
                Start-Sleep -Seconds 10
            }
        } while (-Not $queueInstance)
        return [PSCustomObject]@{
            AttendantObjectId = $appInstance.ObjectId.ToString()
            QueueObjectId = $queueInstance.ObjectId.ToString()
        }
    }
    Write-Host "  attendant instance id: $($instanceResult.AttendantObjectId)"
    Write-Host "  queue instance id: $($instanceResult.QueueObjectId)"

    # =============================================================
    # Graph scope: license of the attendant resource account
    # =============================================================

    $null = Invoke-IsolatedProcess -Name "Graph" -Arguments @{
        attendantUpn = $attendantUpn
    } -ScriptBlock {
        Write-Host "Checking license for $attendantUpn" -ForegroundColor $CommandInfo
        $attendantUser = Get-MgBetaUser -UserId $attendantUpn
        $attendantLics = Get-MgBetaUserLicenseDetail -UserId $attendantUser.Id
        $hasLic = $attendantLics.ServicePlans.ServicePlanName -contains "MCOEV_VIRTUALUSER" -or `
                  $attendantLics.ServicePlans.SkuPartNumber -contains "MCOEV_VIRTUALUSER" -or `
                  $attendantLics.ServicePlans.ServicePlanName -contains "MCOEV_VIRTUALUSER_FACULTY" -or `
                  $attendantLics.ServicePlans.SkuPartNumber -contains "MCOEV_VIRTUALUSER_FACULTY"
        if ($attendantUser.UsageLocation -ne $AlyaDefaultUsageLocation)
        {
            Update-MgUser -UserId $attendantUpn -UsageLocation $AlyaDefaultUsageLocation
        }
        if (-Not $hasLic)
        {
            Write-Host "      Adding phone resource account license"
            $Sku = Get-MgBetaSubscribedSku -All | Where-Object { $_.SkuPartNumber -in @("PHONESYSTEM_VIRTUALUSER","PHONESYSTEM_VIRTUALUSER_FACULTY") }
            if (-Not $Sku)
            {
                $Sku = Get-MgBetaSubscribedSku -All | Where-Object { $_.ServicePlans.ServicePlanName -match [string]::Join('|', @("VIRTUALUSER","VIRTUALUSER_FACULTY")) }
                if (-Not $Sku)
                {
                    Write-Warning "No phone resource account license found. Please assign a phone resource account license to the user $attendantUpn manually."
                }
                else
                {
                    Write-Host "      Found phone resource account license $($Sku.SkuPartNumber) with SkuId $($Sku.SkuId)"
                    Set-MgBetaUserLicense -UserId $attendantUser.Id -AddLicenses @(@{SkuId = $Sku.SkuId}) -RemoveLicenses @() | Out-Null
                }
            }
            else
            {
                Write-Host "      Found phone resource account license $($Sku.SkuPartNumber) with SkuId $($Sku.SkuId)"
                Set-MgBetaUserLicense -UserId $attendantUser.Id -AddLicenses @{SkuId = $Sku.SkuId} -RemoveLicenses @() | Out-Null
            }
        }
        while (-Not $hasLic)
        {
            Write-Host "Waiting for license assignment ..."
            Start-Sleep -Seconds 10
            $attendantLics = Get-MgBetaUserLicenseDetail -UserId $attendantUser.Id
            $hasLic = $attendantLics.ServicePlans.ServicePlanName -contains "MCOEV_VIRTUALUSER" -or `
                    $attendantLics.ServicePlans.SkuPartNumber -contains "MCOEV_VIRTUALUSER" -or `
                    $attendantLics.ServicePlans.ServicePlanName -contains "MCOEV_VIRTUALUSER_FACULTY" -or `
                    $attendantLics.ServicePlans.SkuPartNumber -contains "MCOEV_VIRTUALUSER_FACULTY"
        }
    }

    # =============================================================
    # Teams scope: phone number, call queue, auto attendant
    # =============================================================

    $null = Invoke-IsolatedProcess -Name "Teams" -Arguments @{
        attendantName = $attendantName
        attendantUpn = $attendantUpn
        attendantNumber = $attendantNumber
        phoneNumberType = $phoneNumberType
        callQueueName = $callQueueName
        callQueueUpn = $callQueueUpn
        dGrpExternalDirectoryObjectId = $dGrpExternalDirectoryObjectId
        redirectToExternalNumber = $redirectToExternalNumber
        redirectToExternalNumberByMenu = $redirectToExternalNumberByMenu
        setCallerIdToAutoResponder = $setCallerIdToAutoResponder
        noCallHandlingAtAll = $noCallHandlingAtAll
        officeHourMorningStart = $officeHourMorningStart
        officeHourMorningEnd = $officeHourMorningEnd
        officeHourAfternoonStart = $officeHourAfternoonStart
        officeHourAfternoonEnd = $officeHourAfternoonEnd
        redirectToNextAgentAfterSeconds = $redirectToNextAgentAfterSeconds
        keepCallInQueueForSeconds = $keepCallInQueueForSeconds
        presenceBasedRouting = $presenceBasedRouting
        allLinesBusyTextToSpeechPrompt = $allLinesBusyTextToSpeechPrompt
        pleaseWaitTextToSpeechPrompt = $pleaseWaitTextToSpeechPrompt
        outOfOfficeTimeTextToSpeechPrompt = $outOfOfficeTimeTextToSpeechPrompt
        afterHoursMenuTextToSpeechPrompt = $afterHoursMenuTextToSpeechPrompt
        allLinesBusyTextToSpeechPromptAudioFile = $allLinesBusyTextToSpeechPromptAudioFile
        pleaseWaitTextToSpeechPromptAudioFile = $pleaseWaitTextToSpeechPromptAudioFile
        outOfOfficeTimeTextToSpeechPromptAudioFile = $outOfOfficeTimeTextToSpeechPromptAudioFile
        afterHoursMenuTextToSpeechPromptAudioFile = $afterHoursMenuTextToSpeechPromptAudioFile
        musicOnHoldAudioFile = $musicOnHoldAudioFile
        allowSharedVoicemail = $allowSharedVoicemail
        languageId = $languageId
        timeZoneId = $timeZoneId
        voiceId = $voiceId
        allowOptOut = $allowOptOut
        redirectAlways = $redirectAlways
    } -ScriptBlock {
        $appInstance = Get-CsOnlineApplicationInstance -Identity $attendantUpn
        $queueInstance = Get-CsOnlineApplicationInstance -Identity $callQueueUpn
        $dGrp = [PSCustomObject]@{
            ExternalDirectoryObjectId = $dGrpExternalDirectoryObjectId
        }

        Write-Host "Checking phone number $attendantNumber for $attendantUpn" -ForegroundColor $CommandInfo
        if (-Not $appInstance.PhoneNumber)
        {
            do {
                try {
                    Set-CsPhoneNumberAssignment -Identity $attendantUpn -PhoneNumber $attendantNumber -PhoneNumberType $phoneNumberType
                    break
                }
                catch {
                    if ($_.Exception.Message -match "lacks appropriate license")
                    {
                        Write-Warning "License not yet ready. Waiting..."
                        Start-Sleep -Seconds 10
                    }
                    else
                    {
                        throw $_.Exception
                    }
                }
            } while ($true)
            Start-Sleep -Seconds 10
        }
        else
        {
            if ($appInstance.PhoneNumber -ne "tel:$attendantNumber")
            {
                Write-Warning "Changing phone number from '$($appInstance.PhoneNumber)' to '$attendantNumber'."
                $numberType = (Get-CsPhoneNumberAssignment -TelephoneNumber $appInstance.PhoneNumber.Replace("tel:","")).NumberType
                Remove-CsPhoneNumberAssignment -Identity $attendantUpn -PhoneNumber $appInstance.PhoneNumber.Replace("tel:","") -PhoneNumberType $numberType
                Set-CsPhoneNumberAssignment -Identity $attendantUpn -PhoneNumber $attendantNumber -PhoneNumberType $numberType
                Start-Sleep -Seconds 10
            }
        }
        $appInstance = Get-CsOnlineApplicationInstance -Identity $attendantUpn

        Write-Host "Checking call queue $callQueueName" -ForegroundColor $CommandInfo
        $callQueue = Get-CsCallQueue -NameFilter $callQueueName
        if (-Not $callQueue)
        {
            Write-Warning "Call queue '$callQueueName' not found! Creating it now."
            $null = New-CsCallQueue -Name $callQueueName -UseDefaultMusicOnHold $true
            $callQueue = Get-CsCallQueue -NameFilter $callQueueName
        }

        #OverflowThreshold Maximum calls in the queue
        #TimeoutThreshold Maximum wait time until TimeoutAction

        $cmdParamBuilder = @{            
            Identity = $callQueue.Identity
            Name = $callQueueName
            LanguageId = $languageId
            RoutingMethod = "Attendant"
            PresenceBasedRouting = $presenceBasedRouting
            Users = $null
            AllowOptOut = $allowOptOut
            AgentAlertTime = $redirectToNextAgentAfterSeconds
            ConferenceMode = $true
        }
        if ($null -eq $musicOnHoldAudioFile)
        {
            $cmdParamBuilder.add('UseDefaultMusicOnHold', $true)
        }
        else
        {
            $content = [System.IO.File]::ReadAllBytes($musicOnHoldAudioFile)
            $name = Split-Path -Path $musicOnHoldAudioFile -Leaf
            $audioFile = Import-CsOnlineAudioFile -ApplicationId "OrgAutoAttendant" -FileName $name -Content $content # ApplicationID HuntGroup ?
            $cmdParamBuilder.add('MusicOnHoldAudioFileId', $audioFile.ID)
        }
        if ($redirectToExternalNumber -ne $null -or $redirectToExternalNumberByMenu -ne $null)
        {
            if ($redirectToExternalNumberByMenu){
                $cmdParamBuilder.add('OverflowThreshold', 5)
                $cmdParamBuilder.add('OverflowAction', "Forward")
                $cmdParamBuilder.add('OverflowActionTarget', "tel:$redirectToExternalNumberByMenu")
                $cmdParamBuilder.add('TimeoutThreshold', $keepCallInQueueForSeconds)
                $cmdParamBuilder.add('TimeoutAction', "Forward")
                $cmdParamBuilder.add('TimeoutActionTarget', "tel:$redirectToExternalNumberByMenu")
                $cmdParamBuilder.add('DistributionLists', $dGrp.ExternalDirectoryObjectId)
            } else {
                $cmdParamBuilder.add('OverflowThreshold', 5)
                $cmdParamBuilder.add('OverflowAction', "Forward")
                $cmdParamBuilder.add('OverflowActionTarget', "tel:$redirectToExternalNumber")
                $cmdParamBuilder.add('TimeoutThreshold', $keepCallInQueueForSeconds)
                $cmdParamBuilder.add('TimeoutAction', "Forward")
                $cmdParamBuilder.add('TimeoutActionTarget', "tel:$redirectToExternalNumber")
                $cmdParamBuilder.add('DistributionLists', $dGrp.ExternalDirectoryObjectId)
            }
        }
        else
        {
            if ($allowSharedVoicemail)
            {
                $cmdParamBuilder.add('OverflowAction', "SharedVoicemail")
                $cmdParamBuilder.add('EnableOverflowSharedVoicemailTranscription', $true)
                $cmdParamBuilder.add('TimeoutAction', "SharedVoicemail")
                $cmdParamBuilder.add('EnableTimeoutSharedVoicemailTranscription', $true)
                if ($null -eq $allLinesBusyTextToSpeechPromptAudioFile) {
                    $cmdParamBuilder.add('OverflowSharedVoicemailTextToSpeechPrompt', $allLinesBusyTextToSpeechPrompt)
                    $cmdParamBuilder.add('TimeoutSharedVoicemailTextToSpeechPrompt', $allLinesBusyTextToSpeechPrompt)
                } else {
                    $content = [System.IO.File]::ReadAllBytes($allLinesBusyTextToSpeechPromptAudioFile)
                    $name = Split-Path -Path $allLinesBusyTextToSpeechPromptAudioFile -Leaf
                    $audioFile = Import-CsOnlineAudioFile -ApplicationId "OrgAutoAttendant" -FileName $name -Content $content
                    $cmdParamBuilder.add('OverflowSharedVoicemailAudioFilePrompt', $audioFile)
                    $cmdParamBuilder.add('TimeoutSharedVoicemailAudioFilePrompt', $audioFile)
                }
                if (-Not $noCallHandlingAtAll) {
                    $cmdParamBuilder.add('OverflowThreshold', 5)
                    $cmdParamBuilder.add('OverflowActionTarget', $dGrp.ExternalDirectoryObjectId)
                    $cmdParamBuilder.add('TimeoutThreshold', $keepCallInQueueForSeconds)
                    $cmdParamBuilder.add('TimeoutActionTarget', $dGrp.ExternalDirectoryObjectId)
                    $cmdParamBuilder.add('DistributionLists', $dGrp.ExternalDirectoryObjectId)
                } else {
                    $cmdParamBuilder.add('OverflowThreshold', 0)
                    $cmdParamBuilder.add('OverflowActionTarget', $null)
                    $cmdParamBuilder.add('TimeoutThreshold', 0)
                    $cmdParamBuilder.add('TimeoutActionTarget', $null)
                    $cmdParamBuilder.add('DistributionLists', $null)
                }
            }
            else
            {
                if (-Not $noCallHandlingAtAll) {
                    $cmdParamBuilder.add('OverflowThreshold', 5)
                    $cmdParamBuilder.add('OverflowAction', "Disconnect")
                    $cmdParamBuilder.add('TimeoutThreshold', $keepCallInQueueForSeconds)
                    $cmdParamBuilder.add('TimeoutAction', "Disconnect")
                    $cmdParamBuilder.add('DistributionLists', $dGrp.ExternalDirectoryObjectId)
                } else {
                    $cmdParamBuilder.add('OverflowThreshold', 0)
                    $cmdParamBuilder.add('OverflowAction', "Disconnect")
                    $cmdParamBuilder.add('TimeoutThreshold', 0)
                    $cmdParamBuilder.add('TimeoutAction', "Disconnect")
                    $cmdParamBuilder.add('DistributionLists', $null)
                }
            }
        }
        Set-CsCallQueue @cmdParamBuilder

        $queueInstanceAssoc = $null
        try
        {
            $queueInstanceAssoc = Get-CsOnlineApplicationInstanceAssociation -Identity $queueInstance.ObjectId
        } catch {}
        if (-Not $queueInstanceAssoc)
        {
            Write-Warning "Call queue association not found! Creating it now."
            $null = New-CsOnlineApplicationInstanceAssociation -Identities @($queueInstance.ObjectId) -ConfigurationId $callQueue.Identity -ConfigurationType "CallQueue"
        }

        Write-Host "Checking auto attendant $attendantName" -ForegroundColor $CommandInfo
        if ($redirectAlways)
        {
            if ($redirectToExternalNumberByMenu){
                throw "It does make sense to specify redirectAlways and setting redirectToExternalNumberByMenu"
            }
            $externalNumberEntity = New-CsAutoAttendantCallableEntity -Identity $redirectToExternalNumber -Type ExternalPstn
            $defaultOption = New-CsAutoAttendantMenuOption -Action TransferCallToTarget -DtmfResponse Automatic -CallTarget $externalNumberEntity
            $defaultMenu = New-CsAutoAttendantMenu -Name "Default Menu" -MenuOptions @($defaultOption) -DirectorySearchMethod None
            $defaultCallFlow = New-CsAutoAttendantCallFlow -Name "Default call flow" -Menu $defaultMenu

            $appInstanceEntity = New-CsAutoAttendantCallableEntity -Identity $appInstance.ObjectId -Type ApplicationEndpoint
            $autoAttendant = Get-CsAutoAttendant -NameFilter $attendantName -ErrorAction SilentlyContinue
            if (-Not $autoAttendant)
            {
                Write-Warning "Auto attendant '$attendantName' not found! Creating it now."
                $null = New-CsAutoAttendant -Name $attendantName -LanguageId $languageId -VoiceId $voiceId -TimeZoneId $timeZoneId `
                    -Operator $appInstanceEntity -DefaultCallFlow $defaultCallFlow
            }
            else
            {
                Write-Warning "Updating '$attendantName'."
                $autoAttendant.DefaultCallFlow = $defaultCallFlow
                $autoAttendant.CallFlows = $null
                $autoAttendant.CallHandlingAssociations = $null
                $autoAttendant.LanguageId = $languageId
                $autoAttendant.VoiceId = $voiceId
                $autoAttendant.TimeZoneId = $timeZoneId
                $autoAttendant.Operator = $appInstanceEntity
                Set-CsAutoAttendant -Instance $autoAttendant -Force
            }
            $autoAttendant = Get-CsAutoAttendant -NameFilter $attendantName
        }
        else
        {
            $queueInstanceEntity = New-CsAutoAttendantCallableEntity -Identity $queueInstance.ObjectId -Type ApplicationEndpoint
            $defaultOption = New-CsAutoAttendantMenuOption -Action TransferCallToTarget -DtmfResponse Automatic -CallTarget $queueInstanceEntity
            $defaultMenu = New-CsAutoAttendantMenu -Name "Default Menu" -MenuOptions @($defaultOption) -DirectorySearchMethod None
            $greetings = $null
            if (-Not [string]::IsNullOrEmpty($pleaseWaitTextToSpeechPrompt))
            {
                $greetings = @(New-CsAutoAttendantPrompt -TextToSpeechPrompt $pleaseWaitTextToSpeechPrompt)
            }
            if ($null -ne $pleaseWaitTextToSpeechPromptAudioFile)
            {
                $content = [System.IO.File]::ReadAllBytes($pleaseWaitTextToSpeechPromptAudioFile)
                $name = Split-Path -Path $pleaseWaitTextToSpeechPromptAudioFile -Leaf
                $audioFile = Import-CsOnlineAudioFile -ApplicationId "OrgAutoAttendant" -FileName $name -Content $content
                $greetings = @(New-CsAutoAttendantPrompt -AudioFilePrompt $audioFile)
            }
            if ($null -eq $greetings)
            {
                $defaultCallFlow = New-CsAutoAttendantCallFlow -Name "Default call flow" -Menu $defaultMenu
            }
            else
            {
                $defaultCallFlow = New-CsAutoAttendantCallFlow -Name "Default call flow" -Greetings $greetings -Menu $defaultMenu
            }
            $afterHoursGreetingPrompt = New-CsAutoAttendantPrompt -TextToSpeechPrompt $outOfOfficeTimeTextToSpeechPrompt
            if ($null -ne $outOfOfficeTimeTextToSpeechPromptAudioFile)
            {
                $content = [System.IO.File]::ReadAllBytes($outOfOfficeTimeTextToSpeechPromptAudioFile)
                $name = Split-Path -Path $outOfOfficeTimeTextToSpeechPromptAudioFile -Leaf
                $audioFile = Import-CsOnlineAudioFile -ApplicationId "OrgAutoAttendant" -FileName $name -Content $content
                $afterHoursGreetingPrompt = New-CsAutoAttendantPrompt -AudioFilePrompt $audioFile
            }
            $afterHoursMenuPrompt = New-CsAutoAttendantPrompt -TextToSpeechPrompt $afterHoursMenuTextToSpeechPrompt
            if ($null -ne $afterHoursMenuTextToSpeechPromptAudioFile)
            {
                $content = [System.IO.File]::ReadAllBytes($afterHoursMenuTextToSpeechPromptAudioFile)
                $name = Split-Path -Path $afterHoursMenuTextToSpeechPromptAudioFile -Leaf
                $audioFile = Import-CsOnlineAudioFile -ApplicationId "OrgAutoAttendant" -FileName $name -Content $content
                $afterHoursMenuPrompt = New-CsAutoAttendantPrompt -AudioFilePrompt $audioFile
            }
            $sharedVoicemailEntity = New-CsAutoAttendantCallableEntity -Identity $dGrp.ExternalDirectoryObjectId -Type SharedVoiceMail -EnableTranscription -EnableSharedVoicemailSystemPromptSuppression
            if ($allowSharedVoicemail)
            {
                if ($redirectToExternalNumberByMenu -ne $null)
                {
                    $externalNumberEntity = New-CsAutoAttendantCallableEntity -Identity $redirectToExternalNumberByMenu -Type ExternalPstn
                    $afterHoursMenuOptionOne = New-CsAutoAttendantMenuOption -Action TransferCallToTarget -DtmfResponse Tone1 -CallTarget $sharedVoicemailEntity
                    $afterHoursMenuOptionTwo = New-CsAutoAttendantMenuOption -Action TransferCallToTarget -DtmfResponse Tone2 -CallTarget $externalNumberEntity
                    $afterHoursMenu = New-CsAutoAttendantMenu -Name "After Hours menu" -MenuOptions @($afterHoursMenuOptionOne,$afterHoursMenuOptionTwo) -Prompts @($afterHoursMenuPrompt)
                    $afterHoursCallFlow = New-CsAutoAttendantCallFlow -Name "After Hours call flow" -Greetings @($afterHoursGreetingPrompt) -Menu $afterHoursMenu
                }
                else
                {
                    $afterHoursMenuOptionOne = New-CsAutoAttendantMenuOption -Action TransferCallToTarget -DtmfResponse Tone1 -CallTarget $sharedVoicemailEntity
                    $afterHoursMenu = New-CsAutoAttendantMenu -Name "After Hours menu" -MenuOptions @($afterHoursMenuOptionOne) -Prompts @($afterHoursMenuPrompt)
                    $afterHoursCallFlow = New-CsAutoAttendantCallFlow -Name "After Hours call flow" -Greetings @($afterHoursGreetingPrompt) -Menu $afterHoursMenu
                }
            }
            else
            {
                if ($redirectToExternalNumberByMenu -ne $null)
                {
                    $externalNumberEntity = New-CsAutoAttendantCallableEntity -Identity $redirectToExternalNumberByMenu -Type ExternalPstn
                    $afterHoursMenuPrompt = New-CsAutoAttendantPrompt -TextToSpeechPrompt $afterHoursMenuTextToSpeechPrompt
                    $afterHoursMenuOptionOne = New-CsAutoAttendantMenuOption -Action TransferCallToTarget -DtmfResponse Tone1 -CallTarget $externalNumberEntity
                    $afterHoursMenu = New-CsAutoAttendantMenu -Name "After Hours menu" -MenuOptions @($afterHoursMenuOptionOne) -Prompts @($afterHoursMenuPrompt)
                    $afterHoursCallFlow = New-CsAutoAttendantCallFlow -Name "After Hours call flow" -Greetings @($afterHoursGreetingPrompt) -Menu $afterHoursMenu
                }
                else
                {
                    $afterHoursMenuOptionOne = New-CsAutoAttendantMenuOption -Action Disconnect -DtmfResponse Automatic
                    $afterHoursMenu = New-CsAutoAttendantMenu -Name "After Hours menu" -MenuOptions @($afterHoursMenuOptionOne)
                    $afterHoursCallFlow = New-CsAutoAttendantCallFlow -Name "After Hours call flow" -Greetings @($afterHoursGreetingPrompt) -Menu $afterHoursMenu
                }
            }
            if (-Not $noCallHandlingAtAll)
            {
                $timerange1 = New-CsOnlineTimeRange -Start $officeHourMorningStart -end $officeHourMorningEnd
                $timerange2 = New-CsOnlineTimeRange -Start $officeHourAfternoonStart -end $officeHourAfternoonEnd
                $afterHoursSchedule = New-CsOnlineSchedule -Name "After Hours schedule" -WeeklyRecurrentSchedule -MondayHours @($timerange1, $timerange2) -TuesdayHours @($timerange1, $timerange2) -WednesdayHours @($timerange1, $timerange2) -ThursdayHours @($timerange1, $timerange2) -FridayHours @($timerange1, $timerange2) -Complement
                $afterHoursCallHandlingAssociation = New-CsAutoAttendantCallHandlingAssociation -Type AfterHours -ScheduleId $afterHoursSchedule.Id -CallFlowId $afterHoursCallFlow.Id
            }

            $appInstanceEntity = New-CsAutoAttendantCallableEntity -Identity $appInstance.ObjectId -Type ApplicationEndpoint
            $autoAttendant = Get-CsAutoAttendant -NameFilter $attendantName -ErrorAction SilentlyContinue
            if (-Not $autoAttendant)
            {
                $autoAttendant = Get-CsAutoAttendant -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $attendantName }
            }
            if (-Not $autoAttendant)
            {
                Write-Warning "Auto attendant '$attendantName' not found! Creating it now."
                if (-Not $noCallHandlingAtAll) {
                    $null = New-CsAutoAttendant -Name $attendantName -LanguageId $languageId -VoiceId $voiceId -TimeZoneId $timeZoneId `
                        -EnableVoiceResponse -Operator $appInstanceEntity -DefaultCallFlow $defaultCallFlow `
                        -CallFlows @($afterHoursCallFlow) -CallHandlingAssociations @($afterHoursCallHandlingAssociation)
                } else {
                    $null = New-CsAutoAttendant -Name $attendantName -LanguageId $languageId -VoiceId $voiceId -TimeZoneId $timeZoneId `
                        -EnableVoiceResponse -Operator $appInstanceEntity -DefaultCallFlow $defaultCallFlow `
                        -CallFlows @($afterHoursCallFlow) -CallHandlingAssociations $null
                }
            }
            else
            {
                Write-Warning "Updating '$attendantName'."
                $autoAttendant.DefaultCallFlow = $defaultCallFlow
                if (-Not $noCallHandlingAtAll) {
                    $autoAttendant.CallHandlingAssociations = @($afterHoursCallHandlingAssociation)
                    $autoAttendant.CallFlows = @($afterHoursCallFlow)
                } else {
                    $autoAttendant.CallHandlingAssociations = $null
                    $autoAttendant.CallFlows = $null
                }
                $autoAttendant.LanguageId = $languageId
                $autoAttendant.VoiceId = $voiceId
                $autoAttendant.TimeZoneId = $timeZoneId
                $autoAttendant.Operator = $appInstanceEntity
                Set-CsAutoAttendant -Instance $autoAttendant -Force
            }
            $autoAttendant = Get-CsAutoAttendant -NameFilter $attendantName -ErrorAction SilentlyContinue
            if (-Not $autoAttendant)
            {
                $autoAttendant = Get-CsAutoAttendant -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $attendantName }
            }
        }

        $appInstanceAssoc = $null
        try
        {
            $appInstanceAssoc = Get-CsOnlineApplicationInstanceAssociation -Identity $appInstance.ObjectId
        } catch {}
        if (-Not $appInstanceAssoc)
        {
            Write-Warning "Auto attendant association not found! Creating it now."
            $null = New-CsOnlineApplicationInstanceAssociation -Identities @($appInstance.ObjectId) -ConfigurationId $autoAttendant.Identity -ConfigurationType "AutoAttendant"
        }

        if ($setCallerIdToAutoResponder -eq $true)
        {
            Set-CsCallingLineIdentity -Identity "Global" -CallingIDSubstitute Resource -EnableUserOverride $false -ResourceAccount $appInstance.ObjectId -CompanyName $attendantName
        }
    }
}
finally
{
    Stop-IsolatedProcess
    Stop-Transcript
}

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAP03zmEznQr7Ou
# l9r5xNrR/O2YaP6Ex+87S/WIcSjirqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGju
# xOV7dX3H9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQT
# AxEACqVq4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f
# 46P2IukytvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdY
# TA3E3kMHBiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhD
# o6nZ2Iwj1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL
# 1yf/30OVyct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AH
# hviDcudo30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfd
# sbCXAJvYNCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx
# /j+7m9WSaK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cid
# mgdUVveoBPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgf
# tnoAWlVn8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vC
# oTANBgkqhkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQ
# ZpE364hOTSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTso
# VYpQr3IozYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yo
# DsPU9IHP/w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQ
# X6ibUXqjXk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNp
# HbGY6Eg0RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirM
# Jk0b9UF2hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnA
# mrVkGZj2a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj
# 3+nmvWbZfNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL
# /yMvbDOHhREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtH
# dwO39ACaudnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4Qh
# trofETAxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPEtA16R
# dpmwc2V42H2FH8EFEfINr/zzLWI7Y8VLWBawMA0GCSqGSIb3DQEBAQUABIICAGJL
# eyjkI468KnFOXpVN9tLtU161leifT6oWBTOoeXN5LWoA1DrFgzUh7h4fwrQxZ2Xi
# WmRoaewGL7EFrRdaeUaiJYqCeNNTJ3bPzHWGuodV+4Y6lNvyHYQIVAQjSK41bXG5
# lXrJgypGrtOhu1WAWKWpge+Fl1EdFfUI2QFxhFdBRfUM/o+lrtyVHQQWH7qRomjW
# bcCx5911+hFIXlp/xc/yOQ88KM1OH7EVDoj4xNxFjGsXXuIbgJEeeh6rYBJpvCJS
# IdI/FApSCTD9TGWEGwYzpy1mvJATdvJq+LHwXedY2El0geY98M+Q2FRzoXs98IuR
# wO3HvGsI9R7ju9dXJOxj5tqWx/xN6ZDwpiS4ZlNWF6uzyvQLcKXkRM5tw01FsDC3
# OtaW8GP3ybMULN6LRG2g9XT6CdJDOCznSjRASi5D0icPggLWCYvOU7yXtYadKY+f
# 58Ah/biQiV8G0Pn2CtShRKlnF3CxGQlSCOaZXJfuM+e1rAOA8rnITaUN98bgygh9
# HbA1j7/TSUIXfLN1t3XFh78E00rK618sUBg9lQVRxLtagPE6EDEPPVirZnTQ9/u3
# ipviDR/I1pZjq/G+JPd2KjjUzeW0/aj4CM/oF4zW31ZmMQsq90GxPcrNItIug9oh
# McNlUX8u+biEX7e5gyKJEFjbinW29wrjAKiroLWmoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCBXpK5fAOKbnqnIiT37G0E1lpH9QP8JShZF8mwDf2mAGwIUZQ0R
# 6NewhyeBpsKIkHM/Y9gMgz0YDzIwMjYwODExMDcyMTI3WjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDCwEz5ib7T3VMNJ/xmocR13O5wBQxACkcdEKlC9Uicg3o7wVN+PgrmLqoSB
# RwmnG78wgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAWa5XRw/Ob6nWTm/L9QDi6Ks0D7nbjqvfmvGLWw1OYlk6
# //HZWYpO2ApzykypdHCNwW5MwBIeK8nWbqKY1vUupfOfh9+33DoAJJY/tpMAZ/T3
# nYd0/pPtOLvMbbxZHFGOCEImSL5+PDkPV5d/5xguNfRJewZU/0tI6T+QX94Vb1xk
# ZAJafLDB8Uixv/9dpoT8EV/256yEAICTInMc+PTagQ9IA91rhEdRyankUj30yIjO
# X3zeneaT+5fp55277enW1NMCaRudI0/GZnP0GSa73fGmesVKdHks6EIzbBElWvUM
# phxo3zpIlyAYaUI9xm0zCtJseFFMFJwPszoW34hY2wraDOKWnbwVE5dqqYPfHCLq
# sthAmBqPm7F+YseDLunIeVMLfGhP1WYpV1w4h0WUlwBsnp+97H02S1comsR4FB8d
# BGyDhc7gmLH3QufSyqw4HVOcSlL1AwsAI11KY5mrzWa7vrqAhu68xmrqR/nqpIr7
# iNWaesvSvIFCoMswlRnf
# SIG # End signature block
