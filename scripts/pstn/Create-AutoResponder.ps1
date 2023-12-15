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
    03.04.2022 Konrad Brunner       Initial Version
    16.08.2022 Konrad Brunner       External redirect and options

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
    $callGroupUserUpns = @("konrad.brunner@alyaconsulting.ch"),
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
    $allowSharedVoicemail = $true,
    $afterHoursMenuTextToSpeechPrompt = "Drücken Sie 1 um uns eine Nachricht zu hinterlassen.",
    $languageId = "de-DE",
    $timeZoneId = "W. Europe Standard Time",
    [ValidateSet("Female","Male")]
    $voiceId = "Female",
    $allowOptOut = $true,
    $redirectAlways = $false `
)
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

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\pstn\Create-AutoResponder-$($AlyaTimeString).log" | Out-Null

# Members
$callQueueName = "$attendantName Queue"
$callQueueUpn = $attendantUpn -replace "@", ".queue@"
$callGroupName = "$attendantName Group"
$callGroupUpn = $attendantUpn -replace "@", ".group@"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MicrosoftTeams"
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

# =============================================================
# O365 stuff
# =============================================================

try
{
    LoginTo-EXO

    #Distribution Group
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
}
catch
{
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}
finally
{
    DisconnectFrom-EXOandIPPS
}

# Logins
LoginTo-Teams

Write-Host "Checking Application Instance $attendantUpn" -ForegroundColor $CommandInfo
$appInstance = Find-CsOnlineApplicationInstance -SearchQuery $attendantUpn
if (-Not $appInstance)
{
    Write-Warning "Application Instance $attendantUpn not found! Creating it now."
    $appinstanceAppId = "ce933385-9390-45d1-9512-c8d228074e07"
    $appInstance = New-CsOnlineApplicationInstance -UserPrincipalName $attendantUpn -ApplicationId $appinstanceAppId -DisplayName $attendantName -Force
    Start-Sleep -Seconds 10
}
$appInstance = Get-CsOnlineApplicationInstance -Identity $attendantUpn

Write-Host "Checking Application Instance $callQueueUpn" -ForegroundColor $CommandInfo
$queueInstance = Find-CsOnlineApplicationInstance -SearchQuery $callQueueUpn
if (-Not $queueInstance)
{
    Write-Warning "Application Instance $callQueueUpn not found! Creating it now."
    $queueInstanceAppId = "11cd3e2e-fccb-42ad-ad00-878b93575e07"
    $queueInstance = New-CsOnlineApplicationInstance -UserPrincipalName $callQueueUpn -ApplicationId $queueInstanceAppId -DisplayName $callQueueName -Force
    Start-Sleep -Seconds 10
}
$queueInstance = Get-CsOnlineApplicationInstance -Identity $callQueueUpn

Write-Host "Checking licenses for $attendantUpn" -ForegroundColor $CommandInfo
Write-Host " - Please assign license to $attendantUpn in license sheet \data\aad\Lizenzen.xlsx"
Write-Host " - Run script \scripts\aad\Configure-Licenses.ps1"
Write-Host "Hit return when done"
pause

Write-Host "Checking phone number $attendantNumber for $attendantUpn" -ForegroundColor $CommandInfo
if ($appInstance.PhoneNumber -ne "tel:$attendantNumber")
{
    Write-Warning "Changing phone number from '$($appInstance.PhoneNumber)' to '$attendantNumber'."
    $numberType = (Get-CsPhoneNumberAssignment -TelephoneNumber $appInstance.PhoneNumber.Replace("tel:","")).NumberType
    Remove-CsPhoneNumberAssignment -Identity $attendantUpn -PhoneNumber $appInstance.PhoneNumber.Replace("tel:","") -PhoneNumberType $numberType
    Set-CsPhoneNumberAssignment -Identity $attendantUpn -PhoneNumber $attendantNumber -PhoneNumberType $numberType
    Start-Sleep -Seconds 10
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
if ($redirectToExternalNumber -ne $null -or $redirectToExternalNumberByMenu -ne $null)
{
    if ($redirectToExternalNumberByMenu){
        $null = Set-CsCallQueue -Identity $callQueue.Identity -Name $callQueueName -LanguageId $languageId -RoutingMethod "Attendant" -PresenceBasedRouting $presenceBasedRouting `
	    -Users $null -AllowOptOut $allowOptOut -AgentAlertTime $redirectToNextAgentAfterSeconds -UseDefaultMusicOnHold $true -ConferenceMode $true `
	    -OverflowThreshold 5 -OverflowAction Forward -OverflowActionTarget "tel:$redirectToExternalNumberByMenu" `
	    -TimeoutThreshold $keepCallInQueueForSeconds -TimeoutAction Forward -TimeoutActionTarget "tel:$redirectToExternalNumberByMenu" `
	    -DistributionLists $dGrp.ExternalDirectoryObjectId
    } else {
        $null = Set-CsCallQueue -Identity $callQueue.Identity -Name $callQueueName -LanguageId $languageId -RoutingMethod "Attendant" -PresenceBasedRouting $presenceBasedRouting `
	    -Users $null -AllowOptOut $allowOptOut -AgentAlertTime $redirectToNextAgentAfterSeconds -UseDefaultMusicOnHold $true -ConferenceMode $true `
	    -OverflowThreshold 5 -OverflowAction Forward -OverflowActionTarget "tel:$redirectToExternalNumber" `
	    -TimeoutThreshold $keepCallInQueueForSeconds -TimeoutAction Forward -TimeoutActionTarget "tel:$redirectToExternalNumber" `
	    -DistributionLists $dGrp.ExternalDirectoryObjectId
    }
}
else
{
    if ($allowSharedVoicemail)
    {
        if (-Not $noCallHandlingAtAll) {
            $null = Set-CsCallQueue -Identity $callQueue.Identity -Name $callQueueName -LanguageId $languageId -RoutingMethod "Attendant" -PresenceBasedRouting $presenceBasedRouting `
                -Users $null -AllowOptOut $allowOptOut -AgentAlertTime $redirectToNextAgentAfterSeconds -UseDefaultMusicOnHold $true -ConferenceMode $true `
                -OverflowThreshold 5 -OverflowAction SharedVoicemail -OverflowActionTarget $dGrp.ExternalDirectoryObjectId -EnableOverflowSharedVoicemailTranscription $true `
                -OverflowSharedVoicemailTextToSpeechPrompt $allLinesBusyTextToSpeechPrompt `
                -TimeoutThreshold $keepCallInQueueForSeconds -TimeoutAction SharedVoicemail -TimeoutActionTarget $dGrp.ExternalDirectoryObjectId -EnableTimeoutSharedVoicemailTranscription $true `
                -TimeoutSharedVoicemailTextToSpeechPrompt $allLinesBusyTextToSpeechPrompt `
                -DistributionLists $dGrp.ExternalDirectoryObjectId
        } else {
            $null = Set-CsCallQueue -Identity $callQueue.Identity -Name $callQueueName -LanguageId $languageId -RoutingMethod "Attendant" -PresenceBasedRouting $presenceBasedRouting `
                -Users $null -AllowOptOut $allowOptOut -AgentAlertTime $redirectToNextAgentAfterSeconds -UseDefaultMusicOnHold $true -ConferenceMode $true `
                -OverflowThreshold 0 -OverflowAction SharedVoicemail -OverflowActionTarget $null -EnableOverflowSharedVoicemailTranscription $true `
                -OverflowSharedVoicemailTextToSpeechPrompt $allLinesBusyTextToSpeechPrompt `
                -TimeoutThreshold 0 -TimeoutAction SharedVoicemail -TimeoutActionTarget $null -EnableTimeoutSharedVoicemailTranscription $true `
                -TimeoutSharedVoicemailTextToSpeechPrompt $allLinesBusyTextToSpeechPrompt `
                -DistributionLists $null
        }
    }
    else
    {
        if (-Not $noCallHandlingAtAll) {
            $null = Set-CsCallQueue -Identity $callQueue.Identity -Name $callQueueName -LanguageId $languageId -RoutingMethod "Attendant" -PresenceBasedRouting $presenceBasedRouting `
                -Users $null -AllowOptOut $allowOptOut -AgentAlertTime $redirectToNextAgentAfterSeconds -UseDefaultMusicOnHold $true -ConferenceMode $true `
                -OverflowThreshold 5 -OverflowAction Disconnect -TimeoutThreshold $keepCallInQueueForSeconds -TimeoutAction Disconnect `
                -DistributionLists $dGrp.ExternalDirectoryObjectId
        } else {
            $null = Set-CsCallQueue -Identity $callQueue.Identity -Name $callQueueName -LanguageId $languageId -RoutingMethod "Attendant" -PresenceBasedRouting $presenceBasedRouting `
                -Users $null -AllowOptOut $allowOptOut -AgentAlertTime 15 -UseDefaultMusicOnHold $true -ConferenceMode $true `
                -OverflowThreshold 0 -OverflowAction Disconnect -TimeoutThreshold 0 -TimeoutAction Disconnect `
                -DistributionLists $null
        }
    }
}

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

Write-Host "Checking auto attendant $callQueueName" -ForegroundColor $CommandInfo
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
    $greetingPrompt = New-CsAutoAttendantPrompt -TextToSpeechPrompt $pleaseWaitTextToSpeechPrompt
    $defaultCallFlow = New-CsAutoAttendantCallFlow -Name "Default call flow" -Greetings @($greetingPrompt) -Menu $defaultMenu
    $afterHoursGreetingPrompt = New-CsAutoAttendantPrompt -TextToSpeechPrompt $outOfOfficeTimeTextToSpeechPrompt
    if ($allowSharedVoicemail)
    {
        if ($redirectToExternalNumberByMenu -ne $null)
        {
            $sharedVoicemailEntity = New-CsAutoAttendantCallableEntity -Identity $dGrp.ExternalDirectoryObjectId -Type SharedVoiceMail -EnableTranscription -EnableSharedVoicemailSystemPromptSuppression
            $externalNumberEntity = New-CsAutoAttendantCallableEntity -Identity $redirectToExternalNumberByMenu -Type ExternalPstn
            $afterHoursMenuPrompt = New-CsAutoAttendantPrompt -TextToSpeechPrompt $afterHoursMenuTextToSpeechPrompt
            $afterHoursMenuOptionOne = New-CsAutoAttendantMenuOption -Action TransferCallToTarget -DtmfResponse Tone1 -CallTarget $sharedVoicemailEntity
            $afterHoursMenuOptionTwo = New-CsAutoAttendantMenuOption -Action TransferCallToTarget -DtmfResponse Tone2 -CallTarget $externalNumberEntity
            $afterHoursMenu = New-CsAutoAttendantMenu -Name "After Hours menu" -MenuOptions @($afterHoursMenuOptionOne,$afterHoursMenuOptionTwo) -Prompts @($afterHoursMenuPrompt)
            $afterHoursCallFlow = New-CsAutoAttendantCallFlow -Name "After Hours call flow" -Greetings @($afterHoursGreetingPrompt) -Menu $afterHoursMenu
        }
        else
        {
            $sharedVoicemailEntity = New-CsAutoAttendantCallableEntity -Identity $dGrp.ExternalDirectoryObjectId -Type SharedVoiceMail -EnableTranscription -EnableSharedVoicemailSystemPromptSuppression
            $afterHoursMenuPrompt = New-CsAutoAttendantPrompt -TextToSpeechPrompt $afterHoursMenuTextToSpeechPrompt
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
    $autoAttendant = Get-CsAutoAttendant -NameFilter $attendantName
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
