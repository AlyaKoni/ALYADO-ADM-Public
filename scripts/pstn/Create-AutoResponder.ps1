#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

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
    # Logins
    try {
        LoginTo-EXO
    }
    catch {
        Write-Error $_.Exception -ErrorAction Continue
        LogoutFrom-EXOandIPPS
        LoginTo-EXO
    }
    LoginTo-Teams

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

Write-Host "Checking licenses for $attendantUpn" -ForegroundColor $CommandInfo
Write-Host " - Please assign license to $attendantUpn in license sheet \data\aad\Lizenzen.xlsx"
Write-Host " - Run script \scripts\aad\Configure-Licenses.ps1"
Write-Host "Hit return when done"
pause

Write-Host "Checking phone number $attendantNumber for $attendantUpn" -ForegroundColor $CommandInfo
if (-Not $appInstance.PhoneNumber)
{
    Set-CsPhoneNumberAssignment -Identity $attendantUpn -PhoneNumber $attendantNumber -PhoneNumberType $phoneNumberType
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

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAb+50C5c500SwQ
# XFQ+Bm+Fqz9V0WjzP9DIvCbTs3A7/6CCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOSwP0XA60/HVI1E
# AS0Oq5LOZQAe39RC1+vgp0lr3SgXMA0GCSqGSIb3DQEBAQUABIICAI8gNN59Ndrs
# TXicmqI0JdPAJ0sYOv5UC0HwP8oKi6+6PnDkZsIk4onv5YBqqmRdJWhKV4q2XVWv
# qTIZgQJ376MX8P/HnxOXHGZ9wnIn0JTCXjT9dKrg8xDVk4uO5JdDUfI0gIGlWJK7
# Nn71J+sN1cR3CgFrnplBHWxOK1A4hxINBtVwvP6AGpXUEGgE7xqVLtGm5PVMnZ5C
# FFc5ockD5fmhr/mOaHTVajb2TgO1zEnSa5NUnCNuNvPqsqv0/ozviC76Wq5HORUz
# owSqfsykF1YwRcsBQuqkHBYsdcUYUhpdAgcsZ7of8OuKEMPnfA/7jaVL7DSnycf8
# 0UWcTqBMr4v3B/0F6m6EMyScynsuvjln4ScVtJqNkWvskJEuTsUQ6u5DsyZhRHCP
# tdtphkp1SdskFuxDByTnK14mf2re05jbYHstqyGgn6nP/IjvPoUo9uJqzTstzkWf
# rrSHoix4HrtuiRvC9hlPf+4fblN4H3DVvXiGfN0TSEzWA7+B5RGjvz5HAtVlabKw
# Mh4O7ImA6jG1OUkHXds1rokWvl3aIQ3vwMERcihPMDuOs4qQPW+Xj5dhyRuidoyp
# 8C5TjNjZX+807WQ81Sk8/umJYTyEAEdgvosL6nOiviYWmupWkRry45yF5Fs4IdYo
# Ud8youVovunZ7tTjw7HO6VCwqlvZSB6uoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCAF0iZcu8GzfaAnnpvHh6+p+B+JP0Tb+X0AFoVCJJz2+QIULROsz62QPjfl
# 0votoATj49A4U8oYDzIwMjYwMTIwMDk1OTQwWjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
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
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# INPdO28anX1MZuVf3lBSfjDAtNWqLW2K+8lYS16XSEXpMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAbcKinpm9xLTF
# WFlYPfIuijgrvNUj6maOUJ1oDfW0cVD6YhCCER9XCSX1lyK6fQqeRqw+zwT6OxuX
# XIAj65EeQVNL2c4ijh7e8lPpSSLWe/cY5kRkgMxxYXvWbGY8E4S7LqnGM358LWFX
# HULba99uXCdHhj1VeVz0oaYwBHQ8ytrNhK92eU8H8BwzLBZpfQO6pBX1JYUIt7pn
# ddaNkDf3vqMxTgm4PLZMevW3Nxsy/mvro+wJTSAqN/Y33iotF21tTIONJ9ofLZ83
# 7O6UonLDsvQ8O9OIDWi3AGHSBfvpncYvFwgB5W06RoRy/hD75zhncRurBR3Ol3Pe
# NZ4zzeKVWau+Lu/99mOisjgKmtwuQnT7eP/KlayoPRAg4bpAFdUmodcWRRsfuNNP
# iosirkt0j4074hCdrf2ckbTcguFSejZN2VeFrTZzSoHMAtw8AAubmwnqCy5bcKDU
# 1/xoSJfFMKvJA3dxxYze9+rwjEiKhbGAWUxZLL1kS/H6j4XPmj2l
# SIG # End signature block
