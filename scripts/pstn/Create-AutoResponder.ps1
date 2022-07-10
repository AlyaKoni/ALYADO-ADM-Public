#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2021

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
    03.04.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [ValidateNotNullOrEmpty()]
    $attendantName = "Alya Zentrale",
    [ValidateNotNullOrEmpty()]
    $attendantUpn = "zentrale@alyaconsulting.ch",
    [ValidateNotNullOrEmpty()]
    $attendantNumber = "+41625620460",
    [ValidateNotNullOrEmpty()]
    $callGroupUserUpns = @("konrad.brunner@alyaconsulting.ch"),
    $setCallerIdToAutoResponder = $false
)
if ($attendantNumber.StartsWith("tel:"))
{
    Write-Error "The number must not start with 'tel:'" -ErrorAction Continue
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
    $dGrp = Get-DistributionGroup -Identity $callGroupName -ErrorAction SilentlyContinue
    if (-Not $dGrp)
    {
        $grpAlias = $callGroupUpn.Replace("@$AlyaDomainName", "")
        Write-Warning "  Distribution group '$callGroupName' does not exist. Creating it now"
        $dGrp = New-DistributionGroup -Name $callGroupName -Alias $grpAlias -PrimarySmtpAddress $callGroupUpn -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
    }
    $null = $dGrp | Set-DistributionGroup -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
    Write-Host "  checking members"
    $membs = Get-DistributionGroupMember -Identity $callGroupName
    foreach($callGroupUserUpn in $callGroupUserUpns)
    {
        $memb = $membs | where { $_.PrimarySmtpAddress -eq $callGroupUserUpn }
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
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 3) -ErrorAction Continue } catch {}
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
    if ($attendantType -eq "CallQueue") { $appinstanceAppId = "11cd3e2e-fccb-42ad-ad00-878b93575e07" }
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
    $null = Set-CsOnlineApplicationInstance -Identity $attendantUpn -OnpremPhoneNumber $attendantNumber -Force
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
#TimeoutThreshold Maximum wait time
$null = Set-CsCallQueue -Identity $callQueue.Identity -Name $callQueueName -LanguageId "de-DE" -RoutingMethod "Attendant" -PresenceBasedRouting $true `
    -Users $null -AllowOptOut $true -AgentAlertTime 20 -UseDefaultMusicOnHold $true -ConferenceMode $true `
    -OverflowThreshold 2 -OverflowAction SharedVoicemail -OverflowActionTarget $dGrp.ExternalDirectoryObjectId -EnableOverflowSharedVoicemailTranscription $true `    -OverflowSharedVoicemailTextToSpeechPrompt "Leider sind aktuell alle unsere Leitung besetzt. Bitte hinterlassen Sie uns eine Nachricht oder versuchen Sie es später noch einmal." `
    -TimeoutThreshold 120 -TimeoutAction SharedVoicemail -TimeoutActionTarget $dGrp.ExternalDirectoryObjectId -EnableTimeoutSharedVoicemailTranscription $true `    -TimeoutSharedVoicemailTextToSpeechPrompt "Leider sind aktuell alle unsere Leitung besetzt. Bitte hinterlassen Sie uns eine Nachricht oder versuchen Sie es später noch einmal." `    -DistributionLists $dGrp.ExternalDirectoryObjectId

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
$autoAttendant = Get-CsAutoAttendant -NameFilter $attendantName
if (-Not $autoAttendant)
{
    Write-Warning "Auto attendant '$attendantName' not found! Creating it now."

    $queueInstanceEntity = New-CsAutoAttendantCallableEntity -Identity $queueInstance.ObjectId -Type ApplicationEndpoint
    $defaultOption = New-CsAutoAttendantMenuOption -Action TransferCallToTarget -DtmfResponse Automatic -CallTarget $queueInstanceEntity
    $defaultMenu = New-CsAutoAttendantMenu -Name "Default Menu" -MenuOptions @($defaultOption) -DirectorySearchMethod None
    $greetingPrompt = New-CsAutoAttendantPrompt -TextToSpeechPrompt "Willkommen bei der Schreinerei Dubs! Der nächste freie Mitarbeiter kümmert sich gleich um Ihr Anliegen. Bitte haben Sie einen Moment Geduld."
    $defaultCallFlow = New-CsAutoAttendantCallFlow -Name "Default call flow" -Greetings @($greetingPrompt) -Menu $defaultMenu

    $sharedVoicemailEntity = New-CsAutoAttendantCallableEntity -Identity $dGrp.ExternalDirectoryObjectId -Type SharedVoiceMail -EnableTranscription -EnableSharedVoicemailSystemPromptSuppression
    $afterHoursGreetingPrompt = New-CsAutoAttendantPrompt -TextToSpeechPrompt "Willkommen bei der Schreinerei Dubs! Leider erreichen Sie uns ausserhalb unserer Öffnungszeiten. Bitte hinterlassen Sie uns eine Nachricht oder rufen Sie uns von Montag bis Freitag von 8 bis 12 Uhr oder von 13 bis 17 Uhr an."
    $afterHoursMenuOptionOne = New-CsAutoAttendantMenuOption -Action TransferCallToTarget -DtmfResponse Tone1 -CallTarget $sharedVoicemailEntity
    $afterHoursMenuPromptOne = New-CsAutoAttendantPrompt -TextToSpeechPrompt "Drücken Sie 1 um uns eine Nachricht zu hinterlassen."
    $afterHoursMenu = New-CsAutoAttendantMenu -Name "After Hours menu" -MenuOptions @($afterHoursMenuOptionOne) -Prompts @($afterHoursMenuPromptOne)
    $afterHoursCallFlow = New-CsAutoAttendantCallFlow -Name "After Hours call flow" -Greetings @($afterHoursGreetingPrompt) -Menu $afterHoursMenu
    $timerange1 = New-CsOnlineTimeRange -Start 08:00 -end 12:00
    $timerange2 = New-CsOnlineTimeRange -Start 13:00 -end 17:00
    $afterHoursSchedule = New-CsOnlineSchedule -Name "After Hours schedule" -WeeklyRecurrentSchedule -MondayHours @($timerange1, $timerange2) -TuesdayHours @($timerange1, $timerange2) -WednesdayHours @($timerange1, $timerange2) -ThursdayHours @($timerange1, $timerange2) -FridayHours @($timerange1, $timerange2) -Complement
    $afterHoursCallHandlingAssociation = New-CsAutoAttendantCallHandlingAssociation -Type AfterHours -ScheduleId $afterHoursSchedule.Id -CallFlowId $afterHoursCallFlow.Id

    $appInstanceEntity = New-CsAutoAttendantCallableEntity -Identity $appInstance.ObjectId -Type ApplicationEndpoint
    $null = New-CsAutoAttendant -Name $attendantName -LanguageId "de-DE" -VoiceId "Female" -TimeZoneId "W. Europe Standard Time" `
        -EnableVoiceResponse -Operator $appInstanceEntity -DefaultCallFlow $defaultCallFlow `
        -CallFlows @($afterHoursCallFlow) -CallHandlingAssociations @($afterHoursCallHandlingAssociation)
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

if ($setCallerIdToAutoResponder)
{
    Set-CsCallingLineIdentity -Identity "Global" -CallingIDSubstitute Resource -EnableUserOverride $false -ResourceAccount $appInstance.ObjectId -CompanyName $attendantName
}
