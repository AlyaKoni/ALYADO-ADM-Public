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
    04.02.2025 Konrad Brunner       Initial Creation

#>

[CmdletBinding()]
Param(
    [bool]$onAllRoomMailboxs = $true,
    [bool]$onAllEquipmentMailboxs = $true,
    [string]$onSpecificRoomMailbox = $null,
    [string]$onSpecificEquipmentMailbox = $null
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Disable-MaximumDurationInRessourceAccounts-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "EXCHANGE | Disable-MaximumDurationInRessourceAccounts | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

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
    
    if ($onAllRoomMailboxs -eq $true)
    {
        Write-Host "Disabling MaximumDurationInMinutes on all RoomMailbox's"
        Get-Mailbox | Where-Object {$_.recipientTypeDetails -eq "RoomMailbox"} | Set-CalendarProcessing -MaximumDurationInMinutes 0
        Get-Mailbox | Where-Object {$_.recipientTypeDetails -eq "RoomMailbox"} | Get-CalendarProcessing | Select-Object -Property Identity, MaximumDurationInMinutes, AutomateProcessing
    }
    
    if ($onAllEquipmentMailboxs -eq $true)
    {
        Write-Host "Disabling MaximumDurationInMinutes on all EquipmentMailbox's"
        Get-Mailbox | Where-Object {$_.recipientTypeDetails -eq "EquipmentMailbox"} | Set-CalendarProcessing -MaximumDurationInMinutes 0
        Get-Mailbox | Where-Object {$_.recipientTypeDetails -eq "EquipmentMailbox"} | Get-CalendarProcessing | Select-Object -Property Identity, MaximumDurationInMinutes, AutomateProcessing
    }
    
    if (-Not [string]::IsNullOrEmpty($onSpecificRoomMailbox))
    {
        Write-Host "Disabling MaximumDurationInMinutes on RoomMailbox $onSpecificRoomMailbox"
        Get-Mailbox | Where-Object {$_.recipientTypeDetails -eq "EquipmentMailbox" -and ( `
            $_.Name -eq $onSpecificRoomMailbox -or `
            $_.Alias -eq $onSpecificRoomMailbox -or `
            $_.PrimarySmtpAddress -eq $onSpecificRoomMailbox -or `
            $_.Guid -eq $onSpecificRoomMailbox -or `
            $_.DistinguishedName -eq $onSpecificRoomMailbox)} | Set-CalendarProcessing -MaximumDurationInMinutes 0
        Get-Mailbox | Where-Object {$_.recipientTypeDetails -eq "EquipmentMailbox" -and ( `
            $_.Name -eq $onSpecificRoomMailbox -or `
            $_.Alias -eq $onSpecificRoomMailbox -or `
            $_.PrimarySmtpAddress -eq $onSpecificRoomMailbox -or `
            $_.Guid -eq $onSpecificRoomMailbox -or `
            $_.DistinguishedName -eq $onSpecificRoomMailbox)} | Select-Object -Property Identity, MaximumDurationInMinutes, AutomateProcessing
    }

    if (-Not [string]::IsNullOrEmpty($onSpecificEquipmentMailbox))
    {
        Write-Host "Disabling MaximumDurationInMinutes on EquipmentMailbox $onSpecificEquipmentMailbox"
        Get-Mailbox | Where-Object {$_.recipientTypeDetails -eq "EquipmentMailbox" -and ( `
            $_.Name -eq $onSpecificEquipmentMailbox -or `
            $_.Alias -eq $onSpecificEquipmentMailbox -or `
            $_.PrimarySmtpAddress -eq $onSpecificEquipmentMailbox -or `
            $_.Guid -eq $onSpecificEquipmentMailbox -or `
            $_.DistinguishedName -eq $onSpecificEquipmentMailbox)} | Set-CalendarProcessing -MaximumDurationInMinutes 0
        Get-Mailbox | Where-Object {$_.recipientTypeDetails -eq "EquipmentMailbox" -and ( `
            $_.Name -eq $onSpecificEquipmentMailbox -or `
            $_.Alias -eq $onSpecificEquipmentMailbox -or `
            $_.PrimarySmtpAddress -eq $onSpecificEquipmentMailbox -or `
            $_.Guid -eq $onSpecificEquipmentMailbox -or `
            $_.DistinguishedName -eq $onSpecificEquipmentMailbox)} | Select-Object -Property Identity, MaximumDurationInMinutes, AutomateProcessing
    }
}
catch
{
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}

#Stopping Transscript
Stop-Transcript
