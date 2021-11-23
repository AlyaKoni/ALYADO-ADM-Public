#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2021

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
    24.10.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

. $PSScriptRoot\00_Configuration.ps1

Connect-ExchangeOnline -ShowProgress $true

$batch = Get-MigrationBatch -Identity $migBatchName
if (-Not $batch.LastSyncedDateTime)
{
    Write-Warning "Please wait until sync has finished once"
    exit
}

if (-Not (Test-Path "$migDir\MigScripts\AddMembersToGroups.ps1"))
{
    Write-Warning "Please download the migration scripts from https://www.microsoft.com/download/details.aspx?id=55985 to the folder MigScripts"
    exit
}

if (-Not (Test-Path "$migDir\Backup" -PathType Container))
{
    New-Item -Path "$migDir\Backup" -ItemType Directory -Force
}

Disconnect-ExchangeOnline -Confirm:$false

if (-Not $Global:ocred)
{
    $Global:ocred = Get-Credential -Message "Local exchange admin account" -UserName "vorname.nachname@domain.com"
}

Write-Warning "The microsoft migration script does not support MFA! Please remove MFA for $($Global:cred.UserName)"
pause

pushd "$migDir\MigScripts"
.\AddMembersToGroups.ps1 -MappingCsv "$migDir\import.csv" -BackupDir "$migDir\Backup" -ArePublicFoldersOnPremises $true -Credential $Global:ocred
popd
