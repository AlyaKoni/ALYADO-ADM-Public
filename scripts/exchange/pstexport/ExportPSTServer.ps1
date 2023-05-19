#Requires -Version 2

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


#>

$ExportUsers = @(
    "cloud.test@alyaconsulting.ch",
    "first.last@alyaconsulting.ch"
)

$Cmd = Get-Command -Name New-MailboxExportRequest -ErrorAction SilentlyContinue
if (-Not $Cmd)
{
    $Cmd = Get-Command -Name New-MailboxExportRequest -ErrorAction SilentlyContinue
    if (-Not $Cmd)
    {
        Write-Host "You are not running in an Exchange PowerShell!" -ForegroundColor Red
        Return
    }
    else
    {
        $usr = [Environment]::UserName.ToLower()
        New-ManagementRoleAssignment –Role "Mailbox Import Export" –User $usr
        Write-Host "We had to add your account to the export role in exchange. Please close and restart session to make your role active." -ForegroundColor Red
        Return
    }
}

foreach ($ExportUser in $ExportUsers)
{
    Write-Host "Exporting $ExportUser"
    New-MailboxExportRequest -Name $ExportUser -Mailbox $ExportUser -FilePath "\\server\ExchangeExport\ServerExports\$($ExportUser).pst"
}

$AllDone = $false
Write-Host "Exporting" -NoNewline
while(-Not $AllDone)
{
    $AllDone = $true
    foreach ($ExportUser in $ExportUsers)
    {
        $Req = Get-MailboxExportRequest -Name $ExportUser
        if ($Req -eq "Queued" -or $Req -eq "InProgress")
        {
            $AllDone = $false
        }
    }
    Write-Host "." -NoNewline
    Start-Sleep -Seconds 10
}
Write-Host ""
Get-MailboxExportRequest
