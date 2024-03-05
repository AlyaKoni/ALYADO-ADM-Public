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
    25.03.2023 Konrad Brunner       Initial Version
    21.04.2023 Konrad Brunner       Switched to Graph

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Prepare-AllInternalAndExternalGroups-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Prepare-AllInternalAndExternalGroups | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$AllUsers = Get-MgBetaUser -All -Property "Id","UserPrincipalName","ExternalUserState"
$AllInternalsGroup = Get-MgBetaGroup -Filter "DisplayName eq '$AlyaAllInternals'"
$AllExternalsGroup = Get-MgBetaGroup -Filter "DisplayName eq '$AlyaAllExternals'"
$AllInternalsGroupMembers = Get-MgBetaGroupMember -GroupId $AllInternalsGroup.Id
$AllExternalsGroupMembers = Get-MgBetaGroupMember -GroupId $AllExternalsGroup.Id

foreach($user in $AllUsers)
{
    Write-Host "User $($user.UserPrincipalName)"
    if ($user.ExternalUserState -eq "Accepted")
    {
        Write-Host "  Guest $($user.Mail)"
        $extMemb = $AllExternalsGroupMembers | Where-Object { $_.AdditionalProperties.userPrincipalName -eq $user.UserPrincipalName }
        if (-Not $extMemb)
        {
            Write-Warning "    Adding to $AlyaAllExternals"
            New-MgBetaGroupMember -GroupId $AllExternalsGroup.Id -DirectoryObjectId $user.Id
        }
    }
    if (-Not $user.ExternalUserState)
    {
        Write-Host "  Member $($user.UserPrincipalName)"
        $intMemb = $AllInternalsGroupMembers | Where-Object { $_.AdditionalProperties.userPrincipalName -eq $user.UserPrincipalName }
        if (-Not $intMemb)
        {
            Write-Warning "    Adding to $AlyaAllExternals"
            New-MgBetaGroupMember -GroupId $AllInternalsGroup.Id -DirectoryObjectId $user.Id
        }
    }
}

#Stopping Transscript
Stop-Transcript
