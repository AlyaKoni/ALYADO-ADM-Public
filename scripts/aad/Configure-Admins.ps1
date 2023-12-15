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
    28.09.2020 Konrad Brunner       Initial Version
    01.05.2023 Konrad Brunner       Switched to Graph, removed MSOL
    20.11.2023 Konrad Brunner       New concept

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Configure-Admins-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement.Enrolment"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Configure-Admins | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking Global Administrator role
Write-Host "Checking Global Administrator role" -ForegroundColor $CommandInfo
$gaRole = Get-MgBetaRoleManagementDirectoryRoleDefinition -Filter "displayname eq 'Global Administrator'"
$gaRoleMembs = Get-MgBetaRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($gaRole.Id)'" -All -ExpandProperty Principal
Write-Host "Global Administrators:"
$gaRoleMembs
if ($gaRoleMembs.Count -gt 1)
{
    Write-Warning "We suggest to have only one single Global Administrator"
}
foreach($memb in $gaRoleMembs)
{
    $globalAdmin = Get-MgBetaUser -UserId $memb.PrincipalId
    Write-Host "$($globalAdmin.UserPrincipalName)"
    if ($globalAdmin.UserPrincipalName -like "admin@*" -or $globalAdmin.UserPrincipalName -like "administrator@*" -or `
        $globalAdmin.UserPrincipalName -like "globaladmin@*" -or $globalAdmin.UserPrincipalName -like "breakingglass@*" -or `
        $globalAdmin.UserPrincipalName -like "breaking.glass@*" -or $globalAdmin.UserPrincipalName -like "breakglass@*")
    {
        $name = -Join ([System.Security.Cryptography.HashAlgorithm]::Create("MD5").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($AlyaDomainName)) | % { $_.ToString("x2") } )
        $AlyaGlobalAdmin = "$name@$($AlyaDomainName)"
        Write-Warning "We suggest strong names for Global Administrators"
        Write-Warning "Example: $AlyaGlobalAdmin"
    }
}

# Checking breaking glass admin
Write-Host "Checking breaking glass admin $AlyaBreakingGlassUserName" -ForegroundColor $CommandInfo
if ($null -eq $AlyaBreakingGlassUserName -or $AlyaBreakingGlassUserName -eq "PleaseSpecify")
{
    Write-Error "Please specify the breaking glass admin in ConfigureEnv.ps1!"
    exit 1
}
else
{
    $bgAdmin = $null
    try {
        $bgAdmin = Get-MgBetaUser -UserId $AlyaBreakingGlassUserName
    } catch {}
    if (-Not $bgAdmin)
    {
        Write-Host "  Breaking glass account not found. Creating it now."
        $PasswordProfile = @{
            Password = Get-Password -length 36
            ForceChangePasswordNextSignIn = $false
            ForceChangePasswordNextSignInWithMfa = $false
        }
        $bgAdmin = New-MgBetaUser -DisplayName 'John Doe' -PasswordProfile $PasswordProfile -AccountEnabled -MailNickName $AlyaBreakingGlassUserName.Substring(0, $AlyaBreakingGlassUserName.IndexOf("@")) -UserPrincipalName $AlyaBreakingGlassUserName
    }
    else
    {
        Write-Host "  Breaking glass account already exists"
    }
}

# Checking Privileged Role Administrator role
Write-Host "Checking Privileged Role Administrator role" -ForegroundColor $CommandInfo
$paRole = Get-MgBetaRoleManagementDirectoryRoleDefinition -Filter "displayname eq 'Privileged Role Administrator'"
$paRoleMembs = Get-MgBetaRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($paRole.Id)'" -All -ExpandProperty Principal
Write-Host "Privileged Role Administrators:"
$paRoleMembs
if ($paRoleMembs.Count -eq 0)
{
    Write-Warning "We suggest to specify at least one Privileged Role Administrator. Ideally the breaking glass account."
    Write-Warning "He will be able to solve Global Administrator rights if something goes wrong"
}

#Stopping Transscript
Stop-Transcript
