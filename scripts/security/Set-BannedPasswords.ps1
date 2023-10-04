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
    22.04.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$bannedPasswordFile = $null # Defaults to $AlyaScripts\security\CustomBannedPasswordList.txt
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Set-BannedPasswords-$($AlyaTimeString).log" | Out-Null

# Constants
if (-Not $bannedPasswordFile)
{
    $bannedPasswordFile = "$AlyaScripts\security\CustomBannedPasswordList.txt"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"
    
# Logins
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Groups | Set-BannedPasswords | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking banned Password File
Write-Host "Checking banned Password File $bannedPasswordFile" -ForegroundColor $CommandInfo
if (-Not (Test-Path $bannedPasswordFile)) {
    throw "Please prepare the banned password file $bannedPasswordFile"
}
else {
    Write-Host "Using banned password file $bannedPasswordFile"
}
$bannedPasswords = Get-Content -Path $bannedPasswordFile -Encoding $AlyaUtf8Encoding -Raw

# Configuring settings template
Write-Host "Configuring settings template" -ForegroundColor $CommandInfo
$SettingTemplate = Get-MgBetaDirectorySettingTemplate | Where-Object { $_.DisplayName -eq "Password Rule Settings" }
$Setting = Get-MgBetaDirectorySetting | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
if (-Not $Setting)
{
    Write-Warning "Setting not yet created. Creating one based on template."
    $Values = @()
    foreach($dval in $SettingTemplate.Values) {
	    $Values += @{Name = $dval.Name; Value = $dval.DefaultValue}
    }
    $Setting = New-MgBetaDirectorySetting -DisplayName "Password Rule Settings" -TemplateId $SettingTemplate.Id -Values $Values
    $Setting = Get-MgBetaDirectorySetting | Where-Object { $_.TemplateId -eq $SettingTemplate.Id }
}

$Value = $Setting.Values | Where-Object { $_.Name -eq "EnableBannedPasswordCheck" }
if ($Value.Value -eq $true) {
    Write-Host "Setting 'EnableBannedPasswordCheck' was already set to '$true'"
} 
else {
    Write-Warning "Setting 'EnableBannedPasswordCheck' was set to '$($Value.Value)' updating to '$true'"
    ($Setting.Values | Where-Object { $_.Name -eq "EnableBannedPasswordCheck" }).Value = $true
}

$Value = $Setting.Values | Where-Object { $_.Name -eq "EnableBannedPasswordCheckOnPremises" }
if ($Value.Value -eq $true) {
    Write-Host "Setting 'EnableBannedPasswordCheckOnPremises' was already set to '$true'"
} 
else {
    Write-Warning "Setting 'EnableBannedPasswordCheckOnPremises' was set to '$($Value.Value)' updating to '$true'"
    ($Setting.Values | Where-Object { $_.Name -eq "EnableBannedPasswordCheckOnPremises" }).Value = $true
}

if ($AlyaCompanyNameShort.Length -gt 3) { $bannedPasswords = $AlyaCompanyNameShort + "`r`n" + $bannedPasswords }
if ($AlyaTenantName.Length -gt 16) { $bannedPasswords = $AlyaTenantName.Substring(0,16) + "`r`n" + $bannedPasswords } else { $bannedPasswords = $AlyaTenantName + "`r`n" + $bannedPasswords }
if ($AlyaCompanyName.Length -gt 16) { $bannedPasswords = $AlyaCompanyName.Substring(0,16) + "`r`n" + $bannedPasswords } else { $bannedPasswords = $AlyaCompanyName + "`r`n" + $bannedPasswords }
foreach($tok in ($AlyaCompanyNameFull -split "[\s\.,-]"))
{
    if ($tok.Length -gt 3 -and $tok.Length -lt 16) { $bannedPasswords = $tok + "`r`n" + $bannedPasswords }
}
if ($AlyaCompanyNameFull.Length -gt 16) { $bannedPasswords = $AlyaCompanyNameFull.Substring(0,16) + "`r`n" + $bannedPasswords } else { $bannedPasswords = $AlyaCompanyNameFull + "`r`n" + $bannedPasswords }
if ($AlyaDomainName.Length -gt 16) { $bannedPasswords = $AlyaDomainName.Substring(0,16) + "`r`n" + $bannedPasswords } else { $bannedPasswords = $AlyaDomainName + "`r`n" + $bannedPasswords }

Write-Warning "Setting 'BannedPasswordList' to content from banned password file'"
($Setting.Values | Where-Object { $_.Name -eq "BannedPasswordList" }).Value = $bannedPasswords

Update-MgBetaDirectorySetting -DirectorySettingId $Setting.Id -Values $Setting.Values

#Stopping Transscript
Stop-Transcript
