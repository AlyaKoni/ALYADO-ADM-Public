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
    16.10.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNull()]
    [string]$userUpn,
    [Parameter(Mandatory = $true)]
    [ValidateNotNull()]
    [string]$password,
    [bool]$changePasswordNextLogon = $true,
    [bool]$passwordNeverExpires = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Set-UserPassword-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users.Actions"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @("Directory.ReadWrite.All","UserAuthenticationMethod.ReadWrite.All","Directory.AccessAsUser.All")

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Set-UserPassword | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Getting user" -ForegroundColor $CommandInfo
$user = Get-MgBetaUser -UserId $userUpn -Property Id, UserPrincipalName, PasswordPolicies
if ($user) {
    
    Write-Host "Resetting password" -ForegroundColor $CommandInfo
    $mthd = Get-MgBetaUserAuthenticationPasswordMethod -UserId $userUpn
    Reset-MgBetaUserAuthenticationMethodPassword -UserId $userUpn -AuthenticationMethodId $mthd.id -NewPassword $password
    
    $policies = $null
    if ($user.PasswordPolicies -ne "None") {
        $policies = $user.PasswordPolicies
    }
    if ($passwordNeverExpires){
        Write-Host "Disabling password expiration" -ForegroundColor $CommandInfo
        if ($null -ne $policies) {
            if (-Not $policies.Contains("DisablePasswordExpiration")){
                $policies = "$policies, DisablePasswordExpiration"
            }
        } else {
            $policies = "DisablePasswordExpiration"
        }
    } else {
        Write-Host "Enabling password expiration" -ForegroundColor $CommandInfo
        if ($null -ne $policies) {
            if ($policies.Contains("DisablePasswordExpiration")){
                $policies = $policies.Replace(",DisablePasswordExpiration", "").Replace(", DisablePasswordExpiration", "").Replace("DisablePasswordExpiration,", "").Trim()
            }
        }
    }
    Update-MgBetaUser -UserId $userUpn -PasswordPolicies $policies

    Write-Host "Setting change password at next logon to $changePasswordNextLogon" -ForegroundColor $CommandInfo
    $passwordProfile = @{
        ForceChangePasswordNextSignIn = $changePasswordNextLogon
    }
    Update-MgBetaUser -UserId $userUpn -PasswordProfile $passwordProfile

}
else
{
    Write-Error "User does not exist"
}

#Stopping Transscript
Stop-Transcript
