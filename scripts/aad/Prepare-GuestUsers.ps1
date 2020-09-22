#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

    This file is part of the Alya Base Configuration.
    The Alya Base Configuration is free software: you can redistribute it
	and/or modify it under the terms of the GNU General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
	Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
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
    27.02.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Prepare-GuestUsers-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MSOnline"

# Logins
LoginTo-Msol

# Constants
$CompStart = $AlyaB2BCompStart
$CompEnd = $AlyaB2BCompEnd

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Prepare-GuestUsers | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Getting all guest accounts" -ForegroundColor $CommandInfo
$Users = Get-MsolUser -All | where { $_.UserType -eq "Guest" }

Write-Host "Checking $($Users.Count) accounts"
foreach($User in $Users)
{
    #$user = $users[20]
    Write-Host "=============================== $($user.AlternateEmailAddresses)"
    $newUser = @{disp=$User.DisplayName;first=$User.FirstName;last=$User.LastName}
    Write-Host "OLD"
    $newUser | ConvertTo-Json
    $email = $user.UserPrincipalName.Split("#")[0]
    $domain = $email.Split("_")[1]
    $domainParts = $domain.Split(".")
    $comp = Make-PascalCase($domainParts[$domainParts.Length-2])
    if ($comp -eq "Outlook") {
        $comp = "Extern"
    }
    if ($comp -eq "Hotmail") {
        $comp = "Extern"
    }
    if ($comp -eq "Gmail") {
        $comp = "Extern"
    }
    $name = $email.Split("_")[0]
    $first = $newUser.first
    $last = $newUser.last
    $skipFirstLast = $false
    if (((-Not $first) -or (-Not $last)) -and $name.IndexOf(".") -gt -1)
    {
        $first = Make-PascalCase($name.Split(".")[0])
        $uml = $first.Replace("ae", "ä").Replace("oe", "ö").Replace("ue", "ü")
        if ($newUser.disp -like "*$($uml)*")
        {
            $first = $uml
        }
        $last = Make-PascalCase($name.Split(".")[1])
        $uml = $last.Replace("ae", "ä").Replace("oe", "ö").Replace("ue", "ü")
        if ($newUser.disp -like "*$($uml)*")
        {
            $last = $uml
        }
    }
    if ((-Not $first) -and $newUser.first)
    {
        $first = $newUser.first
        $uml = $first.Replace("ae", "ä").Replace("oe", "ö").Replace("ue", "ü")
        if ($newUser.disp -like "*$($uml)*")
        {
            $first = $uml
        }
    }
    if ((-Not $last) -and $newUser.last)
    {
        $last = $newUser.last
        $uml = $last.Replace("ae", "ä").Replace("oe", "ö").Replace("ue", "ü")
        if ($newUser.disp -like "*$($uml)*")
        {
            $last = $uml
        }
    }
    if ((-Not $first) -and (-Not $last) -and (-Not [string]::IsNullOrEmpty($newUser.disp)))
    {
        $test = $newUser.disp.Split(" ")[0]
        $decision = $Host.UI.PromptForChoice("Confirm", "What is '$($test)' in '$($newUser.disp)'?", @("&First", "&Last", "&None"), 1)
        if ($decision -eq 0)
        {
            $first = $newUser.disp.Split(" ")[0]
            $last = $newUser.disp.Split(" ")[1]
        }
        if ($decision -eq 1)
        {
            $first = $newUser.disp.Split(" ")[1]
            $last = $newUser.disp.Split(" ")[0]
        }
        $skipFirstLast = $true
    }
    if ($first -and $newUser.first -ne $first)
    {
        $uml = $first.Replace("ae", "ä").Replace("oe", "ö").Replace("ue", "ü")
        if ($newUser.first -ne $uml)
        {
            $newUser.first = $first
        }
    }
    if ($last -and $newUser.last -ne $last)
    {
        $uml = $last.Replace("ae", "ä").Replace("oe", "ö").Replace("ue", "ü")
        if ($newUser.last -ne $uml)
        {
            $newUser.last = $last
        }
    }
    if ((-Not $skipFirstLast) -and ($User.FirstName -ne $newUser.first -or $User.LastName -ne $newUser.last))
    {
        $decision = $Host.UI.PromptForChoice("Confirm", "Is First='$($newUser.first)' Last='$($newUser.last)' correct?", @("&Yes", "&Swap"), 0)
        if ($decision -eq 1)
        {
            $tmp = $newUser.first
            $newUser.first = $newUser.last
            $newUser.last = $newUser.tmp
        }
    }
    $disp = $newUser.last + " " + $newUser.first + " " + $CompStart + $comp + $CompEnd
    if ($disp -and $newUser.disp -ne $disp)
    {
        $newUser.disp = $disp
    }
    Write-Host "NEW"
    $newUser | ConvertTo-Json
    
    if ($newUser.disp -ne $User.DisplayName -or $newUser.first -ne $User.FirstName -or $newUser.last -ne $User.LastName)
    {
        $decision = $Host.UI.PromptForChoice("Confirm", "Update?", @("&Yes", "&No", "&Stop"), 1)
        if ($decision -eq 2)
        {
            Return
        }
        if ($decision -eq 0)
        {
            Set-MsolUser -ObjectId $user.ObjectId -FirstName $newUser.first -LastName $newUser.last -DisplayName $newUser.disp
        }
    }
}

#Stopping Transscript
Stop-Transcript