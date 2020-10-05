#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2019, 2020

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
    13.09.2020 Konrad Brunner       Initial version
#>

[CmdletBinding()]
Param(
    $UPN1 = "first1.last1@alyaconsulting.ch",
    $UPN2 = "first2.last2@alyaconsulting.ch"
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\onprem\Compair-Users-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Check-Module ActiveDirectory
#Import-Module "ActiveDirectory" -ErrorAction Stop

# =============================================================
# AD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AD | Compair-Users | ONPREMISES" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
$user1 = Get-ADUser -Filter {UserPrincipalName -eq $UPN1} -Properties *
$user2 = Get-ADUser -Filter {UserPrincipalName -eq $UPN2} -Properties *

$user1Groups = $user1 | Select-Object -Property MemberOf -ExpandProperty MemberOf
$user2Groups = $user2 | Select-Object -Property MemberOf -ExpandProperty MemberOf

$user1Accesses = (Get-ACL "AD:$($user1.distinguishedname)").access
$user2Accesses = (Get-ACL "AD:$($user2.distinguishedname)").access

$UserComparison = @()
$user1.GetEnumerator() | ForEach-Object {
    If ([string]$User2.($_.Key) -eq [string]$_.Value)
    {
        $Comparison = 'Equal'
    }
    else
    {
        $Comparison = 'Different'
    }

    $UserObj = New-Object PSObject -Property ([ordered]@{
        Property = $_.Key
        User1 = [string]$_.Value
        User2 = [string]$User2.($_.Key)
        Comparison = $Comparison
    })
    $UserComparison += $UserObj
}

$UserAccessComparison = @()
foreach($user1Access in $user1Accesses)
{
    $fnd = $false
    foreach($user2Access in $user2Accesses)
    {
        if ($user1Access.IdentityReference -eq $user2Access.IdentityReference -and 
            $user1Access.ObjectType -eq $user2Access.ObjectType -and 
            $user1Access.ActiveDirectoryRights -eq $user2Access.ActiveDirectoryRights -and 
            $user1Access.AccessControlType -eq $user2Access.AccessControlType -and 
            $user1Access.InheritanceType -eq $user2Access.InheritanceType -and 
            $user1Access.InheritanceFlags -eq $user2Access.InheritanceFlags)
        {
            $fnd = $true
        }
    }
    if (-not $fnd)
    {
        Write-Host "Different:"
        $user1Access
    }
}

cls
$UserComparison | where { $_.Comparison -eq "Different" } | fl


#Stopping Transscript
Stop-Transcript