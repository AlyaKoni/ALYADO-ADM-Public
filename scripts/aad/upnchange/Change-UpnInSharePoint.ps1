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
    14.09.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    $oldUPN = "konradbrunner@alyaconsulting.ch",
    $newUPN = "konrad.brunner@alyaconsulting.ch",
    $webApplications = @("https://webapp1.alyaconsulting.ch","https://webapp2.alyaconsulting.ch")
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Reading configuration
Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\upnchange\Change-UpnInSharePoint-$($AlyaTimeString).log" | Out-Null

# =============================================================
# SHAREPOINT stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "UPNCHANGE | Change-UpnInSharePoint | SHAREPOINT" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
$webApplications | Foreach-Object {
    $webApplication = $_
    Write-Host "WebApplication: $($webApplication)"
    $sites = Get-SPSite -WebApplication $webApplication -Limit all
    $sites | Foreach-Object {
        $site = $_
        Write-Host " Site: $($site.Url)"
        $someFound = $false
        $webs = Get-SPWeb -Site $site -Limit all
        $webs | Foreach-Object {
            $web = $_
            Write-Host "  Web: $($web.Url)"
            $users = Get-SPUser -Web $web -Limit ALL
            $oldUser = $null
            $newUser = $null
            $users | Foreach-Object {
                $user = $_
                if ($user.UserLogin -like "*$($oldUPN)*")
                {
                    $oldUser = $user
                }
                if ($user.UserLogin -like "*$($newUPN)*")
                {
                    $newUser = $user
                }
            }
            if ($oldUser -and $newUser)
            {
                Write-Host "    Both UPNs exist, removing new user"
            }
            if ($oldUser)
            {
                $newAlias = $oldUser.UserLogin.Replace($oldUPN,$newUPN)
                Write-Host "    Moving old to new UPN"
                Write-Host "     from: $($oldUser.UserLogin)"
                Write-Host "       to: $($newAlias)"
                Move-SPUser –Identity $user –NewAlias $newAlias -IgnoreSID -Confirm:$false
            }
            if ($newUser)
            {
                Write-Host "    New UPN exists"
            }
        }
    }
}

$proxy = Get-SPServiceApplicationProxy | ?{$_.TypeName -eq 'User Profile Service Application Proxy'}
Update-SPRepopulateMicroblogLMTCache -ProfileServiceApplicationProxy $proxy

#Stopping Transscript
Stop-Transcript
