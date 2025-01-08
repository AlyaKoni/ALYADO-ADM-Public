#Requires -Version 7.0

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
    22.12.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string[]] [Parameter(Mandatory=$true)]
    $membersToAdd
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Add-MembersToAllSites-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell" # TODO Remove when null pointer bug is fixed

# Login
#Set-PnPTraceLog -On -WriteToConsole -Level Debug -AutoFlush $true
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Add-MembersToAllSites | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting site collections
Write-Host "Getting site collections" -ForegroundColor $CommandInfo
$retries = 10
do
{
    try
    {
        $sitesToProcess = Get-PnPTenantSite -Connection $adminCon -Detailed
        break
    }
    catch
    {
        Write-Error $_.Exception -ErrorAction Continue
        Write-Warning "Retrying $retries times"
        Start-Sleep -Seconds 15
        $retries--
        if ($retries -lt 0) { throw }
    }
} while ($true)

# Processing site collections
foreach($site in $sitesToProcess)
{
    if ($site.Template -like "Redirect*") { continue }
    if (-Not $site.Url.Contains("/sites/") -And $site.Url.TrimEnd("/") -ne $AlyaSharePointUrl.TrimEnd("/")) { continue }
    Write-Host "$($site.Url)"
    $siteCon = LoginTo-PnP -Url $site.Url

    # Checking connected group
    if ($site.GroupId.Guid -and [Guid]::Empty -ne $site.GroupId.Guid)
    {
        Write-Host "Found site group $($site.GroupId.Guid)"
        try
        {
            $grp = Get-PnPMicrosoft365Group -Connection $siteCon -Identity $site.GroupId.Guid
            if ([string]::IsNullOrEmpty($grp.MembershipRule))
            {
                Add-PnPMicrosoft365GroupMember -Connection $siteCon -Identity $site.GroupId.Guid -Users $membersToAdd
            }
        }
        catch
        {
            Write-Warning "Error adding members: $($_.Exception.Message)"
        }
    }
    else
    {
        Write-Host "No site group found"
        $grp = Get-PnPGroup -Connection $siteCon -AssociatedMemberGroup
        foreach($member in $membersToAdd)
        {
            try
            {
                Add-PnPGroupMember -Connection $siteCon -Group $grp -LoginName $member
            }
            catch
            {
                Write-Warning "Error adding members: $($_.Exception.Message)"
            }
        }
    }
}

# Stopping Transscript
Stop-Transcript
