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
    21.09.2020 Konrad Brunner       Initial Version
    16.12.2020 Konrad Brunner       Fixed bug, not removing users from groups
    19.10.2021 Konrad Brunner       Changed LIC group names
    15.11.2021 Konrad Brunner       Fixed not existing group

#>

[CmdletBinding()]
Param(
    [string]$inputFile = $null #Defaults to "$AlyaData\aad\Lizenzen.xlsx"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Configure-Licenses-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $inputFile)
{
    $inputFile = "$AlyaData\aad\Lizenzen.xlsx"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "AzureAdPreview"
Install-ModuleIfNotInstalled "ImportExcel"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Configure-Licenses | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Reading input file
Write-Host "Reading input file from '$inputFile'" -ForegroundColor $CommandInfo
if (-Not (Test-Path $inputFile))
{
    throw "Input file not found!"
}
$licDefs = Import-Excel $inputFile -ErrorAction Stop

# Configured licenses
Write-Host "Configured licenses:" -ForegroundColor $CommandInfo
$licNames = $null
$fndMissingGroup = $false
$byGroup = @{}
$licDefs | foreach {
    $licDef = $_
    if ($licDef.Name -like "User*")
    {
        $licNames = $licDef
    }
    if ($licDef.Name -like "*@*")
    {
        $outStr = " - $($licDef.Name): "
        for ($i = 1; $i -le 40; $i++)
        {
            $propName = "Lic"+$i
            if ($licDef.$propName -eq 1)
            {
                $outStr += "$($licNames.$propName),"

                $grpName = $AlyaCompanyNameShort.ToUpper() + "SG-LIC-" + $licNames.$propName
                if (-Not $byGroup.$grpName) {
                    $byGroup.$grpName = @{}
                    $byGroup.$grpName.Users = @()
                }
                $byGroup.$grpName.Users += $licDef.Name
                $exGrp = Get-AzureADMSGroup -SearchString $grpName
                if ($exGrp.Count -gt 1)
                {
                    foreach($grp in $exGrp)
                    {
                        if ($grp.DisplayName -eq $secGroup.DisplayName)
                        {
                            $exGrp = $grp
                            break
                        }
                    }
                }
                if (-Not $exGrp)
                {
                    Write-Warning "  Please add missing group $($grpName)"
                    $fndMissingGroup = $true
                }
                $byGroup.$grpName.Id = $exGrp.Id
            }
        }
        Write-Host $outStr.TrimEnd(",")
    }
}
for ($i = 1; $i -le 40; $i++)
{
    $propName = "Lic"+$i
    if ($licNames.$propName)
    {
        $grpName = $AlyaCompanyNameShort.ToUpper() + "SG-LIC-" + $licNames.$propName
        if (-Not $byGroup.$grpName) {
            $byGroup.$grpName = @{}
            $byGroup.$grpName.Users = @()
            $exGrp = Get-AzureADMSGroup -SearchString $grpName
            if ($exGrp.Count -gt 1)
            {
                foreach($grp in $exGrp)
                {
                    if ($grp.DisplayName -eq $secGroup.DisplayName)
                    {
                        $exGrp = $grp
                        break
                    }
                }
            }
            $byGroup.$grpName.Id = $exGrp.Id
        }
    }
}

if ($fndMissingGroup)
{
    Write-Error "Found missing groups. Please add them to data\ad\Groups.xlsx and run Configure-Groups.ps1" -ErrorAction Continue
    exit
}

# Syncing licensed users with license groups
Write-Host "Syncing licensed users with license groups" -ForegroundColor $CommandInfo
foreach ($group in $byGroup.Keys)
{
    Write-Host "  Group '$group'"
    if ($byGroup[$group] -ne $null -and $byGroup[$group].Id -ne $null)
    {
        $members = Get-AzureADGroupMember -ObjectId $byGroup[$group].Id
        foreach ($member in $members)
        {
            if (-Not $byGroup[$group].Users.Contains($member.UserPrincipalName))
            {
                #Remove member
                Write-Host "    Removing member '$($member.UserPrincipalName)'"
                Remove-AzureADGroupMember -ObjectId $byGroup[$group].Id -MemberId $member.ObjectId
            }
        }
        foreach ($user in $byGroup[$group].Users)
        {
            $fnd = $false
            foreach ($member in $members)
            {
                if ($member.UserPrincipalName -eq $user)
                {
                    $fnd = $true
                }
            }
            if (-Not $fnd)
            {
                #Adding member
                Write-Host "    Adding member '$user'"
                $adUser = Get-AzureADUser -ObjectId $user -ErrorAction SilentlyContinue
                if (-Not $adUser)
                {
                    Write-Warning "     Member '$user' not found in AAD"
                }
                else
                {
                    Add-AzureADGroupMember -ObjectId $byGroup[$group].Id -RefObjectId $adUser.ObjectId
                }
            }
        }
    }
}

#Stopping Transscript
Stop-Transcript