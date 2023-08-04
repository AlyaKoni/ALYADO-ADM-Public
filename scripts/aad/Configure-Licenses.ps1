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
    21.09.2020 Konrad Brunner       Initial Version
    16.12.2020 Konrad Brunner       Fixed bug, not removing users from groups
    19.10.2021 Konrad Brunner       Changed LIC group names
    15.11.2021 Konrad Brunner       Fixed not existing group
    21.04.2023 Konrad Brunner       Switched to Graph, removed AzureAdPreview
    03.08.2023 Konrad Brunner       Processing groups and users if useDirectAssignment

#>

[CmdletBinding()]
Param(
    [string]$inputFile = $null, #Defaults to "$AlyaData\aad\Lizenzen.xlsx"
    [bool]$useDirectAssignment = $false,
    [string]$groupsInputFileForDirectAssignment = $null #Defaults to "$AlyaData\aad\Gruppen.xlsx"
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
if (-Not $groupsInputFileForDirectAssignment)
{
    $groupsInputFileForDirectAssignment = "$AlyaData\aad\Gruppen.xlsx"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users.Actions"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"
Install-ModuleIfNotInstalled "ImportExcel"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Configure-Licenses | Graph" -ForegroundColor $CommandInfo
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
$licDefs | Foreach-Object {
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
                $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$grpName'"
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
            $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$grpName'"
            $byGroup.$grpName.Id = $exGrp.Id
        }
    }
}

if (-Not $useDirectAssignment -and $fndMissingGroup)
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
        $members = Get-MgBetaGroupMember -GroupId $byGroup[$group].Id
        foreach ($member in $members)
        {
            if (-Not $byGroup[$group].Users.Contains($member.AdditionalProperties.userPrincipalName))
            {
                #Remove member
                Write-Host "    Removing member '$($member.AdditionalProperties.userPrincipalName)'"
                Remove-MgBetaGroupMemberByRef -GroupId $byGroup[$group].Id -DirectoryObjectId $member.Id
            }
        }
        foreach ($user in $byGroup[$group].Users)
        {
            $fnd = $false
            foreach ($member in $members)
            {
                if ($member.AdditionalProperties.userPrincipalName -eq $user)
                {
                    $fnd = $true
                }
            }
            if (-Not $fnd)
            {
                #Adding member
                Write-Host "    Adding member '$user'"
                $adUser = Get-MgBetaUser -UserId $user
                if (-Not $adUser)
                {
                    Write-Warning "     Member '$user' not found in AAD"
                }
                else
                {
                    New-MgBetaGroupMember -GroupId $byGroup[$group].Id -DirectoryObjectId $adUser.Id
                }
            }
        }
    }
}

if ($useDirectAssignment)
{
    
    # Reading groups file
    Write-Host "Reading groups file from '$groupsInputFileForDirectAssignment" -ForegroundColor $CommandInfo
    if (-Not (Test-Path $groupsInputFileForDirectAssignment))
    {
        throw "Groups file '$groupsInputFileForDirectAssignment' not found!"
    }
    $AllGroups = Import-Excel $groupsInputFileForDirectAssignment -WorksheetName "Gruppen" -ErrorAction Stop

    # Syncing licensed users with direct access
    Write-Host "Syncing licensed users with direct access" -ForegroundColor $CommandInfo

    $assignedLicenses = @{}
    foreach ($group in $byGroup.Keys)
    {
        Write-Host "  Group '$group'"
        if ($byGroup[$group] -ne $null -and $byGroup[$group].Id -ne $null)
        {
            $groupDef = $AllGroups | Where-Object { $_.DisplayName -eq $group }
            foreach ($user in $byGroup[$group].Users)
            {
                Write-Host "    User '$user'"
                $adUser = Get-MgBetaUser -UserId $user
                if ($null -eq $assignedLicenses."$($user)")
                {
                    $assignedLicenses."$($user)" = [System.Collections.ArrayList]@()
                }
                $userLics = $assignedLicenses."$($user)"
                $licDets = Get-MgBetaUserLicenseDetail -UserId $adUser.Id
                foreach($lic in $groupDef.Licenses)
                {
                    if (-Not $userLics.Contains($lic)) { $userLics.Add($lic) | Out-Null }
                    if ($licDets.SkuPartNumber -notcontains $lic)
                    {
                        Write-Host "      Adding license '$lic'"
                        $Sku = Get-MgBetaSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq $lic }
                        Set-MgBetaUserLicense -UserId $adUser.Id -AddLicenses @{SkuId = $Sku.SkuId} -RemoveLicenses @() | Out-Null
                    }
                }
            }
        }
    }

    # Removing not configured licenses
    Write-Host "Removing not configured licenses" -ForegroundColor $CommandInfo

    foreach ($assLic in $assignedLicenses.GetEnumerator())
    {
        $adUser = Get-MgBetaUser -UserId $assLic.Name
        Write-Host "  User '$($assLic.Name)'"
        $userLics = $assignedLicenses."$($assLic.Name)"
        $licDets = Get-MgBetaUserLicenseDetail -UserId $adUser.Id
        foreach($lic in $licDets.SkuPartNumber)
        {
            if (-Not $userLics.Contains($lic))
            {
                Write-Host "    Removing license '$lic'"
                $Sku = Get-MgBetaSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq $lic }
                Set-MgBetaUserLicense -UserId $adUser.Id -AddLicenses @() -RemoveLicenses @($Sku.SkuId) | Out-Null
            }
        }
    }

}

#Stopping Transscript
Stop-Transcript
