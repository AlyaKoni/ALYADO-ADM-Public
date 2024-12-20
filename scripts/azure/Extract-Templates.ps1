﻿#Requires -Version 2.0

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
    02.03.2020 Konrad Brunner       Initial Version
    07.01.2021 Konrad Brunner       Fixed file extension (.json)

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Extract-Templates-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Azure | Extract-Templates | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Exporting all resourcegroup templates
Write-Host "Exporting all resourcegroup templates" -ForegroundColor $CommandInfo
$TemplateRoot = "$($AlyaData)\azure\templates"
Write-Host "  to $($TemplateRoot)" -ForegroundColor $CommandInfo
if (-Not (Test-Path -Path $TemplateRoot -PathType Container))
{
    New-Item -Path $TemplateRoot -ItemType Directory -Force | Out-Null
}
Push-Location -Path $TemplateRoot

foreach ($AlyaSubscriptionName in ($AlyaAllSubscriptions | Select-Object -Unique))
{
    $sub = Get-AzSubscription -SubscriptionName $AlyaSubscriptionName -TenantId $AlyaTenantId -ErrorAction SilentlyContinue
    if ($sub)
    {
        Select-AzSubscription -SubscriptionObject $sub -Force
        $grps = Get-AzResourceGroup
        foreach($grp in $grps)
        {
            Write-Host "Exporting ressource group $($grp.ResourceId) from subscription $($AlyaSubscriptionName)"
            $fileName = ($grp.ResourceId -replace "/", "_") + ".json"
            try
            {
                Export-AzResourceGroup -ResourceGroupName $grp.ResourceGroupName -Path . -IncludeParameterDefaultValue -IncludeComments -Pre -Force
                Move-Item -Path ($grp.ResourceGroupName + ".json") -Destination ($AlyaSubscriptionName + "_" + $grp.ResourceGroupName + ".json") -Force
            }
            catch
            {
                Write-Error $_.Exception -ErrorAction SilentlyContinue
            }
        }
    } else
    {
        Write-Warning "Can't find subscription with name $($AlyaSubscriptionName)"
    }
}

Pop-Location

#Stopping Transscript
Stop-Transcript
