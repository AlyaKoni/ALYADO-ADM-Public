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
    03.09.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Get-IntunePowershellSamples-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$CloneUrl = "https://github.com/microsoftgraph/powershell-intune-samples.git"

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Get-IntunePowershellSamples | Local" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Checking git installation" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$AlyaGitRoot"))
{
    Write-Host "Downloading git"
    $req = Invoke-WebRequestIndep -Uri $AlyaGitDownload -UseBasicParsing -Method Get
    [regex]$regex = "[^`"]*windows[^`"]*portable[^`"]*64[^`"]*.exe"
    $url = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
    $req = Invoke-WebRequestIndep -Uri $url -Method Get -OutFile ".\PortableGit64bit.exe"
    Write-Host "Installing git"
    cmd /c ".\PortableGit64bit.exe" "-o`"$AlyaGitRoot`"".Split(" ") -y
    do
    {
        Start-Sleep -Seconds 5
    } while (Get-Process -Name "PortableGit64bit" -ErrorAction SilentlyContinue)
    Remove-Item -Path ".\PortableGit64bit.exe" -Force
}

Write-Host "Checking user email" -ForegroundColor $CommandInfo
if ([string]::IsNullOrEmpty($AlyaLocalConfig.user.email))
{
    $email = Read-Host -Prompt 'Please specify your email address'
    $decision = $Host.UI.PromptForChoice("Confirm your email", "Is '$($email)' correct?", @("&Yes", "&No"), 0)
    if ($decision -eq 0) {
        $AlyaLocalConfig.user.email = $email
        Save-LocalConfig
    } else {
        Write-Host 'Cancelled'
        exit
    }
}

Write-Host "Checking connection" -ForegroundColor $CommandInfo #Adding host to known_hosts
$devopsHost = ([System.Uri]$CloneUrl).Authority
if (-Not $devopsHost)
{
    $devopsHost = $CloneUrl.Substring($CloneUrl.IndexOf("@")+1,$CloneUrl.IndexOf(":")-$CloneUrl.IndexOf("@")-1)
}
$proc = New-Object System.Diagnostics.Process
$proc.StartInfo.FileName = "$AlyaGitRoot\usr\bin\ssh.exe"
$proc.StartInfo.Arguments = "-T $devopsHost -o `"StrictHostKeyChecking no`"".Split(" ")
$proc.StartInfo.UseShellExecute = $false
$proc.StartInfo.CreateNoWindow = $true
$proc.Start()

#Getting repository
Write-Host "Cloning" -ForegroundColor $CommandInfo
$RepRoot = Join-Path ( Join-Path (Join-Path $AlyaRoot "tools") "powershell") "IntunePowershellSamples"
if ((Test-Path $RepRoot))
{
    $null = Remove-Item -Path $RepRoot -Recurse -Force
}
$null = New-Item -Path $RepRoot -ItemType Directory -Force
cmd /c "$AlyaGitRoot\cmd\git.exe" clone "$CloneUrl" "$RepRoot" -q
Wait-UntilProcessEnds -processName "git"

Write-Host "IntunePowershellSamples installed to $RepRoot" -ForegroundColor $CommandSuccess

#Stopping Transscript
Stop-Transcript
