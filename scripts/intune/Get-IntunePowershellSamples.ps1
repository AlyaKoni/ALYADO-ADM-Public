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

Write-Host "Checking git installation" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$GitRoot"))
{
    Write-Host "Downloading git"
    $req = Invoke-WebRequest -Uri $GitDownload -UseBasicParsing -Method Get
    [regex]$regex = "[^`"]*windows[^`"]*portable[^`"]*64[^`"]*.exe"
    $url = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
    $req = Invoke-WebRequest -Uri $url -Method Get -OutFile ".\PortableGit64bit.exe"
    Write-Host "Installing git"
    & ".\PortableGit64bit.exe" "-o`"$GitRoot`"".Split(" ") -y
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
$proc.StartInfo.FileName = "$GitRoot\usr\bin\ssh.exe"
$proc.StartInfo.Arguments = "-T $devopsHost -o `"StrictHostKeyChecking no`"".Split(" ")
$proc.StartInfo.UseShellExecute = $false
$proc.StartInfo.CreateNoWindow = $true
$proc.Start()

#Getting repository
Write-Host "Cloning" -ForegroundColor $CommandInfo
$RepRoot = Join-Path ( Join-Path (Join-Path $AlyaRoot "tools") "powershell") "IntunePowershellSamples"
if ((Test-Path $RepRoot))
{
    $tmp = Remove-Item -Path $RepRoot -Recurse -Force
}
$tmp = New-Item -Path $RepRoot -ItemType Directory -Force
& "$GitRoot\cmd\git.exe" clone "$CloneUrl" "$RepRoot" -q
Wait-UntilProcessEnds -processName "git"

Write-Host "IntunePowershellSamples installed to $RepRoot" -ForegroundColor $CommandSuccess

#Stopping Transscript
Stop-Transcript