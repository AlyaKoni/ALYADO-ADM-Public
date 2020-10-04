#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2019, 2020

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
    06.11.2019 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\GitClone-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

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

Write-Host "Checking ssh keys" -ForegroundColor $CommandInfo
if ([string]::IsNullOrEmpty($AlyaLocalConfig.user.ssh))
{
    Write-Host "Generating new ssh key pair"
    if (-Not (Test-Path "$AlyaRoot\_local\ssh"))
    {
        $tmp = New-Item -Path "$AlyaRoot\_local\ssh" -ItemType Directory -Force
        $sshPath = [System.Environment]::ExpandEnvironmentVariables("%USERPROFILE%\.ssh")
        if (Test-Path $sshPath)
        {
            $sshPath += "\id_rsa"
            if (Test-Path $sshPath)
            {
                $decision = $Host.UI.PromptForChoice("SSH Keys", "Use existing SSH keys from your userprofile?", @("&Yes", "&No"), 0)
                if ($decision -eq 0)
                {
                    Copy-Item -Path $sshPath -Destination "$($AlyaRoot)\_local\ssh\id_rsa"
                    Copy-Item -Path "$($sshPath).pub" -Destination "$($AlyaRoot)\_local\ssh\id_rsa.pub"
                }

            }
        }
    }
    if (-Not (Test-Path "$($AlyaRoot)\_local\ssh\id_rsa"))
    {
        & "$GitRoot\usr\bin\ssh-keygen.exe" "-q -t rsa -b 1024 -f `"$($AlyaRoot)\_local\ssh\id_rsa`" -N `"`" -C `"$($AlyaLocalConfig.user.email)`"".Split(" ")
        if (-Not (Test-Path "$($AlyaRoot)\_local\ssh\id_rsa"))
        {
            Write-Error "Error generating id_rsa" -ErrorAction Continue
            exit 1
        }
    }
    $AlyaLocalConfig.user.ssh = "$AlyaRoot\_local\ssh\id_rsa"
    Save-LocalConfig
    Write-Host "Please upload the following ssh key to DevOps and hit enter:" -ForegroundColor Red
    Get-Content -Path "$($AlyaLocalConfig.user.ssh).pub"
    $tmp = Read-Host -Prompt 'Please press enter'
}

Write-Host "Checking devops url" -ForegroundColor $CommandInfo
if ([string]::IsNullOrEmpty($AlyaGlobalConfig.source.devops))
{
    $devopsssh = Read-Host -Prompt 'Please specify devops ssh uri'
    $decision = $Host.UI.PromptForChoice("Confirm devops ssh uri", "Is '$($devopsssh)' correct?", @("&Yes", "&No"), 0)
    if ($decision -eq 0) {
        $AlyaGlobalConfig.source.devops = $devopsssh
        Save-GlobalConfig
    } else {
        Write-Host 'Cancelled'
        exit
    }
}

Write-Host "Checking .ssh content" -ForegroundColor $CommandInfo
$sshPath = [System.Environment]::ExpandEnvironmentVariables("%USERPROFILE%\.ssh")
if (-Not (Test-Path $sshPath))
{
    $tmp = New-Item -Path $sshPath -ItemType Directory -Force
}
#Checking kex in config
$sshConfigPath = $sshPath + "\config"
$kexMissing = $true
$devopsHost = ([System.Uri]$AlyaGlobalConfig.source.devops).Authority
if (-Not $devopsHost)
{
    $devopsHost = $AlyaGlobalConfig.source.devops.Substring($AlyaGlobalConfig.source.devops.IndexOf("@")+1,$AlyaGlobalConfig.source.devops.IndexOf(":")-$AlyaGlobalConfig.source.devops.IndexOf("@")-1)
}
if ((Test-Path $sshConfigPath))
{
    $kexCont = Get-Content -Path $sshConfigPath -Raw
    if ($kexCont.IndexOf($devopsHost) -gt -1)
    {
        $kexMissing = $false
    }
}
if ($kexMissing)
{
    Write-Host "Fixing DevOps Kex issue" -ForegroundColor $CommandInfo
    "Host $($devopsHost)`nKexAlgorithms +diffie-hellman-group1-sha1" | Add-Content -Path $sshConfigPath
}
#check keys
$sshPath += "\id_rsa"
if (-Not (Test-Path $sshPath))
{
    Copy-Item -Path "$($AlyaLocalConfig.user.ssh)" -Destination $sshPath
    Copy-Item -Path "$($AlyaLocalConfig.user.ssh).pub" -Destination "$($sshPath).pub"
}
else
{
    if ((Get-FileHash "$($AlyaLocalConfig.user.ssh)").Hash -ne (Get-FileHash $sshPath).Hash)
    {
        Write-Host "Old key pair found in $sshPath"
        $decision = $Host.UI.PromptForChoice("Overwrite?", "Do you want to overwrite the existing file?", @("&Yes", "&No"), 0)
        if ($decision -eq 0) {
            Copy-Item -Path "$($AlyaLocalConfig.user.ssh)" -Destination $sshPath -Force
            Copy-Item -Path "$($AlyaLocalConfig.user.ssh).pub" -Destination "$($sshPath).pub" -Force
        } else {
            Write-Host "Please backup existing files in $($sshPath) and rerun this script"
            exit
        }
    }
}

Write-Host "Checking connection" -ForegroundColor $CommandInfo #Adding host to known_hosts
$devopsHost = ([System.Uri]$AlyaGlobalConfig.source.devops).Authority
if (-Not $devopsHost)
{
    $devopsHost = $AlyaGlobalConfig.source.devops.Substring($AlyaGlobalConfig.source.devops.IndexOf("@")+1,$AlyaGlobalConfig.source.devops.IndexOf(":")-$AlyaGlobalConfig.source.devops.IndexOf("@")-1)
}
$proc = New-Object System.Diagnostics.Process
$proc.StartInfo.FileName = "$GitRoot\usr\bin\ssh.exe"
$proc.StartInfo.Arguments = "-T $devopsHost -o `"StrictHostKeyChecking no`"".Split(" ")
$proc.StartInfo.UseShellExecute = $false
$proc.StartInfo.CreateNoWindow = $true
$proc.Start()

Write-Host "Fetching repository " -ForegroundColor $CommandInfo
Push-Location
$errAct = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
try {
    Set-Location "$($AlyaRoot)"
    Write-Host "connecting actual directory to git repository"
    $check = (& "$GitRoot\cmd\git.exe" status)
    if ($check -like "*On branch *") {
        & "$GitRoot\cmd\git.exe" status
        Write-Host "Repository is already connected!" -ForegroundColor $CommandSuccess
        Write-Host "Fetching changes"
        & "$GitRoot\cmd\git.exe" fetch
        Wait-UntilProcessEnds -processName "git"
    }
    else {
        Write-Host "Repository is not yet connected. Connecting..."
        & "$GitRoot\cmd\git.exe" init
        Wait-UntilProcessEnds -processName "git"
        Write-Host "To: $($AlyaGlobalConfig.source.devops)"
        & "$GitRoot\cmd\git.exe" "remote add origin $($AlyaGlobalConfig.source.devops)".Split(" ")
        Wait-UntilProcessEnds -processName "git"
        Write-Host "Fetching changes"
        & "$GitRoot\cmd\git.exe" fetch
        Wait-UntilProcessEnds -processName "git"
        Write-Host "Checking out"
        & "$GitRoot\cmd\git.exe" "checkout -t origin/master --force".Split(" ")
        Wait-UntilProcessEnds -processName "git"
        & "$GitRoot\cmd\git.exe" status
        Write-Host "Repository now connected!" -ForegroundColor $CommandSuccess
    }
}
finally {
    Pop-Location
    $ErrorActionPreference = $errAct
}

# Stopping Transscript
Stop-Transcript
