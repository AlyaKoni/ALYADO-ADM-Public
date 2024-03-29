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
    25.01.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

$exitCode = 0
$AlyaTimeString = (Get-Date).ToString("yyyyMMddHHmmssfff")
$AlyaScriptName = Split-Path $PSCommandPath -Leaf
$AlyaScriptDir = Split-Path $PSCommandPath -Parent

function Wait-UntilProcessEnds(
    [string] [Parameter(Mandatory = $true)] $processName)
{
    $maxStartTries = 10
    $startTried = 0
    do
    {
        $prc = Get-Process -Name $processName -ErrorAction SilentlyContinue
        $startTried = $startTried + 1
        if ($startTried -gt $maxStartTries)
        {
            $prc = "Continue"
        }
    } while (-Not $prc)
    do
    {
        Start-Sleep -Seconds 5
        $prc = Get-Process -Name $processName -ErrorAction SilentlyContinue
    } while ($prc)
}

if (![System.Environment]::Is64BitProcess)
{
    Write-Host "Launching 64bit PowerShell"
    $arguments = ""
    foreach($key in $MyInvocation.BoundParameters.keys)
    {
        switch($MyInvocation.BoundParameters[$key].GetType().Name)
        {
            "SwitchParameter" {if($MyInvocation.BoundParameters[$k].IsPresent) { $arguments += "-$key " } }
            "String"          { $arguments += "-$key `"$($MyInvocation.BoundParameters[$key])`" " }
            "Int32"           { $arguments += "-$key $($MyInvocation.BoundParameters[$key]) " }
            "Boolean"         { $arguments += "-$key `$$($MyInvocation.BoundParameters[$key]) " }
        }
    }
    $sysNativePowerShell = "$($PSHOME.ToLower().Replace("syswow64", "sysnative"))\powershell.exe"
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $sysNativePowerShell
    $pinfo.Arguments = "-ex bypass -file `"$PSCommandPath`" $arguments"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.CreateNoWindow = $true
    $pinfo.UseShellExecute = $false
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $stdout = $p.StandardOutput.ReadToEnd()
    if (-Not [string]::IsNullOrEmpty($stdout)) { Write-Host $stdout }
    $stderr = $p.StandardError.ReadToEnd()
    if (-Not [string]::IsNullOrEmpty($stderr)) { Write-Error $stderr }
    $exitCode = $p.ExitCode
}
else
{
    Start-Transcript -Path "C:\ProgramData\AlyaConsulting\Logs\$($AlyaScriptName)-LocalCUS-$($AlyaTimeString).log" -Force

    try
    {
        $ErrorActionPreference = "Stop"

        # Running version
        Write-Host "Running version:"
        $versionFile = Join-Path $AlyaScriptDir "version.json"
        Get-Content -Path $versionFile -Raw -Encoding UTF8

        # Unpacking content
        $cmdTst = Get-Command -Name "Expand-Archive" -ParameterName "DestinationPath" -ErrorAction SilentlyContinue
        if ($cmdTst)
        {
            Expand-Archive -Path "$AlyaScriptDir\Content.zip" -DestinationPath "$AlyaScriptDir" -Force #AlyaAutofixed
        }
        else
        {
            Expand-Archive -Path "$AlyaScriptDir\Content.zip" -OutputPath "$AlyaScriptDir" -Force #AlyaAutofixed
        }
        $dubsSourceRoot = Join-Path $AlyaScriptDir "ContentZip"

        # Installing files
        $destRoot = "C:\CUS"
        if (-Not (Test-Path $destRoot))
        {
            $null = New-Item -Path $destRoot -ItemType Directory -Force
        }

        try
        {
            $BuiltinUsersSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-545'
            $BuiltinAdminSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
            $AuthSystemSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'
            $CreatorOwnerSID = New-Object System.Security.Principal.SecurityIdentifier 'S-1-3-0'
            $InheritanceFlagContainerAndObject = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            $PropagationFlagInheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly
            $PropagationFlagNone = [System.Security.AccessControl.PropagationFlags]::None
            $AccessTypeAllow = [System.Security.AccessControl.AccessControlType]::Allow 
            $AccessFullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
            $AccessReadExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
            $AccessModify = [System.Security.AccessControl.FileSystemRights]::CreateDirectories -bor [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor [System.Security.AccessControl.FileSystemRights]::AppendData -bor [System.Security.AccessControl.FileSystemRights]::WriteData
            $acl = Get-Acl -Path $destRoot
            $acl.SetAccessRuleProtection($True, $False)
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($AuthSystemSID, $AccessFullControl, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
            $acl.SetAccessRule($accessRule)
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinAdminSID, $AccessFullControl, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
            $acl.SetAccessRule($accessRule)
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinUsersSID, $AccessReadExecute, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
            $acl.SetAccessRule($accessRule)
            $null = Set-Acl -Path $destRoot -AclObject $acl
        }
        catch
        {
            Write-Error $_.Exception -ErrorAction Continue
        }

        try
        {
            $scriptRoot = "$destRoot\Skripte"
            if (-Not (Test-Path $scriptRoot))
            {
                $null = New-Item -Path $scriptRoot -ItemType Directory -Force
            }
            robocopy /mir /w:1 /r:1 "$dubsSourceRoot\Skripte" $scriptRoot
        }
        catch
        {
            Write-Error $_.Exception -ErrorAction Continue
        }

        try
        {
            $documentRoot = "$destRoot\Dokumente"
            if (-Not (Test-Path $documentRoot))
            {
                $null = New-Item -Path $documentRoot -ItemType Directory -Force
            }
            robocopy /mir /w:1 /r:1 "$dubsSourceRoot\Dokumente" $documentRoot
        }
        catch
        {
            Write-Error $_.Exception -ErrorAction Continue
        }

        # Setting version in registry
        $versionFile = Join-Path $AlyaScriptDir "version.json"
        $versionObj = Get-Content -Path $versionFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $version = [Version]$versionObj.version
        $regPath = "HKLM:\SOFTWARE\AlyaConsulting\Intune\Win32AppVersions"
        $valueName = "LocalCUS"
        if (!(Test-Path $regPath))
        {
            New-Item -Path $regPath -Force
        }
        $prop = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
        if (-Not $prop)
        {
            New-ItemProperty -Path $regPath -Name $valueName -Value $version -PropertyType String -Force
        }
        else
        {
            Set-ItemProperty -Path $regPath -Name $valueName -Value $version -Force
        }
    }
    catch
    {   
        try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
        Write-Error ($_.Exception) -ErrorAction Continue
        $exitCode = -1
    }

    Stop-Transcript
}

exit $exitCode
