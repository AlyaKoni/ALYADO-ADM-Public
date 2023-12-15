#Requires -Version 2.0

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
    22.10.2020 Konrad Brunner       Initial Version
    06.10.2023 Konrad Brunner       WinGet version

#>

[CmdletBinding()]
Param(
)

$exitCode = 0
$AlyaTimeString = (Get-Date).ToString("yyyyMMddHHmmssfff")
$AlyaScriptName = Split-Path $PSCommandPath -Leaf
$AlyaScriptDir = Split-Path $PSCommandPath -Parent

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
    Start-Transcript -Path "C:\ProgramData\AlyaConsulting\Logs\$($AlyaScriptName)-WindowsLanguagePacks-$($AlyaTimeString).log" -Force

    try
    {
        $ErrorActionPreference = "Stop"

        # Running version
        Write-Host "Running version:"
        $versionFile = Join-Path $AlyaScriptDir "version.json"
        Get-Content -Path $versionFile -Raw -Encoding UTF8

        # Prevent language packs to be cleaned
        Write-Host "Prevent language packs to be cleaned"
        $regPath = "HKLM:\Software\Policies\Microsoft\Control Panel\International"
        $valueName = "BlockCleanupOfUnusedPreinstalledLangPacks"
        if (!(Test-Path $regPath))
        {
            New-Item -Path $regPath -Force
        }
        $prop = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
        if (-Not $prop)
        {
            New-ItemProperty -Path $regPath -Name $valueName -Value 1 -PropertyType DWORD -Force
        }
        else
        {
            Set-ItemProperty -Path $regPath -Name $valueName -Value 1 -Force
        }            

        # Reading language definitions
        Write-Host "Reading language definitions"
        $languagesToInstall = Get-Content -Path "$AlyaScriptDir\localesToInstall.json" -Raw -Encoding UTF8 | ConvertFrom-Json
        
        # Trigger package installation
        Write-Host "Trigger package installation"
        $UsingPowerShellModule = Get-Command -Name "Install-Language" -ErrorAction SilentlyContinue
        if ($UsingPowerShellModule)
        {
            Write-Host "  Using LanguagePackManagement module"
            foreach($languageToInstall in $languagesToInstall)
            {
                Write-Host "    Installing $($languageToInstall.Locale)"
                Install-Language -Language "$($languageToInstall.Locale)"
            }
        }
        else
        {
            Write-Host "  Using winget"
            foreach($languageToInstall in $languagesToInstall)
            {
                Write-Host "    Installing $($languageToInstall.ProductId)"
                winget install --accept-package-agreements --accept-source-agreements --silent --scope machine --wait --force --verbose --disable-interactivity --id "$($languageToInstall.ProductId)"
            }
        }

        # Waiting 1 hour for package installation
        Write-Host "Waiting 1 hour for package installation"
        $counter = 0
        do {
            Start-Sleep 60
            Write-Host "  Checking for installed packages"
            $allFound = $true
            $counter++
            if ($counter -ge 60)
            {
                throw "Was not able to install packages within 1 hour. Please retry."
            }
            foreach($languageToInstall in $languagesToInstall)
            {
                if ($UsingPowerShellModule)
                {
                    $pkg = Get-InstalledLanguage -Language "$($languageToInstall.Locale)"
                    if (-Not $pkg)
                    {
                        $allFound = $false
                        break
                    }
                }
                else
                {
                    $pkg = winget list $languageToInstall.ProductId | Out-String
                    if (-Not $pkg.Contains($languageToInstall.ProductId))
                    {
                        $allFound = $false
                        break
                    }
                }
            }
        } while (-Not $allFound)

        # Trigger package updates
        Write-Host "Trigger package updates"
        foreach($languageToInstall in $languagesToInstall)
        {
            if ($UsingPowerShellModule)
            {
                Write-Host "  Updating $($languageToInstall.Locale)"
                #TODO
            }
            else
            {
                Write-Host "  Updating $($languageToInstall.ProductId)"
                winget upgrade --accept-package-agreements --accept-source-agreements --silent --scope machine --wait --force --verbose --disable-interactivity --id "$($languageToInstall.ProductId)"
            }
        }

        # Trigger install for language FOD packages"
        Write-Host "Trigger install for language FOD packages"
        foreach($languageToInstall in $languagesToInstall)
        {
            $language = $languageToInstall.Locale
            & DISM.exe /Online /Add-Capability /CapabilityName:Language.Basic~~~$language~0.0.1.0
            & DISM.exe /Online /Add-Capability /CapabilityName:Language.Handwriting~~~$language~0.0.1.0
            & DISM.exe /Online /Add-Capability /CapabilityName:Language.OCR~~~$language~0.0.1.0
            & DISM.exe /Online /Add-Capability /CapabilityName:Language.Speech~~~$language~0.0.1.0
            & DISM.exe /Online /Add-Capability /CapabilityName:Language.TextToSpeech~~~$language~0.0.1.0
        }

        # Setting version in registry
        Write-Host "Setting version in registry"
        $versionFile = Join-Path $AlyaScriptDir "version.json"
        $versionObj = Get-Content -Path $versionFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $version = [Version]$versionObj.version
        $regPath = "HKLM:\SOFTWARE\AlyaConsulting\Intune\Win32AppVersions"
        $valueName = "WindowsLanguagePacks"
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
