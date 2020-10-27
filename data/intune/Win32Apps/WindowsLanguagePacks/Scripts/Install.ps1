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
    22.10.2020 Konrad Brunner       Initial Version

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
        # with help from https://github.com/okieselbach/Intune/blob/master/Win32/SetLanguage-de-DE/Install-LanguageExperiencePack.ps1#L157
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
        $namespaceName = "root\cimv2\mdm\dmmap"
        $session = New-CimSession
        $omaUri = "./Vendor/MSFT/EnterpriseModernAppManagement/AppInstallation"
        $packages = Get-AppxPackage -AllUsers
        foreach($languageToInstall in $languagesToInstall)
        {
            $packageFamilyName = $languageToInstall.PackageFamilyName
            $pkg = $packages | where { $_.PackageFamilyName -eq $packageFamilyName }
            if (-Not $pkg)
            {
                $applicationId = $languageToInstall.ProductId.ToLower()
                $skuId = $languageToInstall.SkuId
                Write-Host "Submitting Language Experience Pack '$packageFamilyName' for installation"
                $newInstance = New-Object Microsoft.Management.Infrastructure.CimInstance "MDM_EnterpriseModernAppManagement_AppInstallation01_01", $namespaceName
                $property = [Microsoft.Management.Infrastructure.CimProperty]::Create("ParentID", $omaUri, "string", "Key")
                $newInstance.CimInstanceProperties.Add($property)
                $property = [Microsoft.Management.Infrastructure.CimProperty]::Create("InstanceID", $packageFamilyName, "String", "Key")
                $newInstance.CimInstanceProperties.Add($property)
                $flags = 0
                $paramValue = [Security.SecurityElement]::Escape($('<Application id="{0}" flags="{1}" skuid="{2}"/>' -f $applicationId, $flags, $skuId))
                $params = New-Object Microsoft.Management.Infrastructure.CimMethodParametersCollection
                $param = [Microsoft.Management.Infrastructure.CimMethodParameter]::Create("param", $paramValue, "String", "In")
                $params.Add($param)
                $instance = $session.CreateInstance($namespaceName, $newInstance)
                $result = $session.InvokeMethod($namespaceName, $instance, "StoreInstallMethod", $params)
                if ($result.ReturnValue.Value -eq 0)
                {
                    Write-Host "  install process triggered via MDM/StoreInstall method"
                }
                else
                {
                    throw "Problems triggering install process via MDM/StoreInstall method for '$($packageFamilyName)'"
                }
                $session.DeleteInstance($namespaceName, $instance) | Out-Null
            }
        }
        Remove-CimSession -CimSession $session

        # Waiting 1 hour for package installation
        Write-Host "Waiting 1 hour for package installation"
        $counter=0
        do {
            Start-Sleep 60
            $allFound = $true
            $counter++
            if ($counter -ge 60)
            {
                throw "Was not able to install packages within 1 hour. Please retry."
            }
            $packages = Get-AppxPackage -AllUsers
            foreach($languageToInstall in $languagesToInstall)
            {
                $packageFamilyName = $languageToInstall.PackageFamilyName
                $pkg = $packages | where { $_.PackageFamilyName -eq $packageFamilyName }
                $pkg
                if (-Not $pkg -or $pkg.Status -ne "Ok")
                {
                    $allFound = $false
                    break
                }
            }
        } while (-Not $allFound)

        # Listing installed packages
        Write-Host "Listing installed packages"
        $packages = Get-AppxPackage -AllUsers
        foreach($languageToInstall in $languagesToInstall)
        {
            $packageFamilyName = $languageToInstall.PackageFamilyName
            $packages | where { $_.PackageFamilyName -eq $packageFamilyName }
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

        # Trigger store updates, there might be new app versions due to the language change
        Write-Host "Trigger store updates"
        Get-CimInstance -Namespace $namespaceName -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName "UpdateScanMethod"

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
        try { Write-Error ($_.Exception | ConvertTo-Json -Depth 3) -ErrorAction Continue } catch {}
        Write-Error ($_.Exception) -ErrorAction Continue
        $exitCode = -1
    }

    Stop-Transcript
}

exit $exitCode
