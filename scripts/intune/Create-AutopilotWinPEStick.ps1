#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    16.10.2020 Konrad Brunner       Initial Version
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Creates a Windows PE USB stick customized for Windows Autopilot provisioning.

.DESCRIPTION
The Create-AutopilotWinPEStick.ps1 script automates the creation and customization of a Windows Preinstallation Environment (WinPE) image that includes Windows Autopilot tools and Alya configuration data. It checks and installs required Windows Assessment and Deployment Kit (ADK) components, prepares the WinPE environment, adds necessary packages and PowerShell modules, configures scripts and registry providers, builds an ISO image, and writes it to a selected USB drive to create a bootable Autopilot preparation stick.

.INPUTS
None. The script does not accept pipeline input.

.OUTPUTS
A bootable WinPE USB stick pre-configured for Windows Autopilot device information collection and registration.

.EXAMPLE
PS> .\Create-AutopilotWinPEStick.ps1

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Pscx"

# Starting Transcript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Create-AutopilotWinPEStick-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Create-AutopilotWinPEStick | Local" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Checking ADK dir" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$($AlyaTools)\ADK"))
{
    $null = New-Item -Path "$($AlyaTools)\ADK" -ItemType Directory -Force
}

Write-Host "Checking AlyaADK" -ForegroundColor $CommandInfo
if (-Not (Test-Path "C:\AlyaADK"))
{
    Write-Host "Creating C:\AlyaADK"
    $null = New-Item -Path "C:\AlyaADK" -ItemType Directory -Force
}

Write-Host "Checking Assessment and Deployment Kit" -ForegroundColor $CommandInfo
if (-Not (Test-Path "C:\AlyaADK\Assessment and Deployment Kit"))
{
    Write-Host "Checking adksetup" -ForegroundColor $CommandInfo
    if (-Not (Test-Path "$($AlyaTools)\ADK\adksetup.exe"))
    {
        Write-Host "Downloading ADK setup tool"
        Invoke-RestMethod -Uri $AlyaAdkDownload -OutFile "$($AlyaTools)\ADK\adksetup.exe"
    }
    if (-Not (Test-Path "$($AlyaTools)\ADK\adksetup.exe"))
    {
        Write-Error "Problems downloding the adk setup" -ErrorAction Continue
        exit 92
    }

    Write-Host "Checking adk layout" -ForegroundColor $CommandInfo
    if (-Not (Test-Path "$($AlyaTemp)\ADKoffline"))
    {
        Write-Host "Downloading adk layout"
        cmd /c "$($AlyaTools)\ADK\adksetup.exe" /quiet /layout "$($AlyaTemp)\ADKoffline"
        do
        {
            Start-Sleep -Seconds 5
            $process = Get-Process -Name "adksetup" -ErrorAction SilentlyContinue
        } while ($process)
    }

    Write-Host "Installing ADK"
    Push-Location -Path "$($AlyaTemp)\ADKoffline"
    cmd /c ".\adksetup.exe" /quiet /installpath "C:\AlyaADK" /features OptionId.DeploymentTools
    do
    {
        Start-Sleep -Seconds 5
        $process = Get-Process -Name "adksetup" -ErrorAction SilentlyContinue
    } while ($process)
    Pop-Location
}

Write-Host "Checking Windows Preinstallation Environment" -ForegroundColor $CommandInfo
if (-Not (Test-Path "C:\AlyaADK\Assessment and Deployment Kit\Windows Preinstallation Environment"))
{
    Write-Host "Checking adkwinpesetup" -ForegroundColor $CommandInfo
    if (-Not (Test-Path "$($AlyaTools)\ADK\adkwinpesetup.exe"))
    {
        Write-Host "Downloading ADK WinPE setup tool"
        Invoke-RestMethod -Uri $AlyaADKpeDownload -OutFile "$($AlyaTools)\ADK\adkwinpesetup.exe"
    }
    if (-Not (Test-Path "$($AlyaTools)\ADK\adkwinpesetup.exe"))
    {
        Write-Error "Problems downloding the adk WinPE setup" -ErrorAction Continue
        exit 92
    }

    Write-Host "Checking adk WinPE layout" -ForegroundColor $CommandInfo
    if (-Not (Test-Path "$($AlyaTemp)\ADKPEoffline"))
    {
        Write-Host "Downloading adk WinPE layout"
        cmd /c "$($AlyaTools)\ADK\adkwinpesetup.exe" /quiet /layout "$($AlyaTemp)\ADKPEoffline"
        do
        {
            Start-Sleep -Seconds 5
            $process = Get-Process -Name "adkwinpesetup" -ErrorAction SilentlyContinue
        } while ($process)
    }

    Write-Host "Installing WinPE"
    Push-Location -Path "$($AlyaTemp)\ADKPEoffline"
    cmd /c ".\adkwinpesetup.exe" /quiet /installpath "C:\AlyaADK" /features OptionId.WindowsPreinstallationEnvironment
    do
    {
        Start-Sleep -Seconds 5
        $process = Get-Process -Name "adkwinpesetup" -ErrorAction SilentlyContinue
    } while ($process)
    Pop-Location
}

Write-Host "Getting WinPE environment" -ForegroundColor $CommandInfo
Invoke-BatchFile "C:\AlyaADK\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat"

Write-Host "Checking iso image" -ForegroundColor $CommandInfo
$adkAutopilot = "$($AlyaTools)\ADK\Autopilot"
$adkAutopilotIso = "$($AlyaTools)\ADK\Autopilot.iso"
if (-Not (Test-Path "$($AlyaTools)\ADK") -or -Not (Test-Path $($adkAutopilotIso)))
{
    Write-Host "Creating new iso image"
    if ((Test-Path $($adkAutopilot)))
    {
        $null = Remove-Item -Path $($adkAutopilot) -Recurse -Force
    }

    Write-Host "Copying pe image"
    cmd /c copype amd64 $($adkAutopilot)

    Write-Host "Mounting image"
    if ((Test-Path "C:\AlyaADKpe"))
    {
        cmd /c rmdir "C:\AlyaADKpe"
    }
    Start-Sleep -Seconds 1
    cmd /c mklink /d "C:\AlyaADKpe" $($adkAutopilot)
    Start-Sleep -Seconds 1
    if (-Not (Test-Path "C:\AlyaADKpe"))
    {
        throw "Not able to create symbolic link"
    }

    Push-Location -Path "C:\AlyaADKpe"
    cmd /c Dism /mount-image /ImageFile:Media\Sources\boot.wim /Index:1 /MountDir:mount

    Write-Host "Customizing image"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-Fonts-Legacy.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-Fonts-Legacy_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-RNDIS.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-RNDIS_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-WMI.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-WMI_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-NetFx.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-NetFx_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-Scripting.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-Scripting_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-PowerShell.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-PowerShell_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-EnhancedStorage.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-EnhancedStorage_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-FMAPI.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-FMAPI_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-HTA.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-HTA_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-StorageWMI.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-StorageWMI_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-SecureStartup.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-SecureStartup_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-WDS-Tools.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-WDS-Tools_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-MDAC.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-MDAC_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-PPPoE.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-PPPoE_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-Setup.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-Setup_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-Setup-Client.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-Setup-Client_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-PlatformId.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-PlatformId_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-SecureBootCmdlets.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-SecureBootCmdlets_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-DismCmdlets.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-DismCmdlets_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-PmemCmdlets.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-PmemCmdlets_en-us.cab"

    $sourceRoot = "C:\AlyaADKpe\mount\Windows\System32\wbem"
    cmd /c xcopy /herky "C:\Windows\System32\wbem\MDMAppProv*" "$($sourceRoot)"
    cmd /c xcopy /herky "C:\Windows\System32\wbem\MDMSettingsProv*" "$($sourceRoot)"
    cmd /c xcopy /herky "C:\Windows\System32\wbem\DMWmiBridgeProv*" "$($sourceRoot)"

    $ACL = Get-ACL "$sourceRoot\cimwin32.dll"
    Set-Acl -Path "$sourceRoot\MDMAppProv.dll" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\MDMSettingsProv.dll" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\DMWmiBridgeProv.dll" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\DMWmiBridgeProv1.dll" -AclObject $ACL

    $ACL = Get-ACL "$sourceRoot\cimwin32.mof"
    Set-Acl -Path "$sourceRoot\MDMAppProv.mof" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\MDMSettingsProv.mof" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\DMWmiBridgeProv.mof" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\DMWmiBridgeProv1.mof" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\MDMAppProv_Uninstall.mof" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\MDMSettingsProv_Uninstall.mof" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\DMWmiBridgeProv_Uninstall.mof" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\DMWmiBridgeProv1_Uninstall.mof" -AclObject $ACL

    $ACL = Get-ACL "$sourceRoot\en-US\cimwin32.mfl"
    Set-Acl -Path "$sourceRoot\en-US\MDMAppProv.mfl" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\en-US\MDMSettingsProv.mfl" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\en-US\MDMAppProv_Uninstall.mfl" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\en-US\MDMSettingsProv_Uninstall.mfl" -AclObject $ACL

    $sourceRoot = "C:\AlyaADKpe\mount\Alya"
    if (-Not (Test-Path $sourceRoot))
    {
        $null = New-Item -Path $sourceRoot -ItemType Directory -Force
    }
    if (-Not (Test-Path "$sourceRoot\data"))
    {
        $null = New-Item -Path "$sourceRoot\data" -ItemType Directory -Force
    }
    cmd /c robocopy "$($AlyaRoot)" "$($sourceRoot)" /MIR /XF 9*.cmd /XF .gitignore /XD data /XD .git /XD WVD /XD Solutions /XD _logs /XD _local /XD _temp /XD tools
    cmd /c copy /y "$($AlyaData)\ConfigureEnv.ps1" "$($sourceRoot)\data"
    cmd /c copy /y "$($AlyaData)\GlobalConfig.json" "$($sourceRoot)\data"

    $sourceRoot = "C:\AlyaADKpe\mount\Alya\tools\WindowsPowerShell"
    if (-Not (Test-Path $sourceRoot))
    {
        $null = New-Item -Path $sourceRoot -ItemType Directory -Force
    }
    if (-Not (Test-Path "$($sourceRoot)\Scripts"))
    {
        $null = New-Item -Path "$($sourceRoot)\Scripts" -ItemType Directory -Force
    }
    if (-Not (Test-Path "$($sourceRoot)\Modules"))
    {
        $null = New-Item -Path "$($sourceRoot)\Modules" -ItemType Directory -Force
    }
    Save-Module -Name PackageManagement -Path "$($sourceRoot)\Modules" -Force
    Save-Module -Name PowershellGet -Path "$($sourceRoot)\Modules" -Force
    Save-Module -Name Microsoft.Graph.Beta.Intune -Path "$($sourceRoot)\Modules" -Force
    Save-Module -Name WindowsAutopilotIntune -Path "$($sourceRoot)\Modules" -Force
    Save-Module -Name PSWindowsUpdate -Path "$($sourceRoot)\Modules" -Force
    Save-Module -Name AzureAD -Path "$($sourceRoot)\Modules" -Force
    Save-Script -Name Get-WindowsAutoPilotInfo -Path "$($sourceRoot)\Scripts" -Force

    cmd /c Dism /image:mount /Set-AllIntl:en-US
    cmd /c Dism /image:mount /Set-InputLocale:0409:00000807

    #Create init script
    $initScript = @"
powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
wpeutil initializenetwork
wpeutil disablefirewall
"@
<#
netsh int ip set addr Eth static 192.168.2.15 255.255.255.0 192.168.2.1
net start dnscache
netsh int ip set dns Eth static 192.168.20.1 primary
#>
    $initScript | Set-Content -Path "C:\AlyaADKpe\mount\Alya\80_Init.cmd" -Encoding Ascii

    #Register MDM CIM providers
    $providerRegFile = @"
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\CLSID]

; %systemroot%\system32\wbem\MDMAppProv.dll

[HKEY_CLASSES_ROOT\CLSID\{6E7E2EF2-F881-472A-8E32-17CA95710402}]
@="MDM Enterprise Application Provider"

[HKEY_CLASSES_ROOT\CLSID\{6E7E2EF2-F881-472A-8E32-17CA95710402}\InprocServer32]
@=hex(2):25,00,73,00,79,00,73,00,74,00,65,00,6d,00,72,00,6f,00,6f,00,74,00,25,\
  00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,77,00,62,00,\
  65,00,6d,00,5c,00,4d,00,44,00,4d,00,41,00,70,00,70,00,50,00,72,00,6f,00,76,\
  00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

; %systemroot%\system32\wbem\MDMSettingsProv.dll

[HKEY_CLASSES_ROOT\CLSID\{8B19C1CD-C80C-4AEC-AAE2-4E39FEDD24D0}]
@="Microsoft Device Management Settings Provider"

[HKEY_CLASSES_ROOT\CLSID\{8B19C1CD-C80C-4AEC-AAE2-4E39FEDD24D0}\InprocServer32]
@=hex(2):25,00,73,00,79,00,73,00,74,00,65,00,6d,00,72,00,6f,00,6f,00,74,00,25,\
  00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,77,00,62,00,\
  65,00,6d,00,5c,00,4d,00,44,00,4d,00,53,00,65,00,74,00,74,00,69,00,6e,00,67,\
  00,73,00,50,00,72,00,6f,00,76,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

; %systemroot%\system32\wbem\DMWmiBridgeProv.dll

[HKEY_CLASSES_ROOT\CLSID\{0E9847B3-13E8-44E6-9659-2B60A140A573}]
@="DM WMI Bridge Provider"

[HKEY_CLASSES_ROOT\CLSID\{0E9847B3-13E8-44E6-9659-2B60A140A573}\InprocServer32]
@=hex(2):25,00,73,00,79,00,73,00,74,00,65,00,6d,00,72,00,6f,00,6f,00,74,00,25,\
  00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,77,00,62,00,\
  65,00,6d,00,5c,00,44,00,4d,00,57,00,6d,00,69,00,42,00,72,00,69,00,64,00,67,\
  00,65,00,50,00,72,00,6f,00,76,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

; %systemroot%\system32\wbem\DMWmiBridgeProv1.dll

[HKEY_CLASSES_ROOT\CLSID\{E17A999C-97F7-4213-BF6F-DE08E9D7ECF5}]
@="DM WMI Bridge Provider"

[HKEY_CLASSES_ROOT\CLSID\{E17A999C-97F7-4213-BF6F-DE08E9D7ECF5}\InprocServer32]
@=hex(2):25,00,73,00,79,00,73,00,74,00,65,00,6d,00,72,00,6f,00,6f,00,74,00,25,\
  00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,77,00,62,00,\
  65,00,6d,00,5c,00,44,00,4d,00,57,00,6d,00,69,00,42,00,72,00,69,00,64,00,67,\
  00,65,00,50,00,72,00,6f,00,76,00,31,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"
"@
    $providerRegFile | Set-Content -Path "C:\AlyaADKpe\mount\Alya\81_RegisterProviders.reg" -Encoding Ascii

    $providerRegistration = @"
net stop winmgmt

regsvr32 /s %systemroot%\system32\wbem\MDMAppProv.dll
regsvr32 /s %systemroot%\system32\wbem\MDMSettingsProv.dll
regsvr32 /s %systemroot%\system32\wbem\DMWmiBridgeProv.dll
regsvr32 /s %systemroot%\system32\wbem\DMWmiBridgeProv1.dll
rem start %~dp081_RegisterProviders.reg

net start winmgmt

mofcomp %systemroot%\system32\wbem\MDMAppProv.mof
mofcomp %systemroot%\system32\wbem\MDMSettingsProv.mof
mofcomp %systemroot%\system32\wbem\DMWmiBridgeProv.mof
mofcomp %systemroot%\system32\wbem\DMWmiBridgeProv1.mof

mofcomp %systemroot%\system32\wbem\en-US\MDMAppProv.mfl
mofcomp %systemroot%\system32\wbem\en-US\MDMSettingsProv.mfl

mofcomp %systemroot%\system32\wbem\MDMAppProv_Uninstall.mof
mofcomp %systemroot%\system32\wbem\MDMSettingsProv_Uninstall.mof
mofcomp %systemroot%\system32\wbem\DMWmiBridgeProv_Uninstall.mof
mofcomp %systemroot%\system32\wbem\DMWmiBridgeProv1_Uninstall.mof

mofcomp %systemroot%\system32\wbem\en-US\MDMAppProv_Uninstall.mfl
mofcomp %systemroot%\system32\wbem\en-US\MDMSettingsProv_Uninstall.mfl

rem Register-CimProvider.exe -Namespace "root/cimv2/mdm" -ProviderName "MDMAppProv" -Path %systemroot%\system32\wbem\MDMAppProv.dll -Verbose -ForceUpdate
rem Register-CimProvider.exe -Namespace "root/cimv2/mdm" -ProviderName "MDMSettingsProv" -Path %systemroot%\system32\wbem\MDMSettingsProv.dll -Verbose -ForceUpdate
rem Register-CimProvider.exe -Namespace "root/cimv2/mdm/dmmap" -ProviderName "DMWmiBridgeProv" -Path %systemroot%\system32\wbem\DMWmiBridgeProv.dll -Verbose -ForceUpdate
rem other params: -Impersonation True -HostingModel LocalServiceHost -SupportWQL
"@
    $providerRegistration | Set-Content -Path "C:\AlyaADKpe\mount\Alya\81_RegisterProviders.cmd" -Encoding Ascii
    
    #Create PowerShell script
    $startPowerShellScript = @"
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList 'Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force' -Verb RunAs}"
set PSModulePath=%SystemDrive%\Alya\tools\WindowsPowerShell\modules;%PSModulePath%
set Path=%SystemDrive%\Alya\tools\WindowsPowerShell\scripts;%Path%
PowerShell
"@
    $startPowerShellScript | Set-Content -Path "C:\AlyaADKpe\mount\Alya\82_StartPowerShell.cmd" -Encoding Ascii

    #Create autopilot script
    $startAutopilotScript = @"
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& '\Alya\scripts\intune\Get-AutopilotDeviceInfos.ps1'"
"@
    $startAutopilotScript | Set-Content -Path "C:\AlyaADKpe\mount\Alya\83_GetAutopilotDeviceInfos.cmd" -Encoding Ascii
    
    #Create images finder script
    $imagesFinder = @"
@echo Find a drive that has a folder titled Images.
@for %%a in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do @if exist %%a:\Images\ set IMAGESDRIVE=%%a
@echo The Images folder is on drive: %IMAGESDRIVE%
@dir %IMAGESDRIVE%:\Images /w
"@
    $imagesFinder | Set-Content -Path "C:\AlyaADKpe\mount\Alya\89_FindImages.cmd" -Encoding Ascii

    #wpeinit
    $Startnetcmd = @"
wpeinit
"@
    $Startnetcmd | Set-Content -Path "C:\AlyaADKpe\mount\Windows\System32\startnet.cmd" -Encoding Ascii

    #Launch powershell on start
    $Winpeshlini = @"
[LaunchApp]
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
"@
    $Winpeshlini | Set-Content -Path "C:\AlyaADKpe\mount\Windows\System32\winpeshl.ini" -Encoding Ascii
    $ACL = Get-ACL "C:\AlyaADKpe\mount\Windows\System32\startnet.cmd"
    Set-Acl -Path "C:\AlyaADKpe\mount\Windows\System32\winpeshl.ini" -AclObject $ACL

    #Set the background image
    $ACL = Get-ACL "C:\AlyaADKpe\mount\Windows\System32\WinPE.jpg"
    $Group = New-Object System.Security.Principal.NTAccount("Builtin", "Administrators")
    $ACL.SetOwner($Group)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Group,"FullControl","None","None","Allow")
    $acl.SetAccessRule($rule)
    Set-Acl -Path "C:\AlyaADKpe\mount\Windows\System32\WinPE.jpg" -AclObject $ACL
    Copy-Item -Path $AlyaWinPEBackgroundJpgImage -Destination "C:\AlyaADKpe\mount\Windows\System32\WinPE.jpg" -Force

    Write-Host "Getting actual features"
    cmd /c Dism /Image:mount /Get-Features

    Write-Host "Commiting image"
    #cmd /c Dism /unmount-image /MountDir:mount /discard
    cmd /c Dism /unmount-image /MountDir:mount /commit

    Write-Host "Building iso"
    $actPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    cmd /c MakeWinPEMedia /iso /f "$adkAutopilot" "$adkAutopilotIso"
    $ErrorActionPreference = $actPref
    Pop-Location

    if (-Not (Test-Path $($adkAutopilotIso)))
    {
        Write-Error "Could not create iso image" -ErrorAction Continue
        Exit 92
    }
}

Write-Host "Writing iso image to usb stick" -ForegroundColor $CommandInfo
$disk = $null
$usbDisk = Get-Disk | Where-Object BusType -eq USB
switch (($usbDisk | Measure-Object | Select-Object Count).Count)
{
    1 {
        $disk = $usbDisk[0]
    }
    {$_ -gt 1} {
        $disk = Get-Disk | Where-Object BusType -eq USB | Out-GridView -Title 'Select USB Drive to use' -OutputMode Single
    }
}
if ($disk)
{
    $res = $disk | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false -PassThru | New-Partition -UseMaximumSize -IsActive -AssignDriveLetter | Format-Volume -FileSystem NTFS
    cmd /c bootsect.exe /nt60 "$($res.DriveLetter):" /force /mbr
    $vol = Mount-DiskImage -ImagePath $adkAutopilotIso -StorageType ISO -PassThru | Get-DiskImage | Get-Volume
    cmd /c xcopy /herky "$($vol.DriveLetter):\*.*" "$($res.DriveLetter):\"
    Dismount-DiskImage -ImagePath $adkAutopilotIso
}
else
{
    Write-Warning "No stick selected or detected!"
}
if ((Test-Path "C:\AlyaADKpe"))
{
    cmd /c rmdir "C:\AlyaADKpe"
}

# Stopping Transcript
Stop-Transcript

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC3gmXtuX8vFnMU
# tZn0hkY1cg8Kkemfgd+0dijyPICWMaCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFe3nyLC
# mnKIN8yKhd07sBTLJuJp2SGXVzdddEJu5JYdMA0GCSqGSIb3DQEBAQUABIICACwG
# aO6Fb40A+siv2jNeXOMS+KiOIj0V9RHv2Kkmuvt9YqtvqWa6ZQlaBaLzbTeetapc
# qVcP2FBrn+kVieiw8lbZOknhbXzcNhh639gDrIEy5w0u/fkagHt6rGL+g0nJndZ/
# fDE4mKR/zteLQATftrkXIcvPBqsYsBMO13VS03oakCONQXZA25/7FG8ve3ejZncx
# unYSQoX0TpbBeB3WUGg9T7CdUSt9f21+JV77WEyS5q7ngn0iYzSte2RxTQ/iQeWi
# lO55TNCVdDnHqeqx8OpIwKajPuB80VXLAF9yLYkbzKlfsRISAtLFnlxUti5LDWr6
# OknBGTQHERo4z9tKc6abIAb7YlitmQ6vnklknz5o0ng+C8ok7E6n/blC8eYUgfA5
# 0wYpyUQ0RYQ2RAZm8A+VXVSwZ0PxYPKNcZN/4LVvmVcUBL5IxZIFUljGAz+0B8WP
# CuF3Khg4RSSmQKu+/ApaLJ4UMvts6dnkoui/FbdARuGn98eP5V88g7uMQ//5o6xp
# KchfAok6kC9iwrSwD6gK+hkP4XaSpmnRLiR5hMVdKqbA8+gNGDkt32n5ZRMXpS0U
# LdmJsMSvKijyTzxk1rhdfP0bimu0haHoBaFbb6F5YnDF6SEJr3FxCfAZbved5zyJ
# 1wzlmhqbnRBUmW+ogpZCuwv45G/sTtBoixdzk/CmoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCD/LVkCfuCGHmeXcM0yIolecpDzAZa8L/5S4NBmHb7OfAIUP2Sg
# i9vEyE1RcTHBYjc3k+yZB3gYDzIwMjYwODI5MTUyNDAyWjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDBa+WlydE8qJBv/Kbf7Uml4gyoypx1N0cjbEzTCQnxFN4BO2pSfYS03Qg7+
# o/9Xs5MwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAv4dfUtZ3T841jkZyIYShXYiyR3lwYik3h7IBfOJrgyla
# y3cNgFT7FJ+2unVPYRCbCy/il5hfaXQbFj924xjdubUggWkNysAw7gBYcV4FMzOh
# Rk97qdZO0ZYwwsBlJpniX6N6kg+ZpIcYQjYzgGiuN+vvywRvYhV0MsTXDlR3Yp/7
# HBTPwKJRrB2iecccFkPwIvKsH6llHtqXSrcpy9oBWn7DHA+1AQlqVmPBTQ+fboYt
# RdUTf6cKqgvgru2PDDkwq/avMf899euXHdIeftP5qnZ6rW0BjcAEBer4D3KoPcx9
# z9lkkgSTPqoUNR/gvAqf7pt6gkaAjpTLUYZtIOebVdgeDLtVM5IkKQ2PURNUbmU+
# UqoGYasOxNAXAYWapOaSMXC+fmGzWket/8wimERRHjBu21myKZP5uAaepa59DaDy
# /28pxq/2TCowhUco9Qt9r3kcpfPzHjzU1uYcdr3C0/YdLe8uSzokQi0om0D6EuwP
# xS/BzNr/1yoiYv1oP2Lk
# SIG # End signature block
