#Requires -Version 2.0
#Requires -RunAsAdministrator

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
    16.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Pscx"

# Starting Transscript
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

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIvGwYJKoZIhvcNAQcCoIIvDDCCLwgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAME20j7XE5xdzZ
# p6pdPaLoLlJNKGGpTMTl3zaxm8t8x6CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxghnmMIIZ4gIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPbUeFY1
# t/55rq3o7SI40BlKEOg/0IXUZrD2hk6JUT/ZMA0GCSqGSIb3DQEBAQUABIICAE10
# X2mjQOh4LdSEi13gEth6kBjCuEbaZH7qX9l1zBf4FXyGF65pW8vBGxFZx7/2HJd8
# 0RyxADZkoFuIRepjB/akkKX4aBOeMqWIqyzXD+n8NJOeL8BWlRm4RhU+cxj2IYF3
# S6PQz6BxwkI5wgfoWrv9vGI/L9i8n2pFLqyoY7xuo2W5LPXBEAlernYfRJ1KXWI9
# m8DL2m5txfbKmnxdOOh2NHAyDsqF2v8GzuhYnuwPmzBIAmIqEIcinG+7LLFM38yn
# bnPbTQZzxp7s3ysuD9IggDDn3ChUvvaw3l+appoKP2YuxLPlGoHseIuOWfBIQ53Z
# 7X3ANBZ/UI4Ao9VAjp3qKjAHEw5+czxDOyfveGqMrBrPDIrQjcvrWXLyKMnJrHbJ
# 4YozibaIzryYLSb8zeqWH1Jvpi2FBmevZgYUYEhX8DjwqG1UCt/Syur+rTsk8d2X
# SwYxdeoQd5gjWwCmUuvQ/E0MXwk+jpWU5+xB+/iL9l2B5mSSlqAJ6zycZxUX1KNN
# aP2+jEvPEFilIhYpLG6gcopbeEJ82z4QaX0qG2fTcClPrzFAnLGkz2nAtzHVUqQL
# C1N3Z+t6KQm8YNGnrlE5o5YDfCO0qFXvKf53Z4/mmuwDZ3L3ieS2J5FE4cr+yBXA
# ED/gYIcDpVJ5RcdtKty8NwKtXZJMZp17NYDALJ65oYIWzTCCFskGCisGAQQBgjcD
# AwExgha5MIIWtQYJKoZIhvcNAQcCoIIWpjCCFqICAQMxDTALBglghkgBZQMEAgEw
# gegGCyqGSIb3DQEJEAEEoIHYBIHVMIHSAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCCZQaBNXvUZY5/MJjeOyoPm9Le8lRcHr47TxRrjL7lSYAIUPSFT
# wTHXYuN5NsN3CR6aL0T7GBgYDzIwMjUwMjA2MTkyMjE0WjADAgEBoGGkXzBdMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwq
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2IC0gMjAyMzExoIISVDCC
# BmwwggRUoAMCAQICEAGb6t7ITWuP92w6ny4BJBYwDQYJKoZIhvcNAQELBQAwWzEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMT
# KEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjMx
# MTA3MTcxMzQwWhcNMzQxMjA5MTcxMzQwWjBdMQswCQYDVQQGEwJCRTEZMBcGA1UE
# CgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwqR2xvYmFsc2lnbiBUU0EgZm9y
# IENvZGVTaWduMSAtIFI2IC0gMjAyMzExMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A
# MIIBigKCAYEA6oQ3UGg8lYW1SFRxl/OEcsmdgNMI3Fm7v8tNkGlHieUs2PGoan5g
# N0lzm7iYsxTg74yTcCC19SvXZgV1P3qEUKlSD+DW52/UHDUu4C8pJKOOdyUn4Ljz
# fWR1DJpC5cad4tiHc4vvoI2XfhagxLJGz2DGzw+BUIDdT+nkRqI0pz4Yx2u0tvu+
# 2qlWfn+cXTY9YzQhS8jSoxMaPi9RaHX5f/xwhBFlMxKzRmUohKAzwJKd7bgfiWPQ
# HnssW7AE9L1yY86wMSEBAmpysiIs7+sqOxDV8Zr0JqIs/FMBBHkjaVHTXb5zhMub
# g4htINIgzoGraiJLeZBC5oJCrwPr1NDag3rDLUjxzUWRtxFB3RfvQPwSorLAWapU
# l05tw3rdhobUOzdHOOgDPDG/TDN7Q+zw0P9lpp+YPdLGulkibBBYEcUEzOiimLAd
# M9DzlR347XG0C0HVZHmivGAuw3rJ3nA3EhY+Ao9dOBGwBIlni6UtINu41vWc9Q+8
# iL8nLMP5IKLBAgMBAAGjggGoMIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFPlOq764+Fv/wscD9EHunPjWdH0/MFYG
# A1UdIARPME0wCAYGZ4EMAQQCMEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8E
# AjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3Au
# Z2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdo
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0
# ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6
# MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNo
# YTM4NGc0LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAlfRnz5OaQ5KDF3bWIFW8if/k
# X7LlFRq3lxFALgBBvsU/JKAbRwczBEy0tGL/xu7TDMI0oJRcN5jrRPhf+CcKAr4e
# 0SQdI8svHKsnerOpxS8M5OWQ8BUkHqMVGfjvg+hPu2ieI299PQ1xcGEyfEZu8o/R
# nOhDTfqD4f/E4D7+3lffBmvzagaBaKsMfCr3j0L/wHNp2xynFk8mGVhz7ZRe5Bqi
# EIIHMjvKnr/dOXXUvItUP35QlTSfkjkkUxiDUNRbL2a0e/5bKesexQX9oz37obDz
# K3kPsUusw6PZo9wsnCsjlvZ6KrutxVe2hLZjs2CYEezG1mZvIoMcilgD9I/snE7Q
# 3+7OYSHTtZVUSTshUT2hI4WSwlvyepSEmAqPJFYiigT6tJqJSDX4b+uBhhFTwJN7
# OrTUNMxi1jVhjqZQ+4h0HtcxNSEeEb+ro2RTjlTic2ak+2Zj4TfJxGv7KzOLEcN0
# kIGDyE+Gyt1Kl9t+kFAloWHshps2UgfLPmJV7DOm5bga+t0kLgz5MokxajWV/vbR
# /xeKriMJKyGuYu737jfnsMmzFe12mrf95/7haN5EwQp04ZXIV/sU6x5a35Z1xWUZ
# 9/TVjSGvY7br9OIXRp+31wduap0r/unScU7Svk9i00nWYF9A43aZIETYSlyzXRrZ
# 4qq/TVkAF55gZzpHEqAwggZZMIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqG
# SIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMw
# EQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYy
# MDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDwAuIwI/rgG+GadLOvdYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64H
# iifuV6PENe2zNMeswwzrgGZt0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//
# NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe
# 9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirU
# IceU/kKWO/ELsX9/RpgOhz16ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0Kvq
# WsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50
# xHAotIB7vSqbu4ThDqxvDbm19m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU
# 2EESwVX9bpHFu7FMCEue1EIGbxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE
# 6giunUlnEYuC5a1ahqdm/TMDAd6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3s
# qSbldwKsDlcMCdFhniaI/MiyTdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac
# 0zd0hNkdZqs0c48efXxeltY9GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCC
# ASUwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3Ay
# Lmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8v
# Y3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0g
# ADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBv
# c2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZM
# v9sbB3DG+wsJrQA6YDMfOcYWaxlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7A
# I4zGhf5LFST5GETsH8KkrNCyz+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG
# 0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0
# +X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3Wd
# rG9KyC5qucqIwxIwTrIIc59eodaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXa
# jR63Wy+ILj198fKRMAWcznt8oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpI
# iScseeI85Zse46qEgok+wEr1If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ
# 7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx
# 773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZq
# HcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV
# 5yBZtnjGpGqqIpswggWDMIIDa6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG
# 9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEG
# A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAw
# MDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9v
# dCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxT
# aWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns8
# 9w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0b
# WsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZ
# gQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ
# 3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2M
# sonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI5
# 5KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPF
# OJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4Py
# XhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYF
# AJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWV
# ZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlw
# g3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4IC
# AQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/A
# VJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6x
# CCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc
# 053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6q
# TFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvd
# OxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJd
# w+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ
# 4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4Z
# sRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3
# nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZ
# xRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8w
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb
# 6t7ITWuP92w6ny4BJBYwCwYJYIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZI
# hvcNAQELBQAwLwYJKoZIhvcNAQkEMSIEIPCJF7rvarKR3JmCq6gz3RR0wwM6y5PA
# skqpv22KHttxMIGwBgsqhkiG9w0BCRACLzGBoDCBnTCBmjCBlwQgOoh6lRteuSpe
# 4U9su3aCN6VF0BBb8EURveJfgqkW0egwczBfpF0wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwDQYJ
# KoZIhvcNAQELBQAEggGALaGluXhLbnsdD8TYmx6WkPBFFp0Jf/O5biGagmHgQlU8
# dInikF6QtI0I/vOadfiNMgfdtCG3uqhGiHnEWcpos6/JhOKg8atsDrDuX/v33ve3
# 4kaaFnZvubdEJMQE60eJARZpp9Wy59AQ8UBmYQSeKkk5ZslKO24QlTEGOQP5dq0T
# vbr4HyR30nX9DSB9ObMs/uDBqv5bY0KzeDz9HITVA3E6njoKc0BjI2sFTuL24g/b
# 9tOf+QT+wGKny4DTP7CLsACKhk3HK0rGmtm1Zq9mGufGyg2eKP/Q16qzgYl0lXmO
# gw71TdFF9NxglL6lSDV3UZWYH9oWGD4A0M5GtQX6+NvcgUJjdBHnv3ozIwlL1tHf
# DZjmsBSLa8fKA/3qqDg/uOD+DQEB1telC66N+W8er6RT6bF7G7I8EFpSuHkR9x/A
# eJiQVsuC2Y7lncmNywWDrb7muO/aRZzxcJAEf2SWDxlHdIpfaJ9BEbgucsqP6avy
# Qg+yaNlEgTefrXX2AWiM
# SIG # End signature block
