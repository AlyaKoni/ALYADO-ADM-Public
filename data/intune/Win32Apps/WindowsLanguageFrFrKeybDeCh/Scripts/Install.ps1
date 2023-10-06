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
    Start-Transcript -Path "C:\ProgramData\AlyaConsulting\Logs\$($AlyaScriptName)-LanguagePackDeDe-$($AlyaTimeString).log" -Force

    try
    {
        # with help from https://github.com/okieselbach/Intune/blob/master/Win32/SetLanguage-de-DE/Install-LanguageExperiencePack.ps1#L157
        $ErrorActionPreference = "Stop"

        # Running version
        Write-Host "Running version:"
        $versionFile = Join-Path $AlyaScriptDir "version.json"
        Get-Content -Path $versionFile -Raw -Encoding UTF8

        # Reading language definitions
        Write-Host "Reading language definitions"
        $languagesToInstall = Get-Content -Path "$AlyaScriptDir\localesToInstall.json" -Raw -Encoding UTF8 | ConvertFrom-Json
        
        # Getting windows language
        Write-Host "Getting windows language"
        $languageToInstall = $languagesToInstall | Sort-Object -Property Order | Select-Object -First 1
        $languageToInstall | ConvertTo-Json -Depth 50
        #$language = $languageToInstall.Locale
        $languageTag = $languageToInstall.LanguageTag
        $applicationId = $languageToInstall.ProductId.ToLower()
        $packageFamilyName = $languageToInstall.PackageFamilyName
        $skuId = $languageToInstall.SkuId
        $geoId = $languageToInstall.GeoId
        $inputLanguageID = $languageToInstall.InputLanguageID

        $languagListString = "`$UserLanguageList = Get-WinUserLanguageList`n"
        $languagListString += "`$UserLanguageList.Clear()`n"
        $languageToInstall = $languagesToInstall | Sort-Object -Property Order | Foreach-Object {
            $languagListString += "`$UserLanguageList.Add(`"$($_.LanguageTag)`")`n"
            $languagListString += "`$UserLanguageList | Where-Object { `$_.LanguageTag -eq `"$($_.LanguageTag)`" } | Foreach-Object {`n"
            $languagListString += "    `$_.Handwriting=`$true`n"
            $languagListString += "    `$_.Spellchecking=`$true`n"
            $languagListString += "    `$_.InputMethodTips[0] = `"$($_.InputLanguageID)`"`n"
            $languagListString += "}`n"
        }
        $languagListString += "Set-WinUserLanguageList -LanguageList `$UserLanguageList -Force"

        # Preparing user scripts
        Write-Host "Preparing user scripts"
        $scriptFolderPath = "$env:SystemDrive\ProgramData\AlyaConsulting\LanguageScripts"
        $null = New-Item -ItemType Directory -Force -Path $scriptFolderPath
        $languageXmlPath = Join-Path -Path $scriptFolderPath -ChildPath "MUI_$($languageTag).xml"
        $languageXml = @"
<gs:GlobalizationServices xmlns:gs="urn:longhornGlobalizationUnattend">
    <gs:UserList>
        <gs:User UserID="Current" CopySettingsToDefaultUserAcct="true" CopySettingsToSystemAcct="true"/>
    </gs:UserList>
    <gs:LocationPreferences>
        <gs:GeoID Value="$geoId"/>
    </gs:LocationPreferences>
    <gs:MUILanguagePreferences>
        <gs:MUILanguage Value="$languageTag"/>
    </gs:MUILanguagePreferences>
    <gs:SystemLocale Name="$languageTag"/>
    <gs:InputPreferences>
        <gs:InputLanguageID Action="add" ID="$inputLanguageID" Default="true"/>
    </gs:InputPreferences>
    <gs:UserLocale>
        <gs:Locale Name="$languageTag" SetAsCurrent="true" ResetAllSettings="false"/>
    </gs:UserLocale>
</gs:GlobalizationServices>
"@
        Out-File -FilePath $languageXmlPath -InputObject $languageXml -Encoding ascii -Force
        $userConfigScriptPath = Join-Path -Path $scriptFolderPath -ChildPath "UserConfig_$($languageTag).ps1"
        $userConfigScript = @"
#`$language = "$language"
`$languageTag = "$languageTag"
`$packageFamilyName = "$packageFamilyName"
`$geoId = $geoId
`$appxLxpPath = (Get-AppxPackage | Where-Object { `$_.PackageFamilyName -eq `$packageFamilyName }).InstallLocation
Add-AppxPackage -Register -Path "`$appxLxpPath\AppxManifest.xml" -DisableDevelopmentMode
#Set-WinUserLanguageList `$languageTag -Force
$languagListString
Set-WinUILanguageOverride -Language `$languageTag
Set-WinSystemLocale -SystemLocale `$languageTag
Set-Culture -CultureInfo `$languageTag
Set-WinHomeLocation -GeoId `$geoId
"@
        Out-File -FilePath $userConfigScriptPath -InputObject $userConfigScript -Encoding ascii -Force
        $userConfigScriptHiddenStarterPath = Join-Path -Path $scriptFolderPath -ChildPath "UserConfig_$($languageTag).cmd"
        $userConfigScriptHiddenStarter = @"
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -File "$userConfigScriptPath" 2>&1 1>>C:\ProgramData\AlyaConsulting\Logs\UserConfig_$($languageTag).cmd.log
"@
        Out-File -FilePath $userConfigScriptHiddenStarterPath -InputObject $userConfigScriptHiddenStarter -Encoding ascii -Force

        # Trigger language change for current user session via ScheduledTask
        Write-Host "Triggering language change via ScheduledTask"
        $taskName = "LXP-UserSession-Config-$languageTag"
        $action = New-ScheduledTaskAction -Execute "$userConfigScriptHiddenStarterPath"
        $trigger = New-ScheduledTaskTrigger -AtLogOn # TODO: Once?
        $principal = New-ScheduledTaskPrincipal -UserId (Get-CimInstance –ClassName Win32_ComputerSystem | Select-Object -expand UserName)
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
        Register-ScheduledTask $taskName -InputObject $task
        Start-ScheduledTask -TaskName $taskName
        Start-Sleep -Seconds 30
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false

        # Trigger 'LanguageComponentsInstaller\ReconcileLanguageResources' otherwise 'Windows Settings' need a long time to change finally
        Write-Host "Triggering language change via ScheduledTask"
        Start-ScheduledTask -TaskName "\Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources"

        # Changing language on system components
        Write-Host "Changing language on system components"
        # check eventlog 'Microsoft-Windows-Internationl/Operational' for troubleshooting
        & $env:SystemRoot\System32\control.exe "intl.cpl,,/f:`"$languageXmlPath`""

        # Trigger store updates, there might be new app versions due to the language change
        Write-Host "Trigger store updates"
        $namespaceName = "root\cimv2\mdm\dmmap"
        Get-CimInstance -Namespace $namespaceName -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName "UpdateScanMethod"
        Start-Sleep -Seconds 30

        # Setting version in registry
        Write-Host "Setting version in registry"
        $versionFile = Join-Path $AlyaScriptDir "version.json"
        $versionObj = Get-Content -Path $versionFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $version = [Version]$versionObj.version
        $regPath = "HKLM:\SOFTWARE\AlyaConsulting\Intune\Win32AppVersions"
        $valueName = "WindowsLanguageFrFrKeybDeCh"
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
