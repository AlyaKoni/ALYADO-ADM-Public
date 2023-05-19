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
    16.11.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\test\Configure-HostPool-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefixTest)resg$($AlyaResIdAvdManagementResGrp)"
$HostPoolName = "$($AlyaNamingPrefixTest)avdh$($AlyaResIdAvdHostpool)"
$HostPoolMaxSessionLimit = $AlyaAvdMaxSessions
$IsTestHostPool = $false #needs to be $true to use AllowNonAadJoinedDevices so far

#special na handling
$na = "{[(N/A)]}"
#use $null if you dont want to take into account a value

$AllowNonAadJoinedDevices = $null
#targetisaadjoined:i:value
#Indicates whether not AAD joined devices are allowed
#- 0*: Do not allow not AAD joined devices
#- 1: Enable not AAD joined devices

$AudioCapturingMode = 1
#audiocapturemode:i:value
#Microphone redirection: Indicates whether audio input redirection is enabled.
#- 0*: Disable audio capture from the local device
#- 1: Enable audio capture from the local device and redirection to an audio application in the remote session

$EncodeRedirectedVideoCapture = 1
#encode redirected video capture:i:value
#Enables or disables encoding of redirected video.
#- 0: Disable encoding of redirected video
#- 1*: Enable encoding of redirected video

$EncodeQualityRedirectedVideoCapture = 0
#redirected video capture encoding quality:i:value
#Controls the quality of encoded video.
#- 0*: High compression video. Quality may suffer when there is a lot of motion.
#- 1: Medium compression.
#- 2: Low compression video with high picture quality.

$AudioMode = 0
#audiomode:i:value
#Audio output location: Determines whether the local or remote machine plays audio.
#- 0*: Play sounds on the local computer (Play on this computer)
#- 1: Play sounds on the remote computer (Play on remote computer)
#- 2: Do not play sounds (Do not play)

$CameraRedirect = "*"
#camerastoredirect:s:value
#Camera redirection: Configures which cameras to redirect. This setting uses a semicolon-delimited list of KSCATEGORY_VIDEO_CAMERA interfaces of cameras enabled for redirection.
#- $NA*: Don't redirect any cameras
#- * : Redirect all cameras
#- List of cameras, such as camerastoredirect:s:\?\usb#vid_0bda&pid_58b0&mi
#- One can exclude a specific camera by prepending the symbolic link string with "-"

$PlugNPlayRedirect = "*"
#devicestoredirect:s:value
#Plug and play device redirection:
#Determines which devices on the local computer will be redirected and available in the remote session.
#- $NA*: Don't redirect any devices
#- *: Redirect all supported devices, including ones that are connected later
#- Valid hardware ID for one or more devices
#- DynamicDevices: Redirect all supported devices that are connected later

$DriveRedirect = "*"
#drivestoredirect:s:value
#Drive/storage redirection:
#Determines which disk drives on the local computer will be redirected and available in the remote session.
#- $NA*: Don't redirect any drives
#- No value specified: don't redirect any drives
#- * : Redirect all disk drives, including drives that are connected later
#- DynamicDrives: redirect any drives that are connected later
#- The drive and labels for one or more drives, such as "drivestoredirect:s:C:;E:;": redirect the specified drive(s)

$KeyboardHook = 2
#keyboardhook:i:value
#Determines when Windows key combinations (WIN key, ALT+TAB) are applied to the remote session for desktop connections.
#- 0: Windows key combinations are applied on the local computer
#- 1: Windows key combinations are applied on the remote computer when in focus
#- 2*: Windows key combinations are applied on the remote computer in full screen mode only

$ClipboardRedirect = 1
#redirectclipboard:i:value
#Clipboard redirection: Determines whether clipboard redirection is enabled.
#- 0: Clipboard on local computer isn't available in remote session
#- 1*: Clipboard on local computer is available in remote session

$ComPortsRedirect = 1
#redirectcomports:i:value
#COM ports redirection: Determines whether COM (serial) ports on the local computer will be redirected and available in the remote session.
#- 0*: COM ports on the local computer are not available in the remote session
#- 1: COM ports on the local computer are available in the remote session

$PrintersRedirect = 1
#redirectprinters:i:value
#Printer redirection: Determines whether printers configured on the local computer will be redirected and available in the remote session
#- 0: The printers on the local computer are not available in the remote session
#- 1*: The printers on the local computer are available in the remote session

$SmartCardsRedirect = 1
#redirectsmartcards:i:value
#Smart card redirection: Determines whether smart card devices on the local computer will be redirected and available in the remote session.
#- 0: The smart card device on the local computer is not available in the remote session
#- 1*: The smart card device on the local computer is available in the remote session

$UsbRedirect = "*"
#usbdevicestoredirect:s:value
#USB redirection
#- $NA*: Don't redirect any USB devices
#- *: Redirect all USB devices that are not already redirected by another high-level redirection
#- {Device Setup Class GUID}: Redirect all devices that are members of the specified device setup class
#- USBInstanceID: Redirect a specific USB device identified by the instance ID



# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.DesktopVirtualization"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionNameTest

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AVD | Configure-HostPool | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

function Fill-Integer($skey, $svalue)
{
    $posKey = $Global:properties.IndexOf("$($skey):i:")
    if ($posKey -eq -1)
    {
        $Global:properties += "$($skey):i:$($svalue);"
        return $true
    }
    else
    {
        if ($Global:properties.IndexOf("$($skey):i:$($svalue)") -gt -1)
        {
            return $false
        }
        else
        {
            $semiPos = $Global:properties.IndexOf(";", $posKey)
            if ($semiPos -gt -1)
            {
                $actVal = $Global:properties.Substring($posKey, $semiPos - $posKey)
            }
            else
            {
                $actVal = $Global:properties.Substring($posKey)
            }
            $Global:properties = $Global:properties.Replace($actVal, "$($skey):i:$($svalue)")
            return $true
        }
    }
    throw "Not expected"
}
function Fill-String($skey, $svalue)
{
    $posKey = $Global:properties.IndexOf("$($skey):s:")
    if ($posKey -eq -1)
    {
        if ($svalue -ne $NA)
        {
            $Global:properties += "$($skey):s:$($svalue);"
            return $true
        }
        return $false
    }
    else
    {
        if ($Global:properties.IndexOf("$($skey):s:$($svalue)") -gt -1)
        {
            return $false
        }
        else
        {
            $semiPos = $Global:properties.IndexOf(";", $posKey)
            if ($semiPos -gt -1)
            {
                $actVal = $Global:properties.Substring($posKey, $semiPos - $posKey)
            }
            else
            {
                $actVal = $Global:properties.Substring($posKey)
            }
            $replValue = "$($skey):s:$($svalue)"
            if ($svalue -eq $NA)
            {
                $actVal += ";"
                $replValue = ""
            }
            $Global:properties = $Global:properties.Replace($actVal, $replValue)
            return $true
        }
    }
    throw "Not expected"
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    throw "Ressource Group not found. Please create the Ressource Group $ResourceGroupName"
}

# Checking HostPool
Write-Host "Checking HostPool" -ForegroundColor $CommandInfo
$HstPl = Get-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $HstPl)
{
    throw "HostPool not found. Please create the HostPool $HostPoolName"
}

if ($HstPl.MaxSessionLimit -ne $HostPoolMaxSessionLimit)
{
    Update-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -MaxSessionLimit $HostPoolMaxSessionLimit
}

if ($HstPl.ValidationEnvironment -ne $IsTestHostPool)
{
    Update-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -ValidationEnvironment:$IsTestHostPool
}

# Configurations
$Dirty = $false
$Global:properties = $HstPl.CustomRdpProperty
if (-Not $properties)
{
    $Global:properties = ""
}
else
{
    $Global:properties = $properties.TrimEnd(";")+";"
}

if ($AllowNonAadJoinedDevices -ne $null)
{
    $Changed = Fill-Integer -skey "targetisaadjoined" -svalue $AllowNonAadJoinedDevices
    $Dirty = $Dirty -or $Changed
}
if ($AudioCapturingMode -ne $null)
{
    $Changed = Fill-Integer -skey "audiocapturemode" -svalue $AudioCapturingMode
    $Dirty = $Dirty -or $Changed
}
if ($EncodeRedirectedVideoCapture -ne $null)
{
    $Changed = Fill-Integer -skey "encode redirected video capture" -svalue $EncodeRedirectedVideoCapture
    $Dirty = $Dirty -or $Changed
}
if ($EncodeQualityRedirectedVideoCapture -ne $null)
{
    $Changed = Fill-Integer -skey "redirected video capture encoding quality" -svalue $EncodeQualityRedirectedVideoCapture
    $Dirty = $Dirty -or $Changed
}
if ($AudioMode -ne $null)
{
    $Changed = Fill-Integer -skey "audiomode" -svalue $AudioMode
    $Dirty = $Dirty -or $Changed
}
if ($KeyboardHook -ne $null)
{
    $Changed = Fill-Integer -skey "keyboardhook" -svalue $KeyboardHook
    $Dirty = $Dirty -or $Changed
}
if ($ClipboardRedirect -ne $null)
{
    $Changed = Fill-Integer -skey "redirectclipboard" -svalue $ClipboardRedirect
    $Dirty = $Dirty -or $Changed
}
if ($ComPortsRedirect -ne $null)
{
    $Changed = Fill-Integer -skey "redirectcomports" -svalue $ComPortsRedirect
    $Dirty = $Dirty -or $Changed
}
if ($PrintersRedirect -ne $null)
{
    $Changed = Fill-Integer -skey "redirectprinters" -svalue $PrintersRedirect
    $Dirty = $Dirty -or $Changed
}
if ($SmartCardsRedirect -ne $null)
{
    $Changed = Fill-Integer -skey "redirectsmartcards" -svalue $SmartCardsRedirect
    $Dirty = $Dirty -or $Changed
}
if ($CameraRedirect -ne $null)
{
    $Changed = Fill-String -skey "camerastoredirect" -svalue $CameraRedirect
    $Dirty = $Dirty -or $Changed
}
if ($PlugNPlayRedirect -ne $null)
{
    $Changed = Fill-String -skey "devicestoredirect" -svalue $PlugNPlayRedirect
    $Dirty = $Dirty -or $Changed
}
if ($DriveRedirect -ne $null)
{
    $Changed = Fill-String -skey "drivestoredirect" -svalue $DriveRedirect
    $Dirty = $Dirty -or $Changed
}
if ($UsbRedirect -ne $null)
{
    $Changed = Fill-String -skey "usbdevicestoredirect" -svalue $UsbRedirect
    $Dirty = $Dirty -or $Changed
}

if ($Dirty){
    if ($properties.Length -gt 0)
    {
        $properties = $properties.TrimEnd(";")
    }
    else
    {
        $properties = $null
    }
    Write-Warning "Setting CustomRdpProperty to"
    Write-Warning "$properties"
    Update-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -CustomRdpProperty $properties
}

# Checking HostPool RegistrationInfo
Write-Host "Checking HostPool RegistrationInfo" -ForegroundColor $CommandInfo
$HstPlRegInf = Get-AzWvdRegistrationInfo -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if ((-Not $HstPlRegInf) -or (-Not $HstPlRegInf.Token))
{
    Write-Warning "HostPool RegistrationInfo not found. Creating the HostPool RegistrationInfo"
    $HstPlRegInf = New-AzWvdRegistrationInfo -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
        -ExpirationTime $((get-date).ToUniversalTime().AddDays(1).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))
}

#Stopping Transscript
Stop-Transcript
