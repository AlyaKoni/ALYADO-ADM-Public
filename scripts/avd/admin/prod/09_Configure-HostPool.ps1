#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

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
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\prod\Configure-HostPool-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.DesktopVirtualization"

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdManagementResGrp)"
$HostPoolName = "$($AlyaNamingPrefix)avdh$($AlyaResIdAvdHostpool)"
$HostPoolMaxSessionLimit = $AlyaAvdMaxSessions
$IsTestHostPool = $false #needs to be $true to use AllowNonAadJoinedDevices so far

#special na handling
$na = "{[(N/A)]}"
#use $null if you dont want to take into account a value
#more settings: https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-properties

$EnableRdsAadAuth = $null
#enablerdsaadauth:i:value
#Determines whether the client will use Microsoft Entra ID to authenticate to the remote PC. When used with Azure Virtual Desktop, this provides a single sign-on experience. This property replaces the property targetisaadjoined.
#- 0*: Connections won't use Microsoft Entra authentication, even if the remote PC supports it.
#- 1: Connections will use Microsoft Entra authentication if the remote PC supports it.
#
# Replaces this setting: $AllowNonAadJoinedDevices = $null
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

$DynamicResolution = 1
#dynamic resolution:i:value
#Determines whether the resolution of the remote session is automatically updated when the local window is resized
#- 0: Session resolution remains static during the session
#- 1*: Session resolution updates as the local window resizes

$SingleMonInWindowedMode = 1
#singlemoninwindowedmode:i:value
#Determines whether a multi display remote session automatically switches to single display when exiting full screen. Requires use multimon to be set to 1
#- 0*: Session retains all displays when exiting full screen
#- 1: Session switches to single display when exiting full screen

$SmartSizing = 1
#smart sizing:i:value
#Determines whether or not the local computer scales the content of the remote session to fit the window size
#- 0*: The local window content won't scale when resized
#- 1: The remote session will appear full screen

$UseMultimon = 1
#use multimon:i:value
#Determines whether the remote session will use one or multiple displays from the local computer
#- 0: Don't enable multiple display support
#- 1*: Enable multiple display support

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

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

if ($null -ne $EnableRdsAadAuth)
{
    $Changed = Fill-Integer -skey "enablerdsaadauth" -svalue $EnableRdsAadAuth
    $Dirty = $Dirty -or $Changed
}
#if ($null -ne $AllowNonAadJoinedDevices)
#{
#    $Changed = Fill-Integer -skey "targetisaadjoined" -svalue $AllowNonAadJoinedDevices
#    $Dirty = $Dirty -or $Changed
#}
if ($null -ne $AudioCapturingMode)
{
    $Changed = Fill-Integer -skey "audiocapturemode" -svalue $AudioCapturingMode
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $EncodeRedirectedVideoCapture)
{
    $Changed = Fill-Integer -skey "encode redirected video capture" -svalue $EncodeRedirectedVideoCapture
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $EncodeQualityRedirectedVideoCapture)
{
    $Changed = Fill-Integer -skey "redirected video capture encoding quality" -svalue $EncodeQualityRedirectedVideoCapture
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $AudioMode)
{
    $Changed = Fill-Integer -skey "audiomode" -svalue $AudioMode
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $KeyboardHook)
{
    $Changed = Fill-Integer -skey "keyboardhook" -svalue $KeyboardHook
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $ClipboardRedirect)
{
    $Changed = Fill-Integer -skey "redirectclipboard" -svalue $ClipboardRedirect
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $ComPortsRedirect)
{
    $Changed = Fill-Integer -skey "redirectcomports" -svalue $ComPortsRedirect
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $PrintersRedirect)
{
    $Changed = Fill-Integer -skey "redirectprinters" -svalue $PrintersRedirect
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $SmartCardsRedirect)
{
    $Changed = Fill-Integer -skey "redirectsmartcards" -svalue $SmartCardsRedirect
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $CameraRedirect)
{
    $Changed = Fill-String -skey "camerastoredirect" -svalue $CameraRedirect
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $PlugNPlayRedirect)
{
    $Changed = Fill-String -skey "devicestoredirect" -svalue $PlugNPlayRedirect
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $DriveRedirect)
{
    $Changed = Fill-String -skey "drivestoredirect" -svalue $DriveRedirect
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $UsbRedirect)
{
    $Changed = Fill-String -skey "usbdevicestoredirect" -svalue $UsbRedirect
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $DynamicResolution)
{
    $Changed = Fill-Integer -skey "dynamic resolution" -svalue $DynamicResolution
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $SingleMonInWindowedMode)
{
    $Changed = Fill-Integer -skey "singlemoninwindowedmode" -svalue $SingleMonInWindowedMode
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $UseMultimon)
{
    $Changed = Fill-Integer -skey "use multimon" -svalue $SingleMonInWindowedMode
    $Dirty = $Dirty -or $Changed
}
if ($null -ne $SmartSizing)
{
    $Changed = Fill-Integer -skey "smart sizing" -svalue $SmartSizing
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

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDGxy3Kxs5FfwRh
# s/BNb7oXsmOvDewB2PE4m3NUrHnkY6CCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMpU3FvT8PWJ8D3u
# OVUvXYWN1/72tT4WpzczTq+TvLUdMA0GCSqGSIb3DQEBAQUABIICAAA6ZbOKiHUs
# 5VV75xStiPqxfZeBnKniMf61XmuK3nYHhivIGy8HBU0KaNdinKUpLjAJV7JK5st/
# jyXnWX7rWKawHs3u+0swT0xeIzLBx82VxgB3SS1bh8X3bEm8eyy1A9Q4wFeM/hvv
# BcFT8y/ZaHwIZrFLw7Tc+EfmB/tlyEL7H/qToV7UMkDjrBobghb6Xw+eFoT5821z
# EnC7fhCTpxlxlMydajErgEebfk9tySZYEGuSmD+hP6PVsLADHlaFCIsXeBGvl8Cd
# 9OYOZuotyEbsnH5cNt0eF/E+b0Cdm3TdzvLH8oGTs6P7ab+ebUJiq8xfZW1AsVEI
# UNQ0GqUuiStIOC9FcTqVkyd26zi5+oOER0Z5RWd7QDIX3IL6h99DdugTr8sdriJN
# 6FJ9CDmNeH880YNmSUu2eE2UFCSwu+OcS5iNkGdLhqUWCqeT2DAHKprATGm53Dn5
# Q/wcm64zfIDGXisPkQDze+kxtpHT9KZz2uYSygn10Fv7xHE1pp8YO0aRu8pAwruv
# x4Pd5y9BK29IsWbGArmht7iiUyULp94gwlPzDBpGfcUvYxwJv/6XtL3PoFtrfIjJ
# zN7rTVm+t75P/hN6Sc6Z+B+TiMzMHAoL403bQbHaslMQ+jMe8qMku9PueqruKJdw
# h3++DudrOKiSiKsFM1AtJLUo2gb7AUKuoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCAd2F9XdkJcy+tI5IZCFJjWvDzE/c9yLbl4w0AnSwkkywIUb6udVMIcWt48
# ZXvcWJNEkBxlXjgYDzIwMjYwMTI3MTAxMzAzWjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
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
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# ILdjyLRiWIokLRM2/U5qLjXSzOVXp5xU1F2bctJPhfETMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAmo99PTm1jU+q
# r/IueAG6hcEdFJQy45lsk3oYMhQrFpuJ+Y9akjfO8Wsl4+v1rWHa5GGGuy8Etavf
# wh66YB6pBNKQhVHpaYOqeGbNeF15JYnFlFOHeCBs7pL0Q/bt/2scM489qYM1iZvc
# in48IWVSpUJ/AAmr+QHJFaekJmo1ugFmPP7U3jOfDFmt3Y9TFGtUsNvU+jiuyxf1
# /CFeCGGb+nU9HpoZe92ToiiwsVkGakgAWBW7qiIqn0HlnlYOqaFojlqTCxOLdUo8
# 3ai44LiA2f5VeRZS5VKdQpMVIRmQnV+H6WsCb6z302NThQXBna8NR96en1m5RZ51
# Yc8g3BSz6G/fK9r2271ipH5CLUCHCnUkpZ4Sv96I8owIeCWEkvv+QBNqmPs8nW51
# Xu8hILgUBVC5UcZirRZ5NIu40CFbJtyw+KjIMCPQZYRYNBPaw3UbzgaPTTsWZWlC
# Eud3RG0PR6o23Hg6iJ3KLWn39XXfQvX4ftqG3PjKaihet2zPr/YP
# SIG # End signature block
