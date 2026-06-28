#Requires -Version 2.0

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
    29.09.2020 Konrad Brunner       Initial Version
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Uninstalls KeePass Password Safe from the system, ensuring execution in a 64-bit PowerShell environment and logging the process.

.DESCRIPTION
The Uninstall.ps1 script verifies whether it is running in a 64-bit PowerShell session and, if not, restarts itself appropriately. It searches the Windows registry for installations of KeePass Password Safe published by Dominik Reichl, retrieves the associated uninstall command, and executes it silently. The script records its activity and the uninstallation process in log files stored under C:\ProgramData\AlyaConsulting\Logs. It handles both 32-bit and 64-bit registry locations to ensure all installations are removed.

.INPUTS
None. The script does not accept pipeline input.

.OUTPUTS
Int32. Returns the exit code of the uninstallation process.

.EXAMPLE
PS> .\Uninstall.ps1
Runs the script to silently uninstall KeePass Password Safe and logs the process.

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
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
    Start-Transcript -Path "C:\ProgramData\AlyaConsulting\Logs\$($AlyaScriptName)-KeePass-$($AlyaTimeString).log" -Force

    try
    {
        $ErrorActionPreference = "Stop"

        $regPlats = @("","\WOW6432Node")
        foreach($regPlat in $regPlats)
        {
            foreach($reg in (Get-ChildItem -Path "HKLM:\SOFTWARE$regPlat\Microsoft\Windows\CurrentVersion\Uninstall"))
            {
                $displayName = $null
                $publisher = $null
                $uninstallString = $null
                try {
                    $displayName = Get-ItemPropertyValue -Path $reg.PSPath -Name "DisplayName" -ErrorAction SilentlyContinue
                } catch {}
                try {
                    $publisher = Get-ItemPropertyValue -Path $reg.PSPath -Name "Publisher" -ErrorAction SilentlyContinue
                } catch {}
                if ($displayName -like "KeePass Password Safe*" -and $publisher -eq "Dominik Reichl")
                {
                    Write-Host "Uninstalling $displayName"
                    Write-Host "with infos from $($reg.Name)"
					try {
						$uninstallString = Get-ItemPropertyValue -Path $reg.PSPath -Name "QuietUninstallString" -ErrorAction SilentlyContinue
					} catch {}
                    if (-Not $uninstallString)
                    {
                        $uninstallString = (Get-ItemPropertyValue -Path $reg.PSPath -Name "UninstallString") + " /SILENT"
                    }
                    if (-Not $uninstallString.ToLower().Contains("msiexec"))
                    {
                        $uninstallStringNew = ""
                        $uninstallParts = $uninstallString.Split()
                        foreach($uninstallPart in $uninstallParts)
                        {
                            if (($uninstallStringNew -eq "") -and (-Not $uninstallPart.StartsWith("`"")))
                            {
                                $uninstallStringNew += "`""
                            }
                            if ($uninstallPart.Contains(".exe") -and -not $uninstallPart.Contains("`""))
                            {
                                $uninstallPart = $uninstallPart + "`""
                            }
                            $uninstallStringNew += $uninstallPart + " "
                        }
                        $uninstallString = $uninstallStringNew
                    }
                    else
                    {
                        $uninstallString = $uninstallString -replace " /I", " /X"
                        if (-Not $uninstallString.Contains("/quiet"))
                        {
                            $uninstallString += " /quiet"
                        }
                        if (-Not $uninstallString.Contains("/norestart"))
                        {
                            $uninstallString += " /norestart"
                        }
                    }
                    $uninstallString += " /L* `"C:\ProgramData\AlyaConsulting\Logs\KeePass-Uninstall-$AlyaTimeString.log`""
                    Write-Host "command: $uninstallString"
                    Write-Host "EXE Start: $((Get-Date).ToString("yyyyMMddHHmmssfff"))"
                    cmd /c "$uninstallString"
					$exitCode = $LASTEXITCODE
					Write-Host "CMD returned: $exitCode at $((Get-Date).ToString("yyyyMMddHHmmssfff"))"
                    do
                    {
                        Start-Sleep -Seconds 5
                        $process = Get-Process -Name "unins000.exe" -ErrorAction SilentlyContinue
                    } while ($process)
                    Write-Host "EXE End: $((Get-Date).ToString("yyyyMMddHHmmssfff"))"
                }
            }
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

# SIG # Begin signature block
# MII2OgYJKoZIhvcNAQcCoII2KzCCNicCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAD+3svYzCZfKLc
# loyeoSs0DZ75+BrA148XX3heUONYQ6CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxgiEFMIIhAQIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHL0gvhU
# CHny8f80VNuC0uCzXOZ9xpP2r7woHz00dw7xMA0GCSqGSIb3DQEBAQUABIICAGQt
# a/aV7Qxg/T1+Xq8kgOnSwKT9bkt/jGDE5g4fsNjuzLI9mh9Bj3zAWHBTbN6P+xtR
# 4zQ1/sedMencFeQC/B8vEbVbUBttoXxwXNAxnll2xWuQYm6Qo+ndQTgSgdlQG8cw
# 6IrEST3hw56wpEzeA2qOTcwDb6jkocF6YwhlzkXc6jBoHwR0+vxjnLFYtVknLZkX
# kG4hwUGqzaA3AObAPs6Vhod02/7QdMkfUlnT5kbEFL0LmXxzObXu8mfen1twXAGR
# Z288Xv3YYvMOYjsczUCOL0zfVOOczCHpuhgX8GYZtMv1OiBY5pAil7anHJr1O43C
# +o4wz+qsy+H4qT9pFGk9HF9Ds5VhYI4XauyMdd2VlIKDhMbbMHXkYKx1Lf9MQmDj
# rYWcMMzD6SFsZS3pmQq7NWBTyCK/OgU8FOGsd58f6HOZpy13OrZUdZH3eydLPb/d
# fqR/O8dN20QU/w2oK6zlpcIimbhgA0x/66i1RRNJ0oscGSBavKoxmvhSVNonhHGc
# 3yy5TN02ArXzGoW2sZ7bQOwjTJtK17ZQBVziuIezVCG4fV8EM0QUXrSGD6G7q47B
# 55N/J7sOZ2q7njzRNR3dREtShrmJHhjW0cfka1sqFtOs4AvVBTgMS5Df7Xk4VuhO
# f0i8I3QiwTGZN3R41P3CZJ7++qvNFH1/cfPmPaO/oYId7DCCHegGCisGAQQBgjcD
# AwExgh3YMIId1AYJKoZIhvcNAQcCoIIdxTCCHcECAQMxDTALBglghkgBZQMEAgIw
# geMGCyqGSIb3DQEJEAEEoIHTBIHQMIHNAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCCxFwTAyLoPLGn/VIPghFoKfJ/NyfTgpffv+hYG7bpuLgITKJDu
# VRatmgswP61ME4utr/cgmhgPMjAyNjA2MjYwODQ0NTVaMAMCAQGgXaRbMFkxCzAJ
# BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMS8wLQYDVQQDEyZH
# bG9iYWxzaWduIFI0NSBUU0EgZm9yIENvZGVTaWduIDIwMjUxMKCCGWAwggaKMIIE
# cqADAgECAhEAhHI/wZXMFvHbK6L2YN8r5DANBgkqhkiG9w0BAQwFADBeMQswCQYD
# VQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xv
# YmFsU2lnbiBPZmZsaW5lIFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNTAeFw0yNTEw
# MTUwNzI1MDRaFw0zNzAxMTAwMDAwMDBaMFkxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMS8wLQYDVQQDEyZHbG9iYWxzaWduIFI0NSBUU0Eg
# Zm9yIENvZGVTaWduIDIwMjUxMDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoC
# ggGBANFKjaGNhkBIKKMJBJzZExA88qiMT/F/hSKNrYmewntKeXaAOjEqND0dxTqt
# UPymDLWwEp1XG0ssWFjeDNj88DaLAizpnMKfGyG2NKGw3VHLNGvNzgWr7TFDHqoA
# NQyf3qaocT/SiTncM9uakGSRQPK0Yzv2dB/D1ZXKZiAD5ORsDT9A6Y800khnoKNf
# S3fAl+EvRxqJe2EEEwRYrFPm/ZTtlFsKr8NUNcD2hfWIVUFVoGnHnswsvTSfIe7H
# QidhLtGvngze02Gbv7SZrGnJMVrnW5jU8e1Mky6n+XdEaihDljB4IfaEOhQ3Ao4L
# tCQVuSWE92rbsReS56Dyos6dEOZU7Wv4HXIwBuXpC5XQv448HVIoEA+mYgWSWYnR
# KiJttSrGxPN6ON0j7LBAtRxeKWiDApawnjqHrCOVTkBWpPsUQFjNYJO3qF/tItBs
# 8azTYFryhpo1+jRIv5oCk33iW4QH/C4TWWCm2tyQvNtCUKnno6CQAlimpi66L5N+
# 54IhTQIDAQABo4IBxjCCAcIwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoG
# CCsGAQUFBwMIMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDL60+EHaCeQawjSPx08
# jGU2KAYZMB8GA1UdIwQYMBaAFHcCOwExDx50d8NIyMMHY1WIpTuiMIGlBggrBgEF
# BQcBAQSBmDCBlTBCBggrBgEFBQcwAYY2aHR0cDovL29jc3AuZ2xvYmFsc2lnbi5j
# b20vZ3NvZmZsaW5lcjQ1dGltZXN0YW1wY2EyMDI1ME8GCCsGAQUFBzAChkNodHRw
# Oi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc29mZmxpbmVyNDV0aW1l
# c3RhbXBjYTIwMjUuY3J0MEoGA1UdHwRDMEEwP6A9oDuGOWh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vZ3NvZmZsaW5lcjQ1dGltZXN0YW1wY2EyMDI1LmNybDBWBgNV
# HSAETzBNMAgGBmeBDAEEAjBBBgkrBgEEAaAyAR4wNDAyBggrBgEFBQcCARYmaHR0
# cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQEM
# BQADggIBAI6ucKaPR4aRim6eLPr9YWb3WzoqOeGQwpiVtx+2CkwG2WHKxWeIQ58G
# +Fy+gVDDgA4cb01FW9mmQGdqDkO3UczcmDbWBFUIHAXI/URPwgPGh+VjHk4PhII0
# sezq8KDqsWQ1PzW/1nLy7TFfLdZug3mIr9JtOYsaoKsAYmKEsut8iG913BWt0HKI
# e14vGCO6BPolCiAJKgEXYmqYfRkEKXnXlu1tO5ZkutBSzm++Xaj3wx2O73LIlFYv
# M9VxSRGT13zEEGLrfwUE4C6jd9zJOEZyd7vBQ5r5OCGHAgdtnenFNimCjlwLERmw
# fwRfCJNRPAd/Sp6yyyD/Zd1wYfuzQBHhPI4nZCcBrJg4Az9c4HE3NRFCDiaEx08v
# 8XxUIwqPeSglpVzHZqSHQHzaV79oFTyrY5r747A7CIcXl75/2b7KHJhvAZKiBYhX
# eGBGX5XIqtyHyC/fkUev9xXPyfT8I8ZFcaJglns/XA46Bh2QwPaIMpVhBvLkjH/E
# IHT+VIoueoSgV7N+acIlsaAAJWzAyzGEkRSO3ERxBz1p9qWd74g62zS//IJGKQmy
# eZVtLTHnQOTY4f5UKJT2z9fLOB8LtbOu1Dl2Ih1zYqyLckxMmbhrQuIQhlaK0Pn7
# o+iQ6RDz7flOwc7BSGzzsj/LImOUhmkBXg5/X8k3xtZUHcR2bhbOMIIGoDCCBIig
# AwIBAgIRAIPahje3nwyEDJR7hApSeB8wDQYJKoZIhvcNAQEMBQAwUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gVGltZXN0YW1waW5nIFJvb3QgUjQ1MB4XDTI1MDcxNjAzMDUwNFoXDTQx
# MDcxNjAwMDAwMFowXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1w
# aW5nIENBIDIwMjUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCkdxb4
# 7X2L4t0ChkVjNL7lf5Zi+dagWpcB+KvWHKeFRN0fhFbUNv7I6atDbvmOWxDpvOhn
# ec3QIydxlfgTRCGmnpC/Hbv5+Wl/N4xBpwPtVyJZSIXdMuK7vBPZsEJIQ1SfeF8Y
# wbg8m9gW87mjgMDWI28eEbihLNy2h2gl9vhzwSNVqELD80uLMHetr41Z7aBkFJpk
# qtozEW3rvrKrHtFxCeNsXhHQ4sai+xm3be9Tr0DkF2g/F0D3O72sz6pMGw8NVQl7
# FjARVTQZjsEnmZRZaeLIA8dbRa/gDOTm3sjRdQiMDf7Y4aSvR1UFdUEPIR4YFWth
# cR2F9UvC6HocEYkV0isRjkqgaWmhP7gEFB7hcIfmy/XlSj4zvZUpaM8DkTHed8Uk
# Lg/kVbVJHqiUJJoiu2dnNz7OCalLKIP4ZwTa51BFAdsOLvh6deBrOTT6S2kdnVny
# hO9JpIhESi9dItsfcoLy4UiRe5yXtc8ftkYiuYX14XjO6ijkUhSey9XrSQuoUPM+
# T5RsuaBkNQI+UUUEF6Fpo2+LETKbH043Ypd6/4x8ro5kKGoZus4LbC+8AUfIqVNl
# tUd2o2K7S7lrZPUL11JNGfLX+HEvBzEv0FY/NAvCGyLJepTMzu4PSUP349gxrFRi
# ChVLGpvjG88KJWos1psj5a2MTNh9DQ/7q0FMWwIDAQABo4IBYjCCAV4wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBIGA1UdEwEB/wQIMAYBAf8C
# AQAwHQYDVR0OBBYEFHcCOwExDx50d8NIyMMHY1WIpTuiMB8GA1UdIwQYMBaAFEay
# HHfhexXwpTmhcN7RxC7qbbLeMIGOBggrBgEFBQcBAQSBgTB/MDcGCCsGAQUFBzAB
# hitodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1MEQG
# CCsGAQUFBzAChjhodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC90
# aW1lc3RhbXByb290cjQ1LmNydDA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
# Lmdsb2JhbHNpZ24uY29tL3RpbWVzdGFtcHJvb3RyNDUuY3JsMBEGA1UdIAQKMAgw
# BgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAgEAMqPuftFu5GYxllheqUw9EmhHpfWf
# /+q5cYtV86kWhH1hrTkv3jDTLAGN6XIYZ/6cAH4JkVDuBQ53ZrZul+lbxfDkCsz5
# iM8R/wC0LgTpivXTlTVg2OVNIRGhYkpzWGRI3mbh2mxi14XKTMVBXBfnSFgoffJn
# pVy7odrQQDmh/MumLaMraNtEMJdsU0uLmY7XEpF0HYDMAXR/kLTRvgfd3mwI4Hye
# NO8DBpMwYQx5OQtYzhn1j7dQ606mjVC7FdsOldWQtetobbmIvVW2+PEQDLjnfidQ
# g0H3CE5GJwklJMttrp84rZ//VAZYR17BYscDMT43mgfRCg1EAuknkmMh94ie876x
# B0GJ2c+4son3kdOPtfIy8mEVmO1sckaURbHhSApy40osMtdYAt/BAM3YN7LeRN93
# jLDidB2TU9y0ssrcXgvaecu/3gEySlj5F+Xneg4Q3jJO+3AJg/5UO5muS1zs1pyh
# NXFmcoaS/xrVqRyR07BBkL6LwDLVXLMwBf9Nvj6vdzrkHtykC2rc6hSKNdQmC9nF
# yLpNfvyyYvZNjLa1af7wbiSude/LYQtHZdicoQ5LgxWatIKyMzmfFKuCETXRUNdB
# sR9r3eWGKR8Wgi4g0rNYMuq+7xm5ybES5/GkeM2edFVdf9m/kpCrym78xCg7PoML
# vifn47ltLC9PmyAwggajMIIEi6ADAgECAhB4SqqBc2ackAlU5CHJR+vAMA0GCSqG
# SIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMw
# EQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTIwMTIw
# OTAwMDAwMFoXDTM0MTIxMDAwMDAwMFowUzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAunQz
# 7CfcEjghG8XTYSjWWrxP34vMkYRDJFe8ZCG8OxwfPU+MrQe388XXAukRFIKaqrSU
# cjtxDRrvaGuFeY6vZupYmA26wXx50v/Ns28xRdAFdAQAcmonfrg3PzqI7ZeD9as1
# TQ+fWTv1L99ZxXylMnZglsjt7vgEfhlRcqi/REF6vHseOwCbvLrglr+Q/o2bw3KL
# ABL4IDpgOPfBzIWK+4d5LqErIObLoIWRI7bEKAdUKN7sEDFPivLNFB8e3VUc6igx
# TPkhaqjN85Zn+gFBm80PC2h/u97xQ+oX5bDccCKzaTZZdGvG5YkqfOULgV2rP4+4
# 0XZy83yiqeKXQb/MjEX+Ycn2bAcLAAToFSNPgiot9u/D+hE2SKHR/Xo5OjRdoywO
# m3dQIDRA3bEDMa1f6WKHc5YDYfeUsNlcbE/nFMXh8XsNI5zNcIwdat5KLYsqu9tC
# FAUHqvsU3DHT9h9sy75oZkRwTW0X+XHrBXOOkZJ162hcHvZEYRgpYt0XZojsKLpJ
# b9s+d/65MR91HBiipke92O5IhTv9s+IPPyqYxpr6gm+xpaWGHVo6+qRsdA93UmFq
# f4cp3jmbi+6zRWAwJJcVEiqFMJMmrJamLehwbQupMq0smygKdkLyVWFRmJTe7fbF
# F288FRCwDq2w3sUW9GXRzC9aVgjPmcTwVZHCLHkCAwEAAaOCAXgwggF0MA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDAPBgNVHRMBAf8EBTADAQH/
# MB0GA1UdDgQWBBRGshx34XsV8KU5oXDe0cQu6m2y3jAfBgNVHSMEGDAWgBSubAWj
# kxPioufi1xzWx/B/yGdToDB7BggrBgEFBQcBAQRvMG0wLgYIKwYBBQUHMAGGImh0
# dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjYwOwYIKwYBBQUHMAKGL2h0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L3Jvb3QtcjYuY3J0MDYG
# A1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC1y
# Ni5jcmwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8v
# d3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBDAUAA4IC
# AQCLSLo2Vzxyxdp1+e8y9Ya93BIo44guTzZfJpnsDwEhEJaSOMZwa23zrtQOvSXv
# hn/iiY2VpX4pRANNqpio8bfc6iljIdztzYgKyxBpYXkpQgwjvOnF71IeLzM31U9m
# emapR1Qzsd0W8thkcaMxlOVv9k1L4oRs0MklZ0/IS9DOSwXWPft9QfqKscAh4H4I
# sNlkK/nq8scK9M8uDDRg7my7kvA/8XtSEmh3WYH1HC6kOow5Aw3t5cyvZkh5Y9VJ
# uP9L0iVPSE6TO5N3sJpIbLagHbN0nl+9IgQ7fDcNhbXDmrvdnFoDjbQNn0x2NNWF
# rUV7tZ+7Lom7rMi/kmNIxj/KF6oNvAARX4vo40OEikM0zf07wKJ72x+4Z8iMFd4/
# pn/HKO+hb2+yQc8CIusB+EvI0nZvJd9e2mhoPXtEBMJBbkk7p5hWBO3RJisElNvk
# 7WaOPYCdpKRVeVBe4/gaH8AWb5AVPIqmSKEMe7oq4LGphwVGm+0lVT03aZjtRpmY
# hUcKHmLb/ZzlwUNCjr3Pb/aMkf2C5J/sreOVVQXzSS9tNPf/Z+6ZQLvTmoBCQNoj
# iWAfg3GStenmygr53cdsslhBnGaNmypvH29XBENcg107aZzeOfqETTXzextti/Fv
# A8EpUuKUv3tUi99AegtwAnc/L4gHAgB10q/G1iIyGaM76DCCBYMwggNroAMCAQIC
# DkXmuwODM8OFZUjm/0VRMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2Jh
# bFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQD
# EwpHbG9iYWxTaWduMB4XDTE0MTIxMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowTDEg
# MB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2Jh
# bFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQCVB+hzymb57BTKezz3DQjxtEULLIK0SMbrWzyug7hBkjMUpG9/
# 6SrMxrCIa8W2idHGsv8UzlEUIexK3RtaxtaH7k06FQbtZGYLkoDKRN5zlE7zp4l/
# T3hjCMgSUG1CZi9NuXkoTVIaihqAtxmBDn7EirxkTCEcQ2jXPTyKxbJm1ZCatzEG
# xb7ibTIGph75ueuqo7i/voJjUNDwGInf5A959eqiHyrScC5757yTu21T4kh8jBAH
# OP9msndhfuDqjDyqtKT285VKEgdt/Yyyic/QoGF3yFh0sNQjOvddOsqi250J3l1E
# LZDxgc1Xkvp+vFAEYzTfa5MYvms2sjnkrCQ2t/DvthwTV5O23rL44oW3c6K4NapF
# 8uCdNqFvVIrxclZuLojFUUJEFZTuo8U4lptOTloLR/MGNkl3MLxxN+Wm7CEIdfzm
# YRY/d9XZkZeECmzUAk10wBTt/Tn7g/JeFKEEsAvp/u6P4W4LsgizYWYJarEGOmWW
# WcDwNf3J2iiNGhGHcIEKqJp1HZ46hgUAntuA1iX53AWeJ1lMdjlb6vmlodiDD9H/
# 3zAR+YXPM0j1ym1kFCx6WE/TSwhJxZVkGmMOeT31s4zKWK2cQkV5bg6HGVxUsWW2
# v4yb3BPpDW+4LtxnbsmLEbWEFIoAGXCDeZGXkdQaJ783HjIH2BRjPChMrwIDAQAB
# o2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU
# rmwFo5MT4qLn4tcc1sfwf8hnU6AwHwYDVR0jBBgwFoAUrmwFo5MT4qLn4tcc1sfw
# f8hnU6AwDQYJKoZIhvcNAQEMBQADggIBAIMl7ejR/ZVSzZ7ABKCRaeZc0ITe3K2i
# T+hHeNZlmKlbqDyHfAKK0W63FnPmX8BUmNV0vsHN4hGRrSMYPd3hckSWtJVewHuO
# mXgWQxNWV7Oiszu1d9xAcqyj65s1PrEIIaHnxEM3eTK+teecLEy8QymZjjDTrCHg
# 4x362AczdlQAIiq5TSAucGja5VP8g1zTnfL/RAxEZvLS471GABptArolXY2hMVHd
# VEYcTduZlu8aHARcphXveOB5/l3bPqpMVf2aFalv4ab733Aw6cPuQkbtwpMFifp9
# Y3s/0HGBfADomK4OeDTDJfuvCp8ga907E48SjOJBGkh6c6B3ace2XH+CyB7+WBso
# K6hsrV5twAXSe7frgP4lN/4Cm2isQl3D7vXM3PBQddI2aZzmewTfbgZptt4KCUhZ
# h+t7FGB6ZKppQ++Rx0zsGN1s71MtjJnhXvJyPs9UyL1n7KQPTEX/07kwIwdMjxC/
# hpbZmVq0mVccpMy7FYlTuiwFD+TEnhmxGDTVTJ267fcfrySVBHioA7vugeXaX3yL
# SqGQdCWnsz5LyCxWvcfI7zjiXJLwefechLp0LWEBIH5+0fJPB1lfiy1DUutGDJTh
# 9WZHeXfVVFsfrSQ3y0VaTqBESMjYsJnFFYQJ9tZJScBluOYacW6gqPGC6EU+bNYC
# 1wpngwVayaQQMYIDYTCCA10CAQEwczBeMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5lIFI0
# NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwCwYJYIZI
# AWUDBAICoIIBQTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcN
# AQk0MR4wHDALBglghkgBZQMEAgKhDQYJKoZIhvcNAQEMBQAwPwYJKoZIhvcNAQkE
# MTIEMBPnACqcZ3zoZ8AduXrV81x151uJBE8EeOU9MbQC9z3WDYejplskXAgZIJJw
# wqNw3DCBtAYLKoZIhvcNAQkQAi8xgaQwgaEwgZ4wgZsEIIMq1y5SP96sg/pGlLzn
# xswmF2SIKGZWZYjIrco6g4VRMHcwYqRgMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUg
# UjQ1IFRpbWVzdGFtcGluZyBDQSAyMDI1AhEAhHI/wZXMFvHbK6L2YN8r5DANBgkq
# hkiG9w0BAQwFAASCAYAByBcIgew2pb1A/pKQwf39Qv0KrKBzxjChBs6T6IQMXfdr
# 5x0Uq1aJNl9Z8cOFo1VX43etxHgHsJIrfqovSKz24gSi5wN86AV6nuG0prDvqK2y
# zng8gsCLDW2RTEobxfcTYdeLu0mxGSt+7RskPn43u5cuSxN6rLrgtaKgYuBkvDAR
# CfdkFBEPXTf6jRQlIxMwWjvSyZD90IabDEiqFMipsRGkyjEVPp13uaz73W2mjklm
# +PVH2iuInnxooqlJfAc1VM7t65+E55ZP6/opaquTXCRaYJA6umJdUscW62v2TSVU
# DqeUKxm44wpK1QCrp4xy4ZX3Io6ixmENzVtsTpXuO0Rt+w27YkvlCKMa1CDkt//r
# xELP1Ip4pKCKsVivqZGjJA+OxkL1/JJf03MHmBi4evc6jW38klVazhCLPbJLiqND
# +eGJ1QfHKPikl0vEqsZe2o4zs6vUGjGCWfdrC+crR5hp6IZSSBz1W787ZFMXZUlm
# uPQGnP+HdjWXbCuRMrk=
# SIG # End signature block
