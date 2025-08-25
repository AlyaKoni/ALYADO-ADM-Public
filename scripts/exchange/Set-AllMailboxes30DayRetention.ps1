#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2025

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
    07.07.2020 Konrad Brunner       Initial Creation
    25.10.2020 Konrad Brunner       Changed from service user to new ExchangeOnline module
    16.07.2024 Konrad Brunner       Added Set-MailboxPlan

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Set-AllMailboxes30DayRetention-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "EXCHANGE | Set-AllMailboxes30DayRetention | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Setting retention in exchange"
try
{
    Write-Host "  Connecting to Exchange Online" -ForegroundColor $CommandInfo
    try {
        LoginTo-EXO
    }
    catch {
        Write-Error $_.Exception -ErrorAction Continue
        LogoutFrom-EXOandIPPS
        LoginTo-EXO
    }

    Get-Mailbox -ResultSize unlimited -Filter "RecipientTypeDetails -eq 'UserMailbox'" | Set-Mailbox -RetainDeletedItemsFor 30
    Set-MailboxPlan -Identity "ExchangeOnlineEnterprise" -RetainDeletedItemsFor 30
}
catch
{
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYgYJKoZIhvcNAQcCoIIpUzCCKU8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAVCQLQMzq4OrPJ
# FNeKzU6Ctt5z13vxjPE3SizFft163aCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# ghnTMIIZzwIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIG+Tlfwkt+nihWhW
# scJWuq0fl3F4wVRB15B9P16V0o5jMA0GCSqGSIb3DQEBAQUABIICAJ4isVgsxqXG
# I9IuaVciiuCq7JRQgUGYYEqVGL0UrxRLnjxPPTiY6NLGhRfls+avMkGMrFxEEYBU
# 81c9CTCxLVYZqQRvargKzvZVmN/81D8aiYwO/Z9/vBmHjYG0PcF7GszpKkqLbSZ2
# sHH81aZje/1liYIWy+FOPSatpXBHw8b4L3f74CoZRl/hLWSDSmkp0Ab4ExLG5NnB
# pCkM1eMsEnpzDORduSIAt+39oG3M5jJ0KhrhLA5+1BguoyC2O7l42Z4vML9l18Yd
# 6kSu8NoyHuferwi97KhuWY5noT+LFhqahy5zv8tlREp0QVowJ3CVBSAtUal/xsYB
# Hx8rSZzZqvq2kScayiqkMRmo8iLHGntWJtglKgMdOk0tO+flQQuYdg1QMRkxNSeb
# T4iCFVIzkj/BycusUoZKYaYxlfmCZWzR4ib2Kc4RBfIEzuGgkbKjIxslde8mLs6b
# vMZFq0IOiftxJ9GaPEe1aVu7lV+pr9Pdcn4M8vBiKQThq0h2gP29jEdiy6VL5dm1
# YwURa2GyaWFfJNfSLXVT2PDFSVK8AwQMTnXb9go7rre/iLqzxRt8eYku8o8kVgHd
# gy583DBx59urOpyYYOLHsQEUVJmOiEppUgPhsGH923ky4NuyuhkRsooYvy/33Tb4
# 9++L62gwprfKQDSEQM9Fc/h1fUPpIqr0oYIWujCCFrYGCisGAQQBgjcDAwExgham
# MIIWogYJKoZIhvcNAQcCoIIWkzCCFo8CAQMxDTALBglghkgBZQMEAgEwgd4GCyqG
# SIb3DQEJEAEEoIHOBIHLMIHIAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCD91tLav3dvHZq9ZpMZbL7p9Ajw6e1wsYqV3Nk5bxlZiQITdJdzZTR64yTj
# Ayp4FqOWLgaUVxgPMjAyNTA4MjUxNTM2MzFaMAMCAQGgWKRWMFQxCzAJBgNVBAYT
# AkJFMRkwFwYDVQQKDBBHbG9iYWxTaWduIG52LXNhMSowKAYDVQQDDCFHbG9iYWxz
# aWduIFRTQSBmb3IgQ29kZVNpZ24xIC0gUjagghJLMIIGYzCCBEugAwIBAgIQAQAL
# IAWzlAdi2z42eZSbqTANBgkqhkiG9w0BAQwFADBbMQswCQYDVQQGEwJCRTEZMBcG
# A1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1l
# c3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBHNDAeFw0yNTA0MTExNDQ3MzlaFw0zNDEy
# MTAwMDAwMDBaMFQxCzAJBgNVBAYTAkJFMRkwFwYDVQQKDBBHbG9iYWxTaWduIG52
# LXNhMSowKAYDVQQDDCFHbG9iYWxzaWduIFRTQSBmb3IgQ29kZVNpZ24xIC0gUjYw
# ggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCiW8SqTUnlI3g+4IXr5qoK
# PtXyrKinRGH3isuZjfsKfx6vzRKR8rN0kcmTdOpr1BjhTBXqF51d9JvmCTRfJ3Lc
# w0SPWoT5miY8RyMLu5G0Z18H8+2eJ5YnOO09VSWYQ+tQyygVTvCglJxFXVbr/p5+
# LYHJIdeyFnfRXUQNnaUpDQMrerdsjiwkT/mf91DLyIviGNNpL2/RhDLlElj6jU1a
# HE/8ew26brs6visUOwYgTzmGDmviDcJcW6Kpa+U2Y9sIFaB3Gn88KpjQuJ7TgO4p
# sPBF3qeubkAfmghEnIVSMu8bgc7QvVRdgy4nonUnM7jfxEDSYlG9TZnBsjrKIUdp
# LTHdKAVqS+EQsufi2bCeBg+P4UNfctpYeeeL8wYldHGc3SlB1gmoRiEpSWswf37Y
# qWd1zP/3JdgYTLBO3zx3fL5NQW9mUADQEw5gwytgVASm2VGDYNivHmxa1fWq8LOT
# qwQEtFU8RsTSL4nTUguUHNGlwm6xlRDIYrZFVI4V9c8CAwEAAaOCAagwggGkMA4G
# A1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQU
# gENM/LptHRPSdRKICXdv28ZPlVQwVgYDVR0gBE8wTTAIBgZngQwBBAIwQQYJKwYB
# BAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29t
# L3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQCMAAwgZAGCCsGAQUFBwEBBIGDMIGAMDkG
# CCsGAQUFBzABhi1odHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9nc3RzYWNh
# c2hhMzg0ZzQwQwYIKwYBBQUHMAKGN2h0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5j
# b20vY2FjZXJ0L2dzdHNhY2FzaGEzODRnNC5jcnQwHwYDVR0jBBgwFoAU6hbGaefj
# y1dFOTOk8EC+0MO9ZZYwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jYS9nc3RzYWNhc2hhMzg0ZzQuY3JsMA0GCSqGSIb3DQEBDAUA
# A4ICAQC3psdKmXZ0/SBiJ72JfDcHPlfPCy+aJiKwSNujJFmKf6OofbogWrt9Awis
# 3lV1fwoaXmkR7bVvyyQ99Ry2KuijpBLmhYRKXiTNmjDaIn+omfvpOS8v6/Z/iYei
# UYsHDIObvh9evrxbrfG6JhKmdt/s1g/IFocjvMn8StJPhsDTRML5+0+21L4b8yE1
# RoqDfjJonxnoAQ2c90IHxUiu3+yp3pHWTz06PHWMvfpAEQ9SvZ20giVLcqLvgJTX
# lhO8b5fG31zAT7QbH+pFC/xhsX5Ryx2BhTiM1FkHSRNXcGx3eXIhaa3wNPhFCP0t
# DUgs6mob8LPB32r0YkvqNIl5KrUALhmhxUy6pxh38P0mkgwv0FD/CTmWAmSBcRzW
# BGA+wOxT3PPfonKY3X5iG/HRWvruOvRB+qTdXTPr/FWYQAkpp9N4h8P2FByGOIaT
# LDcQo2LIfIzfut0r8GxNLHSsHcwd2oT390dBfk1Q5AJZS+GRbLXS7vXLMYpadsBZ
# Do026r1+1zBgVOZzKjlhsXDN+TJL5jvz47262qCLpWgTY3NUlu5yoYtm0kUnMYkP
# vF7+upQvBgd5Dcc9Kc0JqBvqOoF4VKddPHQZu5i6TeMDnV1A22yiBUAZcKoeyHrZ
# BUCX+Bp1N9xFoykhYBzcI+6nfHX10MCmymZHI5XNcFS2yIJawjCCBlkwggRBoAMC
# AQICDQHsHJJA3v0uQF18R3QwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xv
# YmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNV
# BAMTCkdsb2JhbFNpZ24wHhcNMTgwNjIwMDAwMDAwWhcNMzQxMjEwMDAwMDAwWjBb
# MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UE
# AxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAPAC4jAj+uAb4Zp0s691g1+pR1LH
# YTpjfDkjeW10/DHkdBIZlvrOJ2JbrgeKJ+5Xo8Q17bM0x6zDDOuAZm3RKErBLLu5
# cPJyroz3mVpddq6/RKh8QSSOj7rFT/82QaunLf14TkOI/pMZF9nuMc+8ijtuasSI
# 8O6X9tzzGKBLmRwOh6cm4YjJoOWZ4p70nEw/XVvstu/SZc9FC1Q9sVRTB4uZbrhU
# mYqoMZI78np9/A5Y34Fq4bBsHmWCKtQhx5T+QpY78Quxf39GmA6HPXpl69FWqS69
# +1g9tYX6U5lNW3TtckuiDYI3GQzQq+pawe8P1Zm5P/RPNfGcD9M3E1LZJTTtlu/4
# Z+oIvo9Jev+QsdT3KRXX+Q1d1odDHnTEcCi0gHu9Kpu7hOEOrG8NubX2bVb+ih0J
# PiQOZybH/LINoJSwspTMe+Zn/qZYstTYQRLBVf1ukcW7sUwIS57UQgZvGxjVNupk
# rs799QXm4mbQDgUhrLERBiMZ5PsFNETqCK6dSWcRi4LlrVqGp2b9MwMB3pkl+XFu
# 6ZxdAkxgPM8CjwH9cu6S8acS3kISTeypJuV3AqwOVwwJ0WGeJoj8yLJN22TwRZ+6
# wT9Uo9h2ApVsao3KIlz2DATjKfpLsBzTN3SE2R1mqzRzjx59fF6W1j0ZsJfqjFCR
# ba9Xhn4QNx1rGhTfAgMBAAGjggEpMIIBJTAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0T
# AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU6hbGaefjy1dFOTOk8EC+0MO9ZZYwHwYD
# VR0jBBgwFoAUrmwFo5MT4qLn4tcc1sfwf8hnU6AwPgYIKwYBBQUHAQEEMjAwMC4G
# CCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDYG
# A1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC1y
# Ni5jcmwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8v
# d3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBDAUAA4IC
# AQB/4ojZV2crQl+BpwkLusS7KBhW1ky/2xsHcMb7CwmtADpgMx85xhZrGUBJJQge
# 5Jv31qQNjx6W8oaiF95Bv0/hvKvN7sAjjMaF/ksVJPkYROwfwqSs0LLP7MJWZR29
# f/begsi3n2HTtUZImJcCZ3oWlUrbYsbQswLMNEhFVd3s6UqfXhTtchBxdnDSD5bz
# 6jdXlJEYr9yNmTgZWMKpoX6ibhUm6rT5fyrn50hkaS/SmqFy9vckS3RafXKGNbMC
# Vx+LnPy7rEze+t5TTIP9ErG2SVVPdZ2sb0rILmq5yojDEjBOsghzn16h1pnO6X1L
# lizMFmsYzeRZN4YJLOJF1rLNboJ1pdqNHrdbL4guPX3x8pEwBZzOe3ygxayvUQbw
# EccdMMVRVmDofJU9IuPVCiRTJ5eA+kiJJyx54jzlmx7jqoSCiT7ASvUh/mIQ7R0w
# /PbM6kgnfIt1Qn9ry/Ola5UfBFg0ContglDk0Xuoyea+SKorVdmNtyUgDhtRoNRj
# qoPqbHJhSsn6Q8TGV8Wdtjywi7C5HDHvve8U2BRAbCAdwi3oC8aNbYy2ce1SIf4+
# 9p+fORqurNIveiCx9KyqHeItFJ36lmodxjzK89kcv1NNpEdZfJXEQ0H5JeIsEH6B
# +Q2Up33ytQn12GByQFCVINRDRL76oJXnIFm2eMakaqoimzCCBYMwggNroAMCAQIC
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
# 1wpngwVayaQQMYIDSTCCA0UCAQEwbzBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBp
# bmcgQ0EgLSBTSEEzODQgLSBHNAIQAQALIAWzlAdi2z42eZSbqTALBglghkgBZQME
# AgGgggEtMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDArBgkqhkiG9w0BCTQx
# HjAcMAsGCWCGSAFlAwQCAaENBgkqhkiG9w0BAQsFADAvBgkqhkiG9w0BCQQxIgQg
# CW9a6snybxBh82kuXWkfh2XhoeIwXaASp/cpNnmBh/owgbAGCyqGSIb3DQEJEAIv
# MYGgMIGdMIGaMIGXBCByXvJ/SOFuablj2EJojFvKB6iMaRcGQsj/Wit3r2Bc/TBz
# MF+kXTBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEx
# MC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBH
# NAIQAQALIAWzlAdi2z42eZSbqTANBgkqhkiG9w0BAQsFAASCAYBtBiPEUYr2Sjn0
# O0N30xNXwVyAlz4k4NLg4bev/77aH33yl+/Q7qFf8J4+JwNEWhhhaK0F0WzRaOhc
# J3d9XWZSJFIc40HmZAdrUhcsvWDlBovQNhmT8zQQgkfAFfMVsbDEFTYtc0fjh161
# gTYBYBzq3h5G8KRLJ8n2zG4elngIS/BKeWaxU9YUqeQLYPoVn3lrWuvepkVBMcLG
# tOOEi8b0eIo0PQ7Rzpk8dt6BMLVASsPPfb/8M6YS+N1NRVPrLr/5wTlZJdOg16Ap
# toepmow/8QXnepCCQSRyKUCtVCjojBwV3a33BmbfgimvN8yBoz9yt6Sp4A0rUc3X
# RUY23ZOepsnw54vbl4ovpetD4rdcDCUFH9OoBEVsOOBQfYdlH+iD/QAhiCZdipS/
# sPXT/kotiq0+wi6CnHDTliyiekt5+R9dL7bVljbLnSEwvvngZwi8FzL61bjg1NRe
# rfIpxc+8lCL2ZS+9QiQCp3JyKGOcVFXH4/u8y4cFXAxZgXkcjew=
# SIG # End signature block
