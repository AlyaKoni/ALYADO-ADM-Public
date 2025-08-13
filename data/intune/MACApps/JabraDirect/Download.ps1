#Requires -Version 2

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


#>

. "$PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1"

$pageUrl = "https://www.jabra.com/software-and-services/jabra-direct"
$volName = "Jabra Direct Setup"

$req = Invoke-WebRequestIndep -Uri $pageUrl -UseBasicParsing -Method Get -UserAgent "Wget"
[regex]$regex = "[^`"]*blob.core.windows.net[^`"]*JabraDirectSetup.dmg[^`"]*"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value

$fileName = Split-Path -Path $newUrl -Leaf
$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "Content"
if (-Not (Test-Path $contentRoot))
{
    $null = New-Item -Path $contentRoot -ItemType Directory -Force
}
Invoke-WebRequestIndep -UseBasicParsing -Method Get -UserAgent "Wget" -Uri $newUrl -Outfile "$contentRoot/$fileName"

hdiutil attach -nobrowse -readonly "$contentRoot/$fileName"
$volume = "/Volumes/$volName"
$pkgName = $fileName.Replace(".dmg",".pkg")
$pkgFile = "$volume/$pkgName"
cp $pkgFile "$contentRoot/$pkgName"
hdiutil detach $volume
$pkgFile = "$contentRoot/$pkgName"

$dirname = "$contentRoot/temp"
New-Item -Path $dirname -ItemType Directory -Force
pushd $dirName
xar -xf $pkgFile
popd

$distFile = "$contentRoot/temp/Distribution"
$distContent = Get-Content -Path $distFile
[regex]$regex = "<pkg-ref id=.com.jabra.directonline. version=.(\d+)\.(\d+)\.(\d+)"
$grps = [regex]::Match($distContent, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Groups
$bundleVersion = $grps[1].Value+"."+$grps[2].Value+"."+$grps[3].Value

$versionFile = Join-Path $packageRoot "version.json"
$versionObj = @{}
$versionObj.version = ([Version]$bundleVersion).ToString()
$versionObj | ConvertTo-Json | Set-Content -Path $versionFile -Encoding UTF8 -Force

Remove-Item -Path $dirname -Recurse -Force
Remove-Item -Path "$contentRoot/$fileName" -Force


<#
hdiutil attach -nobrowse -readonly "$contentRoot/$fileName"
$volume = "/Volumes/$volName"
file "$volume/$appName.app/Contents/Info.plist"
cp "$volume/$appName.app/Contents/Info.plist" /tmp/tmpPlistFile.plist
plutil -convert xml1 /tmp/tmpPlistFile.plist
$plistCont = Get-Content -Path /tmp/tmpPlistFile.plist -Encoding utf8 -Raw
hdiutil detach $volume
rm /tmp/tmpPlistFile.plist
#>

# SIG # Begin signature block
# MIIpTwYJKoZIhvcNAQcCoIIpQDCCKTwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC09LWTv92FH94n
# v146ZSvX4EXQUGI0GG0p/76JdZ0noaCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g604YfM/tV
# 5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD4ED6gVYD
# U/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S/gJXhZrh
# 0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp8nKmrVa4
# 6Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqtf2phU7+y
# R2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJQWTEE/bP
# 0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKXvYkPbEdx
# +QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4yMYgcMKb
# 9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmYF8T4xO2k
# 6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2mMIVpqWC
# Z1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7spNY6rQb
# 3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd2jANBgkq
# hkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy/fAHsVv1
# RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW2H3Bh6zN
# XULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0MP6pBPKO
# L6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/pFL9zlcc
# tWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcexU0bcV0hL
# Q4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf6AMOGaM5
# 6A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzECp9LnR+34
# c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9mUF5qE6Yw
# QqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+KuaJRsz+cn
# ZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/JlN6m6GM1j
# EhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutofdgNBzMUx
# ghnAMIIZvAIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoGowGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEILOZnSLo2POO43iWuRcddSQpVDgCuvfgmKX48ZxG
# BBkIMA0GCSqGSIb3DQEBAQUABIICALv/s2g0pK02M+QFd4gKXnJl9CxQeeuarEYE
# CIXkpzc+ZLz/Dp9RoeRGs0pGt8bZBsfAdFUy7q6oSpFrpNKqG2kfzxfSmo7uC8Ae
# lP1BbgbxvAPzwRCThgQol0N1dWjbVtdZTapsbldJJ2UkNEQ8H/Oqo8GPGhmd8YqH
# 5ARnsF9UJlKVd4f74pX8T3jDK0CXHTGaA6DnidC+i95xAACgs5sMPsp7Iwm5gB8q
# SThfzOcbalOxkvdFm4S4oeDFw31u9PJrjWr8n0rRxiAPzVWSeaqMlZ6B4BCxH3oY
# zvWLGg4FZMPAUTPXw00inOsaplPDQsqQbn+zxn5iyZ8sutRzKRSzbgQaQWXl7apK
# OZQ4jGxk7NASXULW4wtt9kWEl+NB+GXukT6rQornkCmcmidqivAhnyIJCCzKPbz+
# OAQX276LcVOUcc4ieDakvwek9q/xA/Fqcn182qMBTYYrWufgSK9hVQq2E8xanKgA
# UTUr0whI88H3cxYFKoSMquI3odEC2xJ36PiMpIj95iDaPgdBs4nfbvUsyF1/Wkm2
# JB4lEHz/I9czS1EteEc+rJGea8wNIFzzIaES0XA8qQ+obmXBXD07iKPPcJiF3Gg5
# z+5Y03SoV6nkVeithyePCbjkuXMuAz5s6fOxEyMpMpppgiQksoQueLVzakxRnZZr
# QiyUpui7oYIWuTCCFrUGCisGAQQBgjcDAwExghalMIIWoQYJKoZIhvcNAQcCoIIW
# kjCCFo4CAQMxDTALBglghkgBZQMEAgEwgd0GCyqGSIb3DQEJEAEEoIHNBIHKMIHH
# AgEBBgsrBgEEAaAyAgMBAjAvMAsGCWCGSAFlAwQCAQQg1GNPV0wCPk7CBjGemXVr
# nU8HLHrpif3FIEpe6squpvICFCAPJ4jsgFWqMniRTMjEy7JG+OhXGA8yMDI1MDcy
# OTEzMTMwOFowAwIBAaBYpFYwVDELMAkGA1UEBhMCQkUxGTAXBgNVBAoMEEdsb2Jh
# bFNpZ24gbnYtc2ExKjAoBgNVBAMMIUdsb2JhbHNpZ24gVFNBIGZvciBDb2RlU2ln
# bjEgLSBSNqCCEkswggZjMIIES6ADAgECAhABAAsgBbOUB2LbPjZ5lJupMA0GCSqG
# SIb3DQEBDAUAMFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52
# LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4
# NCAtIEc0MB4XDTI1MDQxMTE0NDczOVoXDTM0MTIxMDAwMDAwMFowVDELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoMEEdsb2JhbFNpZ24gbnYtc2ExKjAoBgNVBAMMIUdsb2Jh
# bHNpZ24gVFNBIGZvciBDb2RlU2lnbjEgLSBSNjCCAaIwDQYJKoZIhvcNAQEBBQAD
# ggGPADCCAYoCggGBAKJbxKpNSeUjeD7ghevmqgo+1fKsqKdEYfeKy5mN+wp/Hq/N
# EpHys3SRyZN06mvUGOFMFeoXnV30m+YJNF8nctzDRI9ahPmaJjxHIwu7kbRnXwfz
# 7Z4nlic47T1VJZhD61DLKBVO8KCUnEVdVuv+nn4tgckh17IWd9FdRA2dpSkNAyt6
# t2yOLCRP+Z/3UMvIi+IY02kvb9GEMuUSWPqNTVocT/x7Dbpuuzq+KxQ7BiBPOYYO
# a+INwlxboqlr5TZj2wgVoHcafzwqmNC4ntOA7imw8EXep65uQB+aCESchVIy7xuB
# ztC9VF2DLieidSczuN/EQNJiUb1NmcGyOsohR2ktMd0oBWpL4RCy5+LZsJ4GD4/h
# Q19y2lh554vzBiV0cZzdKUHWCahGISlJazB/ftipZ3XM//cl2BhMsE7fPHd8vk1B
# b2ZQANATDmDDK2BUBKbZUYNg2K8ebFrV9arws5OrBAS0VTxGxNIvidNSC5Qc0aXC
# brGVEMhitkVUjhX1zwIDAQABo4IBqDCCAaQwDgYDVR0PAQH/BAQDAgeAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMB0GA1UdDgQWBBSAQ0z8um0dE9J1EogJd2/bxk+V
# VDBWBgNVHSAETzBNMAgGBmeBDAEEAjBBBgkrBgEEAaAyAR4wNDAyBggrBgEFBQcC
# ARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDAYDVR0T
# AQH/BAIwADCBkAYIKwYBBQUHAQEEgYMwgYAwOQYIKwYBBQUHMAGGLWh0dHA6Ly9v
# Y3NwLmdsb2JhbHNpZ24uY29tL2NhL2dzdHNhY2FzaGEzODRnNDBDBggrBgEFBQcw
# AoY3aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3N0c2FjYXNo
# YTM4NGc0LmNydDAfBgNVHSMEGDAWgBTqFsZp5+PLV0U5M6TwQL7Qw71lljBBBgNV
# HR8EOjA4MDagNKAyhjBodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2NhL2dzdHNh
# Y2FzaGEzODRnNC5jcmwwDQYJKoZIhvcNAQEMBQADggIBALemx0qZdnT9IGInvYl8
# Nwc+V88LL5omIrBI26MkWYp/o6h9uiBau30DCKzeVXV/ChpeaRHttW/LJD31HLYq
# 6KOkEuaFhEpeJM2aMNoif6iZ++k5Ly/r9n+Jh6JRiwcMg5u+H16+vFut8bomEqZ2
# 3+zWD8gWhyO8yfxK0k+GwNNEwvn7T7bUvhvzITVGioN+MmifGegBDZz3QgfFSK7f
# 7KnekdZPPTo8dYy9+kARD1K9nbSCJUtyou+AlNeWE7xvl8bfXMBPtBsf6kUL/GGx
# flHLHYGFOIzUWQdJE1dwbHd5ciFprfA0+EUI/S0NSCzqahvws8HfavRiS+o0iXkq
# tQAuGaHFTLqnGHfw/SaSDC/QUP8JOZYCZIFxHNYEYD7A7FPc89+icpjdfmIb8dFa
# +u469EH6pN1dM+v8VZhACSmn03iHw/YUHIY4hpMsNxCjYsh8jN+63SvwbE0sdKwd
# zB3ahPf3R0F+TVDkAllL4ZFstdLu9csxilp2wFkOjTbqvX7XMGBU5nMqOWGxcM35
# MkvmO/PjvbraoIulaBNjc1SW7nKhi2bSRScxiQ+8Xv66lC8GB3kNxz0pzQmoG+o6
# gXhUp108dBm7mLpN4wOdXUDbbKIFQBlwqh7IetkFQJf4GnU33EWjKSFgHNwj7qd8
# dfXQwKbKZkcjlc1wVLbIglrCMIIGWTCCBEGgAwIBAgINAewckkDe/S5AXXxHdDAN
# BgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBS
# NjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0x
# ODA2MjAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFsxCzAJBgNVBAYTAkJFMRkwFwYD
# VQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWduIFRpbWVz
# dGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA8ALiMCP64BvhmnSzr3WDX6lHUsdhOmN8OSN5bXT8MeR0EhmW+s4n
# YluuB4on7lejxDXtszTHrMMM64BmbdEoSsEsu7lw8nKujPeZWl12rr9EqHxBJI6P
# usVP/zZBq6ct/XhOQ4j+kxkX2e4xz7yKO25qxIjw7pf23PMYoEuZHA6HpybhiMmg
# 5ZninvScTD9dW+y279Jlz0ULVD2xVFMHi5luuFSZiqgxkjvyen38DljfgWrhsGwe
# ZYIq1CHHlP5CljvxC7F/f0aYDoc9emXr0VapLr37WD21hfpTmU1bdO1yS6INgjcZ
# DNCr6lrB7w/Vmbk/9E818ZwP0zcTUtklNO2W7/hn6gi+j0l6/5Cx1PcpFdf5DV3W
# h0MedMRwKLSAe70qm7uE4Q6sbw25tfZtVv6KHQk+JA5nJsf8sg2glLCylMx75mf+
# pliy1NhBEsFV/W6RxbuxTAhLntRCBm8bGNU26mSuzv31BebiZtAOBSGssREGIxnk
# +wU0ROoIrp1JZxGLguWtWoanZv0zAwHemSX5cW7pnF0CTGA8zwKPAf1y7pLxpxLe
# QhJN7Kkm5XcCrA5XDAnRYZ4miPzIsk3bZPBFn7rBP1Sj2HYClWxqjcoiXPYMBOMp
# +kuwHNM3dITZHWarNHOPHn18XpbWPRmwl+qMUJFtr1eGfhA3HWsaFN8CAwEAAaOC
# ASkwggElMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud
# DgQWBBTqFsZp5+PLV0U5M6TwQL7Qw71lljAfBgNVHSMEGDAWgBSubAWjkxPioufi
# 1xzWx/B/yGdToDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6Ly9v
# Y3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjYwNgYDVR0fBC8wLTAroCmgJ4YlaHR0
# cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXI2LmNybDBHBgNVHSAEQDA+MDwG
# BFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20v
# cmVwb3NpdG9yeS8wDQYJKoZIhvcNAQEMBQADggIBAH/iiNlXZytCX4GnCQu6xLso
# GFbWTL/bGwdwxvsLCa0AOmAzHznGFmsZQEklCB7km/fWpA2PHpbyhqIX3kG/T+G8
# q83uwCOMxoX+SxUk+RhE7B/CpKzQss/swlZlHb1/9t6CyLefYdO1RkiYlwJnehaV
# SttixtCzAsw0SEVV3ezpSp9eFO1yEHF2cNIPlvPqN1eUkRiv3I2ZOBlYwqmhfqJu
# FSbqtPl/KufnSGRpL9KaoXL29yRLdFp9coY1swJXH4uc/LusTN763lNMg/0SsbZJ
# VU91naxvSsguarnKiMMSME6yCHOfXqHWmc7pfUuWLMwWaxjN5Fk3hgks4kXWss1u
# gnWl2o0et1sviC49ffHykTAFnM57fKDFrK9RBvARxx0wxVFWYOh8lT0i49UKJFMn
# l4D6SIknLHniPOWbHuOqhIKJPsBK9SH+YhDtHTD89szqSCd8i3VCf2vL86VrlR8E
# WDQKie2CUOTRe6jJ5r5IqitV2Y23JSAOG1Gg1GOqg+pscmFKyfpDxMZXxZ22PLCL
# sLkcMe+97xTYFEBsIB3CLegLxo1tjLZx7VIh/j72n585Gq6s0i96ILH0rKod4i0U
# nfqWah3GPMrz2Ry/U02kR1l8lcRDQfkl4iwQfoH5DZSnffK1CfXYYHJAUJUg1ENE
# vvqglecgWbZ4xqRqqiKbMIIFgzCCA2ugAwIBAgIORea7A4Mzw4VlSOb/RVEwDQYJ
# KoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYx
# EzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTQx
# MjEwMDAwMDAwWhcNMzQxMjEwMDAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWdu
# IFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xv
# YmFsU2lnbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJUH6HPKZvns
# FMp7PPcNCPG0RQssgrRIxutbPK6DuEGSMxSkb3/pKszGsIhrxbaJ0cay/xTOURQh
# 7ErdG1rG1ofuTToVBu1kZguSgMpE3nOUTvOniX9PeGMIyBJQbUJmL025eShNUhqK
# GoC3GYEOfsSKvGRMIRxDaNc9PIrFsmbVkJq3MQbFvuJtMgamHvm566qjuL++gmNQ
# 0PAYid/kD3n16qIfKtJwLnvnvJO7bVPiSHyMEAc4/2ayd2F+4OqMPKq0pPbzlUoS
# B239jLKJz9CgYXfIWHSw1CM69106yqLbnQneXUQtkPGBzVeS+n68UARjNN9rkxi+
# azayOeSsJDa38O+2HBNXk7besvjihbdzorg1qkXy4J02oW9UivFyVm4uiMVRQkQV
# lO6jxTiWm05OWgtH8wY2SXcwvHE35absIQh1/OZhFj931dmRl4QKbNQCTXTAFO39
# OfuD8l4UoQSwC+n+7o/hbguyCLNhZglqsQY6ZZZZwPA1/cnaKI0aEYdwgQqomnUd
# njqGBQCe24DWJfncBZ4nWUx2OVvq+aWh2IMP0f/fMBH5hc8zSPXKbWQULHpYT9NL
# CEnFlWQaYw55PfWzjMpYrZxCRXluDocZXFSxZba/jJvcE+kNb7gu3GduyYsRtYQU
# igAZcIN5kZeR1BonvzceMgfYFGM8KEyvAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIB
# BjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSubAWjkxPioufi1xzWx/B/yGdT
# oDAfBgNVHSMEGDAWgBSubAWjkxPioufi1xzWx/B/yGdToDANBgkqhkiG9w0BAQwF
# AAOCAgEAgyXt6NH9lVLNnsAEoJFp5lzQhN7craJP6Ed41mWYqVuoPId8AorRbrcW
# c+ZfwFSY1XS+wc3iEZGtIxg93eFyRJa0lV7Ae46ZeBZDE1ZXs6KzO7V33EByrKPr
# mzU+sQghoefEQzd5Mr6155wsTLxDKZmOMNOsIeDjHfrYBzN2VAAiKrlNIC5waNrl
# U/yDXNOd8v9EDERm8tLjvUYAGm0CuiVdjaExUd1URhxN25mW7xocBFymFe944Hn+
# Xds+qkxV/ZoVqW/hpvvfcDDpw+5CRu3CkwWJ+n1jez/QcYF8AOiYrg54NMMl+68K
# nyBr3TsTjxKM4kEaSHpzoHdpx7Zcf4LIHv5YGygrqGytXm3ABdJ7t+uA/iU3/gKb
# aKxCXcPu9czc8FB10jZpnOZ7BN9uBmm23goJSFmH63sUYHpkqmlD75HHTOwY3Wzv
# Uy2MmeFe8nI+z1TIvWfspA9MRf/TuTAjB0yPEL+GltmZWrSZVxykzLsViVO6LAUP
# 5MSeGbEYNNVMnbrt9x+vJJUEeKgDu+6B5dpffItKoZB0JaezPkvILFa9x8jvOOJc
# kvB595yEunQtYQEgfn7R8k8HWV+LLUNS60YMlOH1Zkd5d9VUWx+tJDfLRVpOoERI
# yNiwmcUVhAn21klJwGW45hpxbqCo8YLoRT5s1gLXCmeDBVrJpBAxggNJMIIDRQIB
# ATBvMFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEw
# LwYDVQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0
# AhABAAsgBbOUB2LbPjZ5lJupMAsGCWCGSAFlAwQCAaCCAS0wGgYJKoZIhvcNAQkD
# MQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3DQEJNDEeMBwwCwYJYIZIAWUDBAIBoQ0G
# CSqGSIb3DQEBCwUAMC8GCSqGSIb3DQEJBDEiBCB7Orl7OdWYeE588rhxJwPyMS27
# iYvK5YsIKDQ/gyXJljCBsAYLKoZIhvcNAQkQAi8xgaAwgZ0wgZowgZcEIHJe8n9I
# 4W5puWPYQmiMW8oHqIxpFwZCyP9aK3evYFz9MHMwX6RdMFsxCzAJBgNVBAYTAkJF
# MRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWdu
# IFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0AhABAAsgBbOUB2LbPjZ5lJup
# MA0GCSqGSIb3DQEBCwUABIIBgFiL5sxxYfxkHeIhrsYyi9yHpCQrFj2CykGuZHAL
# qRzTf+e6nulwudaLMbDF5GGmNKOrjA60QkQx1uwYB0G+0cQbhM27wG8GJXrjTRVT
# UK66RCzMngXqllqnLIsIj73dJQday0vy3eJZRcntSpdrG+I3dEcVW3Od7ZTJpqT6
# 3yuOQStT4e6t3OKOwPDfsJ2lWXDBVH+JyJUfTzFWyvdGlFshxjhcEvgPrC9ddhs/
# RXgtK2gVpw1xFOYVWR4I/dZUhvV9e/gTzaQKoTuo77FJENM77/bGt3B/457w7+Xw
# 0oLhkjzIXOLScx+FbQxJsJhIqoV2HQXHBzeFcBResDX1Mdwr33t6kRKAbwya3Q7V
# WRy8WS/D6o4UXPrG2uIlhmHTH77UfUjTm1/VWVxX/b6qrorvZJNyVosrrEdbeVF6
# rgemv7jWSIN8uZA0Av6f4cJhzWjG7q9XtTsjZdssKK8N9Jfgcca0/SDmJhqwAPzE
# 0b2cJ6zKLTnTA5pLmVP1zufyTg==
# SIG # End signature block
