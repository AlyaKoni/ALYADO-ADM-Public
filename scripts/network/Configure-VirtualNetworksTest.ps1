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
    10.03.2020 Konrad Brunner       Initial Version
	16.08.2021 Konrad Brunner		Added provider registration

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\network\Configure-VirtualNetworksTest-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupNameProd = "$($AlyaNamingPrefix)resg$($AlyaResIdMainNetwork)"
$VirtualNetworkNameProd = "$($AlyaNamingPrefix)vnet$($AlyaResIdVirtualNetwork)"
$ResourceGroupNameTest = "$($AlyaNamingPrefixTest)resg$($AlyaResIdMainNetwork)"
$VirtualNetworkNameTest = "$($AlyaNamingPrefixTest)vnet$($AlyaResIdVirtualNetwork)"
$DefaultSubnetName = "$($VirtualNetworkNameTest)snet{0}"
$DefaultSubnetSecGrpName = "$($VirtualNetworkNameTest)snet{0}sgrp"
$VirtualNetworkProdPeeringName = "$($VirtualNetworkNameProd)peer$($VirtualNetworkNameTest)"
$VirtualNetworkTestPeeringName = "$($VirtualNetworkNameTest)peer$($VirtualNetworkNameProd)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Network"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Network | Configure-VirtualNetworksTest | Azure" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking resource provider registration
Write-Host "Checking resource provider registration Microsoft.Network" -ForegroundColor $CommandInfo
$resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Network" -Location $AlyaLocation
if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
{
    Write-Warning "Resource provider Microsoft.Network not registered. Registering now resource provider Microsoft.Network"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Network" | Out-Null
    do
    {
        Start-Sleep -Seconds 5
        $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Network" -Location $AlyaLocation
    } while ($resProv[0].RegistrationState -ne "Registered")
}

# Checking ressource group prod
Write-Host "Checking ressource group prod" -ForegroundColor $CommandInfo
$ResGrpProd = Get-AzResourceGroup -Name $ResourceGroupNameProd -ErrorAction SilentlyContinue
if (-Not $ResGrpProd)
{
    throw "Ressource Group not found. Please create the Ressource Group $ResourceGroupNameProd"
}

# Checking ressource group test
Write-Host "Checking ressource group test" -ForegroundColor $CommandInfo
$ResGrpTest = Get-AzResourceGroup -Name $ResourceGroupNameTest -ErrorAction SilentlyContinue
if (-Not $ResGrpTest)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ResourceGroupNameTest"
    $ResGrpTest = New-AzResourceGroup -Name $ResourceGroupNameTest -Location $AlyaLocation -Tag @{displayName="Main Test Network Services";ownerEmail=$Context.Account.Id}
}

# Checking virtual network prod
Write-Host "Checking virtual network prod" -ForegroundColor $CommandInfo
$VNetProd = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupNameProd -Name $VirtualNetworkNameProd -ErrorAction SilentlyContinue
if (-Not $VNetProd)
{
    throw "Virtual network not found. Please create the virtual network $VirtualNetworkNameProd"
}

# Checking virtual network test
Write-Host "Checking virtual network test" -ForegroundColor $CommandInfo
$VNetTest = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupNameTest -Name $VirtualNetworkNameTest -ErrorAction SilentlyContinue
if (-Not $VNetTest)
{
    Write-Warning "Virtual network not found. Creating the virtual network $VirtualNetworkNameTest"
    $VNetTest = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupNameTest -Name $VirtualNetworkNameTest -Location $AlyaLocation -AddressPrefix $AlyaTestNetwork
}

# Calculating subnets
Write-Host "Calculating subnets" -ForegroundColor $CommandInfo
$Networks = Split-NetworkAddressWithoutGateway -netwandcidr $AlyaTestNetwork -splitcidr $AlyaSubnetPrefixLength

# Checking network subnets and security groups
Write-Host "Checking network subnets and security groups" -ForegroundColor $CommandInfo
$VNet = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupNameTest -Name $VirtualNetworkNameTest -ErrorAction SilentlyContinue
$Subnets = $VNet.Subnets
$dirty = $false
for ($i = 1; $i -lt ($Networks.Count+1); $i++)
{
    $SubnetName = "$DefaultSubnetName" -f "$i".PadLeft(2, "0")
    $SubnetSecGrpName = "$DefaultSubnetSecGrpName" -f "$i".PadLeft(2, "0")
    $Subnet = $Networks[$i-1]
    $exist = $Subnets | Where-Object { $_.Name -eq $SubnetName }
    if (-Not $exist)
    {
        $SubnetSecGrp = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupNameTest -Name $SubnetSecGrpName -ErrorAction SilentlyContinue
        if (-Not $SubnetSecGrp)
        {
            Write-Warning "Network security group not found. Creating the network security group $SubnetSecGrpName"
            $SubnetSecGrp = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupNameTest -Name $SubnetSecGrpName -Location $AlyaLocation
        }
        Write-Warning "Subnet not found. Creating the subnet $SubnetName"
        Add-AzVirtualNetworkSubnetConfig -VirtualNetwork $VNet -Name $SubnetName -AddressPrefix $Subnet -NetworkSecurityGroup $SubnetSecGrp
        $dirty = $true
    }
}
if ($dirty)
{
    $VNet | Set-AzVirtualNetwork
}

# Checking peering test
Write-Host "Checking peering test" -ForegroundColor $CommandInfo
$PeerTest = Get-AzVirtualNetworkPeering -ResourceGroupName $ResourceGroupNameTest -VirtualNetworkName $VirtualNetworkNameTest -Name $VirtualNetworkTestPeeringName -ErrorAction SilentlyContinue
if (-Not $PeerTest)
{
    Write-Warning "Virtual network peering not found. Creating the virtual network peering $VirtualNetworkTestPeeringName"
    if ($AlyaDeployVPNGateway)
    {
        $PeerTest = Add-AzVirtualNetworkPeering -VirtualNetwork $VNetTest -Name $VirtualNetworkTestPeeringName -RemoteVirtualNetworkId $VNetProd.Id -UseRemoteGateways
    }
    else
    {
        $PeerTest = Add-AzVirtualNetworkPeering -VirtualNetwork $VNetTest -Name $VirtualNetworkTestPeeringName -RemoteVirtualNetworkId $VNetProd.Id
    }
}

# Checking peering prod
Write-Host "Checking peering prod" -ForegroundColor $CommandInfo
$PeerProd = Get-AzVirtualNetworkPeering -ResourceGroupName $ResourceGroupNameProd -VirtualNetworkName $VirtualNetworkNameProd -Name $VirtualNetworkProdPeeringName -ErrorAction SilentlyContinue
if (-Not $PeerProd)
{
    Write-Warning "Virtual network peering not found. Creating the virtual network peering $VirtualNetworkProdPeeringName"
    if ($AlyaDeployVPNGateway)
    {
        $PeerProd = Add-AzVirtualNetworkPeering -VirtualNetwork $VNetProd -Name $VirtualNetworkProdPeeringName -RemoteVirtualNetworkId $VNetTest.Id -AllowGatewayTransit
    }
    else
    {
        $PeerProd = Add-AzVirtualNetworkPeering -VirtualNetwork $VNetProd -Name $VirtualNetworkProdPeeringName -RemoteVirtualNetworkId $VNetTest.Id
    }
}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIvCAYJKoZIhvcNAQcCoIIu+TCCLvUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCLqTXScGMWpoQU
# QP5jPCIiXm3Qf32MQ1MtHZUTKxEJwqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxghnTMIIZzwIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHs9JCNo
# hPncqNpZCp8VgHSRPiVZG/y90pog0ibla003MA0GCSqGSIb3DQEBAQUABIICAAp3
# /b/djT6jcsycAjqJ7OPQG5jxq34b8IeMrZK1J2Muj4Au0s7TeIR7M4DN5buV0tmt
# J/IhnEEtyTiTQr9qo0Xfj5z0id4CWgW+bgBdJ2rCzt4lJ/uEi/f6b81zA3ykrbKG
# y9S5CNufea/v9RESDmWd6yZtdvm5mjL5uPKpgwKQOMc0AhaqYPCX9myeUOSytz1n
# E3y6qElMOPGzeug85UjhVhWeW4bAPB5mOKafr+UugXRavQuJo8oaC4eYzGj3mVJy
# iqLk7ScRJ65Jbn4xyJxq+U2lFlxtpOw5SzDqvtA0Sz5GhoHpLdhKWgoZJp8RP7D4
# tm4Td4tqArKHTCf24FERZzsl1y5qpHmErzlMbuYetEQSO8CbqkudSJMfUjqt7twd
# 5DjwkSm4PeFdg3U0eWKKSCHTDmr7W9TLiO8wj14uYDJJV06aCmLymEkCDVKJczul
# P71y9YMYs61uZCiJGgTuzDyu1UdtTtKHDAoA8BhEBdYgLwKqLurClURLx1Qauhmy
# fjJehBK5uWPJVnGtVB6u6YCm8PQiwJqSmEaRe8Xfj8BJR+/zytaKrxdqXaEzAGcF
# b4e6W2WFqT93dzxx5ZrInqEfWwj7QboaREQhJb3AxTRd1blXAsnZ3+18KfhTEQV3
# R//dDfFULf0Ptz4+TAIzCisCTiNit0wPTmqow59NoYIWujCCFrYGCisGAQQBgjcD
# AwExghamMIIWogYJKoZIhvcNAQcCoIIWkzCCFo8CAQMxDTALBglghkgBZQMEAgEw
# gd4GCyqGSIb3DQEJEAEEoIHOBIHLMIHIAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCCfI6EW9ncHhXzPrLanhSW3wgIHOC1ky64U2EJJyLUyBwITU/MC
# KlBnRr+8AIWx9xRuvWDhOhgPMjAyNTA5MTExNTU2MTJaMAMCAQGgWKRWMFQxCzAJ
# BgNVBAYTAkJFMRkwFwYDVQQKDBBHbG9iYWxTaWduIG52LXNhMSowKAYDVQQDDCFH
# bG9iYWxzaWduIFRTQSBmb3IgQ29kZVNpZ24xIC0gUjagghJLMIIGYzCCBEugAwIB
# AgIQAQALIAWzlAdi2z42eZSbqTANBgkqhkiG9w0BAQwFADBbMQswCQYDVQQGEwJC
# RTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2ln
# biBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBHNDAeFw0yNTA0MTExNDQ3Mzla
# Fw0zNDEyMTAwMDAwMDBaMFQxCzAJBgNVBAYTAkJFMRkwFwYDVQQKDBBHbG9iYWxT
# aWduIG52LXNhMSowKAYDVQQDDCFHbG9iYWxzaWduIFRTQSBmb3IgQ29kZVNpZ24x
# IC0gUjYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCiW8SqTUnlI3g+
# 4IXr5qoKPtXyrKinRGH3isuZjfsKfx6vzRKR8rN0kcmTdOpr1BjhTBXqF51d9Jvm
# CTRfJ3Lcw0SPWoT5miY8RyMLu5G0Z18H8+2eJ5YnOO09VSWYQ+tQyygVTvCglJxF
# XVbr/p5+LYHJIdeyFnfRXUQNnaUpDQMrerdsjiwkT/mf91DLyIviGNNpL2/RhDLl
# Elj6jU1aHE/8ew26brs6visUOwYgTzmGDmviDcJcW6Kpa+U2Y9sIFaB3Gn88KpjQ
# uJ7TgO4psPBF3qeubkAfmghEnIVSMu8bgc7QvVRdgy4nonUnM7jfxEDSYlG9TZnB
# sjrKIUdpLTHdKAVqS+EQsufi2bCeBg+P4UNfctpYeeeL8wYldHGc3SlB1gmoRiEp
# SWswf37YqWd1zP/3JdgYTLBO3zx3fL5NQW9mUADQEw5gwytgVASm2VGDYNivHmxa
# 1fWq8LOTqwQEtFU8RsTSL4nTUguUHNGlwm6xlRDIYrZFVI4V9c8CAwEAAaOCAagw
# ggGkMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNV
# HQ4EFgQUgENM/LptHRPSdRKICXdv28ZPlVQwVgYDVR0gBE8wTTAIBgZngQwBBAIw
# QQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNp
# Z24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQCMAAwgZAGCCsGAQUFBwEBBIGD
# MIGAMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9n
# c3RzYWNhc2hhMzg0ZzQwQwYIKwYBBQUHMAKGN2h0dHA6Ly9zZWN1cmUuZ2xvYmFs
# c2lnbi5jb20vY2FjZXJ0L2dzdHNhY2FzaGEzODRnNC5jcnQwHwYDVR0jBBgwFoAU
# 6hbGaefjy1dFOTOk8EC+0MO9ZZYwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS9jYS9nc3RzYWNhc2hhMzg0ZzQuY3JsMA0GCSqGSIb3
# DQEBDAUAA4ICAQC3psdKmXZ0/SBiJ72JfDcHPlfPCy+aJiKwSNujJFmKf6Oofbog
# Wrt9Awis3lV1fwoaXmkR7bVvyyQ99Ry2KuijpBLmhYRKXiTNmjDaIn+omfvpOS8v
# 6/Z/iYeiUYsHDIObvh9evrxbrfG6JhKmdt/s1g/IFocjvMn8StJPhsDTRML5+0+2
# 1L4b8yE1RoqDfjJonxnoAQ2c90IHxUiu3+yp3pHWTz06PHWMvfpAEQ9SvZ20giVL
# cqLvgJTXlhO8b5fG31zAT7QbH+pFC/xhsX5Ryx2BhTiM1FkHSRNXcGx3eXIhaa3w
# NPhFCP0tDUgs6mob8LPB32r0YkvqNIl5KrUALhmhxUy6pxh38P0mkgwv0FD/CTmW
# AmSBcRzWBGA+wOxT3PPfonKY3X5iG/HRWvruOvRB+qTdXTPr/FWYQAkpp9N4h8P2
# FByGOIaTLDcQo2LIfIzfut0r8GxNLHSsHcwd2oT390dBfk1Q5AJZS+GRbLXS7vXL
# MYpadsBZDo026r1+1zBgVOZzKjlhsXDN+TJL5jvz47262qCLpWgTY3NUlu5yoYtm
# 0kUnMYkPvF7+upQvBgd5Dcc9Kc0JqBvqOoF4VKddPHQZu5i6TeMDnV1A22yiBUAZ
# cKoeyHrZBUCX+Bp1N9xFoykhYBzcI+6nfHX10MCmymZHI5XNcFS2yIJawjCCBlkw
# ggRBoAMCAQICDQHsHJJA3v0uQF18R3QwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UE
# CxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2JhbFNpZ24x
# EzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTgwNjIwMDAwMDAwWhcNMzQxMjEwMDAw
# MDAwWjBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEx
# MC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBH
# NDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAPAC4jAj+uAb4Zp0s691
# g1+pR1LHYTpjfDkjeW10/DHkdBIZlvrOJ2JbrgeKJ+5Xo8Q17bM0x6zDDOuAZm3R
# KErBLLu5cPJyroz3mVpddq6/RKh8QSSOj7rFT/82QaunLf14TkOI/pMZF9nuMc+8
# ijtuasSI8O6X9tzzGKBLmRwOh6cm4YjJoOWZ4p70nEw/XVvstu/SZc9FC1Q9sVRT
# B4uZbrhUmYqoMZI78np9/A5Y34Fq4bBsHmWCKtQhx5T+QpY78Quxf39GmA6HPXpl
# 69FWqS69+1g9tYX6U5lNW3TtckuiDYI3GQzQq+pawe8P1Zm5P/RPNfGcD9M3E1LZ
# JTTtlu/4Z+oIvo9Jev+QsdT3KRXX+Q1d1odDHnTEcCi0gHu9Kpu7hOEOrG8NubX2
# bVb+ih0JPiQOZybH/LINoJSwspTMe+Zn/qZYstTYQRLBVf1ukcW7sUwIS57UQgZv
# GxjVNupkrs799QXm4mbQDgUhrLERBiMZ5PsFNETqCK6dSWcRi4LlrVqGp2b9MwMB
# 3pkl+XFu6ZxdAkxgPM8CjwH9cu6S8acS3kISTeypJuV3AqwOVwwJ0WGeJoj8yLJN
# 22TwRZ+6wT9Uo9h2ApVsao3KIlz2DATjKfpLsBzTN3SE2R1mqzRzjx59fF6W1j0Z
# sJfqjFCRba9Xhn4QNx1rGhTfAgMBAAGjggEpMIIBJTAOBgNVHQ8BAf8EBAMCAYYw
# EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU6hbGaefjy1dFOTOk8EC+0MO9
# ZZYwHwYDVR0jBBgwFoAUrmwFo5MT4qLn4tcc1sfwf8hnU6AwPgYIKwYBBQUHAQEE
# MjAwMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9v
# dHI2MDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20v
# cm9vdC1yNi5jcmwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQB/4ojZV2crQl+BpwkLusS7KBhW1ky/2xsHcMb7CwmtADpgMx85xhZr
# GUBJJQge5Jv31qQNjx6W8oaiF95Bv0/hvKvN7sAjjMaF/ksVJPkYROwfwqSs0LLP
# 7MJWZR29f/begsi3n2HTtUZImJcCZ3oWlUrbYsbQswLMNEhFVd3s6UqfXhTtchBx
# dnDSD5bz6jdXlJEYr9yNmTgZWMKpoX6ibhUm6rT5fyrn50hkaS/SmqFy9vckS3Ra
# fXKGNbMCVx+LnPy7rEze+t5TTIP9ErG2SVVPdZ2sb0rILmq5yojDEjBOsghzn16h
# 1pnO6X1LlizMFmsYzeRZN4YJLOJF1rLNboJ1pdqNHrdbL4guPX3x8pEwBZzOe3yg
# xayvUQbwEccdMMVRVmDofJU9IuPVCiRTJ5eA+kiJJyx54jzlmx7jqoSCiT7ASvUh
# /mIQ7R0w/PbM6kgnfIt1Qn9ry/Ola5UfBFg0ContglDk0Xuoyea+SKorVdmNtyUg
# DhtRoNRjqoPqbHJhSsn6Q8TGV8Wdtjywi7C5HDHvve8U2BRAbCAdwi3oC8aNbYy2
# ce1SIf4+9p+fORqurNIveiCx9KyqHeItFJ36lmodxjzK89kcv1NNpEdZfJXEQ0H5
# JeIsEH6B+Q2Up33ytQn12GByQFCVINRDRL76oJXnIFm2eMakaqoimzCCBYMwggNr
# oAMCAQICDkXmuwODM8OFZUjm/0VRMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsT
# F0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMw
# EQYDVQQDEwpHbG9iYWxTaWduMB4XDTE0MTIxMDAwMDAwMFoXDTM0MTIxMDAwMDAw
# MFowTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoT
# Ckdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCVB+hzymb57BTKezz3DQjxtEULLIK0SMbrWzyug7hB
# kjMUpG9/6SrMxrCIa8W2idHGsv8UzlEUIexK3RtaxtaH7k06FQbtZGYLkoDKRN5z
# lE7zp4l/T3hjCMgSUG1CZi9NuXkoTVIaihqAtxmBDn7EirxkTCEcQ2jXPTyKxbJm
# 1ZCatzEGxb7ibTIGph75ueuqo7i/voJjUNDwGInf5A959eqiHyrScC5757yTu21T
# 4kh8jBAHOP9msndhfuDqjDyqtKT285VKEgdt/Yyyic/QoGF3yFh0sNQjOvddOsqi
# 250J3l1ELZDxgc1Xkvp+vFAEYzTfa5MYvms2sjnkrCQ2t/DvthwTV5O23rL44oW3
# c6K4NapF8uCdNqFvVIrxclZuLojFUUJEFZTuo8U4lptOTloLR/MGNkl3MLxxN+Wm
# 7CEIdfzmYRY/d9XZkZeECmzUAk10wBTt/Tn7g/JeFKEEsAvp/u6P4W4LsgizYWYJ
# arEGOmWWWcDwNf3J2iiNGhGHcIEKqJp1HZ46hgUAntuA1iX53AWeJ1lMdjlb6vml
# odiDD9H/3zAR+YXPM0j1ym1kFCx6WE/TSwhJxZVkGmMOeT31s4zKWK2cQkV5bg6H
# GVxUsWW2v4yb3BPpDW+4LtxnbsmLEbWEFIoAGXCDeZGXkdQaJ783HjIH2BRjPChM
# rwIDAQABo2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
# HQ4EFgQUrmwFo5MT4qLn4tcc1sfwf8hnU6AwHwYDVR0jBBgwFoAUrmwFo5MT4qLn
# 4tcc1sfwf8hnU6AwDQYJKoZIhvcNAQEMBQADggIBAIMl7ejR/ZVSzZ7ABKCRaeZc
# 0ITe3K2iT+hHeNZlmKlbqDyHfAKK0W63FnPmX8BUmNV0vsHN4hGRrSMYPd3hckSW
# tJVewHuOmXgWQxNWV7Oiszu1d9xAcqyj65s1PrEIIaHnxEM3eTK+teecLEy8QymZ
# jjDTrCHg4x362AczdlQAIiq5TSAucGja5VP8g1zTnfL/RAxEZvLS471GABptArol
# XY2hMVHdVEYcTduZlu8aHARcphXveOB5/l3bPqpMVf2aFalv4ab733Aw6cPuQkbt
# wpMFifp9Y3s/0HGBfADomK4OeDTDJfuvCp8ga907E48SjOJBGkh6c6B3ace2XH+C
# yB7+WBsoK6hsrV5twAXSe7frgP4lN/4Cm2isQl3D7vXM3PBQddI2aZzmewTfbgZp
# tt4KCUhZh+t7FGB6ZKppQ++Rx0zsGN1s71MtjJnhXvJyPs9UyL1n7KQPTEX/07kw
# IwdMjxC/hpbZmVq0mVccpMy7FYlTuiwFD+TEnhmxGDTVTJ267fcfrySVBHioA7vu
# geXaX3yLSqGQdCWnsz5LyCxWvcfI7zjiXJLwefechLp0LWEBIH5+0fJPB1lfiy1D
# UutGDJTh9WZHeXfVVFsfrSQ3y0VaTqBESMjYsJnFFYQJ9tZJScBluOYacW6gqPGC
# 6EU+bNYC1wpngwVayaQQMYIDSTCCA0UCAQEwbzBbMQswCQYDVQQGEwJCRTEZMBcG
# A1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1l
# c3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBHNAIQAQALIAWzlAdi2z42eZSbqTALBglg
# hkgBZQMEAgGgggEtMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDArBgkqhkiG
# 9w0BCTQxHjAcMAsGCWCGSAFlAwQCAaENBgkqhkiG9w0BAQsFADAvBgkqhkiG9w0B
# CQQxIgQgSAtzmJ1NjalLsIDAw7BHYNn7Sg4qKoh81yT0RqmWR2UwgbAGCyqGSIb3
# DQEJEAIvMYGgMIGdMIGaMIGXBCByXvJ/SOFuablj2EJojFvKB6iMaRcGQsj/Wit3
# r2Bc/TBzMF+kXTBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBu
# di1zYTExMC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEz
# ODQgLSBHNAIQAQALIAWzlAdi2z42eZSbqTANBgkqhkiG9w0BAQsFAASCAYA3antw
# Uicdj1hvVxDyieATgRppjxOY/rFHgg+ZBxjYsWGpmwx419lS54dyd8m0gfyuKbHI
# ZHF5e1WIDIET10PVIGamQ2Q8dKDoBP63IN1DziRnxZuS8FyucHSsQLR0oWDpQIuK
# SZZnFlGCUWztVjixZ/mjMjQurrcN492ZNZ5SFY2+bCU31vH3et+7qSC8+OB9EqdZ
# QoKPx2x4SjXUSFTnMOD7ZSa+aZrtKDDM00D7lRIXMUF/l/CgEtAYRZ3iB2+HzKWO
# 1cVVNux3b3siPATlOlm3m9x9RHztSYCllYCVKay7lg+/0EC3KBZ75xXcHlT+GmVv
# 1lMuQjYiWwsqG+6vrpNrTJeVbKSjicocaufzQ3y7WJ8AZE71+3o8B8ynSKsoY9sF
# TDXFo0tvDgjsAoi9eGi06W1g9854fMfc83SN8nyoPNYiNXJbABB58GKuLik0DcuT
# d2VXNwdZ0NHnuwNbz2N5Xus+e/dW/k0OJsNRAIv41E0xc7iGziBOFXRffVw=
# SIG # End signature block
