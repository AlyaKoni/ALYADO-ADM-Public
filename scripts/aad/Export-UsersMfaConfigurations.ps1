#Requires -Version 2.0

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
    14.11.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$outputFile = $null #Defaults to "$AlyaData\aad\UsersMfaConfigurations.xlsx"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Export-UsersMfaConfigurations-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $outputFile)
{
    $outputFile = "$AlyaData\aad\UsersMfaConfigurations.xlsx"
}
$outputDirectory = Split-Path $outputFile -Parent
if (-Not (Test-Path $outputDirectory))
{
    New-Item -Path $outputDirectory -ItemType Directory -Force
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ImportExcel"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Reports"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes @("Directory.Read.All", "Policy.Read.All", "UserAuthenticationMethod.Read.All", "AuditLog.Read.All")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Export-UsersMfaConfigurations | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting users
Write-Host "Getting users" -ForegroundColor $CommandInfo
$users = Get-MgBetaUser -Property "*" -All
$regDets = Get-MgBetaReportAuthenticationMethodUserRegistrationDetail

$propNames = @(
    "UserPrincipalName",
    "UserType",
    "AccountEnabled",
    "DisplayName",
    "Authentication",
    "CreatedDateTime",
    "Mail",
    "OtherMails",
    "ProxyAddresses"
)

$propNamesAuthenticationPrefs = @(
    "isSystemPreferredAuthenticationMethodEnabled",
    "userPreferredMethodForSecondaryAuthentication",
    "systemPreferredAuthenticationMethod"
)

$propNamesRegistrationDetails = @(
    "DefaultMfaMethod",
    "IsAdmin",
    "IsMfaCapable",
    "IsMfaRegistered",
    "IsPasswordlessCapable",
    "IsSsprCapable",
    "IsSsprEnabled",
    "IsSsprRegistered",
    "IsSystemPreferredAuthenticationMethodEnabled2",
    "MethodsRegistered",
    "SystemPreferredAuthenticationMethods",
    "UserPreferredMethodForSecondaryAuthentication2"
)

$methodNamesAuthentication = @(
    "smsAuthenticationMethod",
    "smsAuthenticationMethodCnt",
    "emailAuthenticationMethod",
    "emailAuthenticationMethodCnt",
    "phoneAuthenticationMethodMobile",
    "phoneAuthenticationMethodMobileCnt",
    "phoneAuthenticationMethodOffice",
    "phoneAuthenticationMethodOfficeCnt",
    "voiceAuthenticationMethod",
    "voiceAuthenticationMethodCnt",
    "microsoftAuthenticatorAuthenticationMethod",
    "microsoftAuthenticatorAuthenticationMethodCnt",
    "temporaryAccessPassAuthenticationMethod",
    "temporaryAccessPassAuthenticationMethodCnt",
    "fido2AuthenticationMethod",
    "fido2AuthenticationMethodCnt",
    "passwordAuthenticationMethod",
    "passwordAuthenticationMethodCnt",
    "passwordlessMicrosoftAuthenticatorMethod",
    "passwordlessMicrosoftAuthenticatorMethodCnt",
    "platformCredentialMethod",
    "platformCredentialMethodCnt",
    "softwareOathMethod",
    "softwareOathMethodCnt",
    "windowsHelloForBusinessMethod",
    "windowsHelloForBusinessMethodCnt"
)

$psusers = @()
foreach($user in $users)
{
    Write-Host "  Exporting $($user.UserPrincipalName)"
    #if ($user.UserPrincipalName -notlike "*brunner*") { continue }
    $psuser = New-Object PSObject
    $allProps = $user.PSObject.Properties
    foreach($prop in $propNames)
    {
        $psProp = $allProps | Where-Object { $_.Name -eq $prop }
        if (-Not $psProp)
        {
            Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value ""
            continue
        }
        if ($prop -eq "Authentication")
        {
            $regDet = $regDets| Where-Object { $_.Id -eq $user.Id -or $_.UserPrincipalName -eq $user.UserPrincipalName }
            foreach($propName in $propNamesRegistrationDetails)
            {
                $name = $propName
                if ($propName -eq "IsSystemPreferredAuthenticationMethodEnabled2") { $propName = "IsSystemPreferredAuthenticationMethodEnabled" }
                if ($propName -eq "UserPreferredMethodForSecondaryAuthentication2") { $propName = "UserPreferredMethodForSecondaryAuthentication" }
                $value = $null
                if ($regDet -and $regDet.$propName) { $value = $regDet.$propName }
                if ($propName -eq "MethodsRegistered") { $value = $regDet.$propName -join "," }
                if ($propName -eq "SystemPreferredAuthenticationMethods") { $value = $regDet.$propName -join "," }
                Add-Member -InputObject $psuser -MemberType NoteProperty -Name $name -Value $value
            }
            $signInPref = Get-MsGraphObject -Uri "https://graph.microsoft.com/beta/users/$([System.Web.HTTPUtility]::UrlEncode($user.UserPrincipalName))/authentication/signInPreferences"
            foreach($propName in $propNamesAuthenticationPrefs)
            {
                Add-Member -InputObject $psuser -MemberType NoteProperty -Name $propName -Value $signInPref[$propName]
            }
            $methods = Get-MgBetaUserAuthenticationMethod -UserId $user.UserPrincipalName
            foreach($prmethodName in $methodNamesAuthentication)
            {
                if ($propNamesAuthenticationPrefs -contains $prmethodName) { continue }
                $className = $prmethodName.Replace("Cnt", "")
                if ($prmethodName.StartsWith("phoneAuthenticationMethod")) {
                    if ($prmethodName.Contains("Office")) {
                        $className = $className.Replace("Office", "")
                        $confMeths = $methods | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.$className" -and $_.AdditionalProperties.phoneType -eq "office"}
                    } else {
                        $className = $className.Replace("Mobile", "")
                        $confMeths = $methods | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.$className" -and $_.AdditionalProperties.phoneType -eq "mobile"}
                    }
                } else {
                    $confMeths = $methods | Where-Object { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.$className"}
                }
                if ($confMeths -and $confMeths.Count -gt 0) {
                    if ($prmethodName.EndsWith("Cnt")) {
                        Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prmethodName -Value $confMeths.Count
                    } else {
                        Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prmethodName -Value ($confMeths | ConvertTo-Json -Compress -Depth 6 -WarningAction SilentlyContinue)
                    }
                } else {
                    Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prmethodName -Value $null
                }
            }
        }
        switch ($psProp.TypeNameOfValue)
        {
            "System.Xml.XmlElement" {
                Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value $user."$prop".OuterXml
            }
            "System.String" {
                Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value $user."$prop"
            }
            "System.String[]" {
                Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value ($user."$prop" -join ";")
            }
            default {
                $val = ""
                if ($psProp.TypeNameOfValue.Contains("DateTime"))
                {
                    if ($null -ne $user."$prop")
                    {
                        $val = $user."$prop".ToString("s")
                    }
                }
                elseif ($psProp.TypeNameOfValue.Contains("Microsoft.Graph.Beta.PowerShell.Models") -or `
                $psProp.TypeNameOfValue.Contains("StrongAuthenticationUserDetails") -or `
                $psProp.TypeNameOfValue.Contains("StrongAuthenticationMethod") -or `
                $psProp.TypeNameOfValue.Contains("ExtensionDataObject"))
                {
                    $val = ($user."$prop" | ConvertTo-Json -Compress -Depth 1 -WarningAction SilentlyContinue)
                }
                elseif ($psProp.TypeNameOfValue.Contains("[]") -or `
                    $psProp.TypeNameOfValue.Contains("System.Collections.Generic.Dictionary") -or `
                    $psProp.TypeNameOfValue.Contains("System.Collections.Generic.List"))
                {
                    $val = ""
                    foreach($prt in $user."$prop")
                    {
                        if ($null -ne $prt)
                        {
                            $val += $prt.ToString() + ";"
                        }
                    }
                    $val = $val.TrimEnd(";")
                }
                elseif ($psProp.TypeNameOfValue.Contains("[[System.String") -and $psProp.TypeNameOfValue.Contains(",[System.Object") -and $psProp.TypeNameOfValue.Contains("System.Collections.Generic.IDictionary"))
                {
                    $val = ""
                    foreach($prt in $user."$prop".GetEnumerator())
                    {
                        if ($null -ne $prt.Value)
                        {
                            $val += $prt.Key + "=" + $prt.Value.ToString() + ";"
                        }
                        else
                        {
                            $val += $prt.Key + "=;"
                        }
                    }
                    $val = $val.TrimEnd(";")
                }
                else
                {
                    if ($null -ne $user."$prop")
                    {
                        $val = $user."$prop".ToString()
                    }
                    else
                    {
                        $val = ""
                    }
                }
                Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value $val
            }
        }
    }
    $psusers += $psuser
}

do
{
    try
    {
        $propNames += $propNamesRegistrationDetails
        $propNames += $propNamesAuthenticationPrefs
        $propNames += $methodNamesAuthentication
        $excel = $psusers | Select-Object -Property $propNames | Export-Excel -Path $outputFile -WorksheetName "Users" -TableName "Users" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru
        #$ws = $excel.Workbook.Worksheets['Users']
        #Set-Format -Worksheet $ws -Range "A:BZ" -
        Close-ExcelPackage $excel -Show
        break
    } catch
    {
        if ($_.Exception.Message.Contains("Could not open Excel Package"))
        {
            Write-Host "Please close excel sheet $outputFile"
            pause
        }
        else
        {
            throw
        }
    }
} while ($true)

#Stopping Transscript
Stop-Transcript
