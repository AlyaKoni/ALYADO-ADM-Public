#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

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
    Alya Basis Konfiguration ist Freie Software: Sie koennen es unter den
	Bedingungen der GNU General Public License, wie von der Free Software
	Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veroeffentlichten Version, weiter verteilen und/oder modifizieren.
    Alya Basis Konfiguration wird in der Hoffnung, dass es nuetzlich sein wird,
	aber OHNE JEDE GEWAEHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewaehrleistung der MARKTFAEHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
	https://www.gnu.org/licenses/gpl-3.0.txt

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    21.04.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "Autoscaling_Config.json"
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\autoscale\Save-AutoscalingCredentials-$($AlyaTimeString).log" | Out-Null

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD Autoscaling | Save-AutoscalingCredentials | LOCAL" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# =============================================================
# Functions
# =============================================================

#Store PWD Function
Function Store-Credentials {
    param(
        [Parameter(Mandatory=$true)]
        [String]$UserName,
        [Parameter(Mandatory=$true)]
        [SecureString]$Password
        )
    $Password | ConvertFrom-SecureString | Out-File "$($PSScriptRoot)\Creds\$($UserName).cred" -Force
}

Function Get-StoredCredential {
    param(
        [Parameter(Mandatory=$false, ParameterSetName="Get")]
        [string]$UserName,
        [Parameter(Mandatory=$false, ParameterSetName="List")]
        [switch]$List
        )

    if ($List) {
        try {
            $CredentialList = @(Get-ChildItem -Path "$($PSScriptRoot)\Creds" -Filter *.cred -ErrorAction STOP)
            foreach ($Cred in $CredentialList) {
                Write-Host $Cred.BaseName
            }
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
    if ($UserName) {
        if (Test-Path "$($PSScriptRoot)\Creds\$($Username).cred") {
            $PwdSecureString = Get-Content "$($PSScriptRoot)\Creds\$($Username).cred" | ConvertTo-SecureString
            $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, $PwdSecureString
        }
        else {
            throw "Unable to locate a credential for $($Username)"
        }
        return $Credential
    }
}

#Function for creating a variable from JSON
function Set-ScriptVariable ($Name,$Value) {
  Invoke-Expression ("`$Script:" + $Name + " = `"" + $Value + "`"")
}

# =============================================================
# Main
# =============================================================

##### Json path #####
$JsonPath = "$PSScriptRoot\$ConfigFile"

###### Verify Json file ######
if (Test-Path $JsonPath) {
  Write-Verbose "Found $JsonPath"
  Write-Verbose "Validating file..."
  try {
    $Variable = Get-Content $JsonPath | Out-String | ConvertFrom-Json
  }
  catch {
    #$Validate = $false
    Write-Error "$JsonPath is invalid. Check Json syntax - Unable to proceed" -ErrorAction Continue
    Write-Log 3 "$JsonPath is invalid. Check Json syntax - Unable to proceed" "Error"
    exit 1
  }
}
else {
  #$Validate = $false
  Write-Error "Missing $JsonPath - Unable to proceed" -ErrorAction Continue
  Write-Log 3 "Missing $JsonPath - Unable to proceed" "Error"
  exit 1
}
##### Load Json Configuration values as variables #########
Write-Verbose "Loading values from Config.Json"
$Variable = Get-Content $JsonPath | Out-String | ConvertFrom-Json
$Variable.WVDScale.Azure | ForEach-Object { $_.Variables } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
$Variable.WVDScale.WVDScaleSettings | ForEach-Object { $_.Variables } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
$Variable.WVDScale.Deployment | ForEach-Object { $_.Variables } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }

New-Item -Path "$($PSScriptRoot)\Creds" -ItemType Directory -Force | Out-Null

##### Getting secrets #####
$sCreds = Get-StoredCredential -List
if ($sCreds -notcontains $AADApplicationId)
{
    Write-Host "Missing credentials for AADApplicationId"
    $creds = Get-Credential -Message "Please provide credentials for AADApplicationId" -UserName "AADApplicationId"
    Store-Credentials -UserName $AADApplicationId -Password $creds.Password
}
else
{
    Write-Host "Credentials for AADApplicationId already set"
}
if ($sCreds -notcontains $UserName)
{
    Write-Host "Missing credentials for UserName"
    $creds = Get-Credential -Message "Please provide credentials for UserName" -UserName "UserName"
    Store-Credentials -UserName $UserName -Password $creds.Password
}
else
{
    Write-Host "Credentials for UserName already set"
}

Write-Host "Actual credentials: "
Get-StoredCredential -List

#Stopping Transscript
Stop-Transcript