#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

    This unpublished material is proprietary to Alya Consulting.
    All rights reserved. The methods and techniques described
    herein are considered trade secrets and/or confidential. 
    Reproduction or distribution, in whole or in part, is 
    forbidden except by express written permission of Alya Consulting.

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    21.04.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "Config_alyainfphpol001.json"
)

#$PSScriptRoot = Split-Path $script:MyInvocation.MyCommand.Path

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\autoscale\02_SaveCredentials-$($AlyaTimeString).log" | Out-Null

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 02_SaveCredentials | WVD" -ForegroundColor $CommandInfo
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
                Write-Output $Cred.BaseName
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
    Write-Error "$JsonPath is invalid. Check Json syntax - Unable to proceed"
    Write-Log 3 "$JsonPath is invalid. Check Json syntax - Unable to proceed" "Error"
    exit 1
  }
}
else {
  #$Validate = $false
  Write-Error "Missing $JsonPath - Unable to proceed"
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