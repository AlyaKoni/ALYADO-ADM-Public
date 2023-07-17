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
    28.05.2021 Konrad Brunner       Initial Creation
    08.05.2023 Konrad Brunner       WebDriver version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
	[string]$emailAddressToAdd
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Set-EmailOnSecurityCenterAlerts-$($AlyaTimeString).log" | Out-Null

# Members
$TenantAdmins = "TenantAdmins"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Security | Set-EmailOnSecurityCenterAlerts | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

try
{
    $browser = Get-SeleniumBrowser
    $browser.Url = "https://security.microsoft.com/"
    $navi = $browser.Navigate()
    do
    {
        Start-Sleep -Milliseconds 1000
    } while ($browser.Title -notlike "Startseite*Microsoft 365 Security" -and $browser.Title -ne "TODO")
    Start-Sleep -Seconds 2
    $browser.Url = "https://security.microsoft.com/alertpolicies"
    $navi = $browser.Navigate()
    do
    {
        Start-Sleep -Milliseconds 1000
    } while ($browser.Title -notlike "Warnungsrichtlinie*Microsoft 365 Security" -and $browser.Title -ne "TODO")
    Start-Sleep -Seconds 2

    $alreadyDone = @()
    do
    {
        $somethingChanged = $false

        $gridField = $null
        do
        {
            Start-Sleep -Milliseconds 500
            try
            {
                $gridField = $browser.FindElement([OpenQA.Selenium.By]::XPath("//div[@role='grid']"))
            } catch {}
        } while ($null -eq $gridField)

        $msgBtns = $browser.FindElements([OpenQA.Selenium.By]::XPath("//button[@type='button' and .//span='Schließen']"))
        foreach($msgBtn in $msgBtns)
        {
            $msgBtn.Click()
        }

        do
        {
            Start-Sleep -Milliseconds 500
            try
            {
                $rows = $gridField.FindElements([OpenQA.Selenium.By]::XPath(".//div[@role='row']"))
            } catch {}
        } while (-Not $rows -or $rows.Count -lt 30)

        $proceed = $true
        foreach($row in $rows)
        {
            $msgBtns = $browser.FindElements([OpenQA.Selenium.By]::XPath("//button[@type='button' and .//span='Schließen']"))
            foreach($msgBtn in $msgBtns)
            {
                $msgBtn.Click()
            }
    
            if (-Not $proceed) { continue }
            if ($row.FindElements([OpenQA.Selenium.By]::XPath(".//div[@data-automation-key='CustomSeverity']")).Count -gt 0)
            {
                $sev = $row.FindElement([OpenQA.Selenium.By]::XPath(".//div[@data-automation-key='CustomSeverity']"))
                $btn = $row.FindElement([OpenQA.Selenium.By]::XPath(".//button"))
                if ($btn.Text -in $alreadyDone) { continue }
                $alreadyDone += $btn.Text
                Write-Host "$($btn.Text)"
                if ($sev.Text -in @("Hoch"))
                {
                    $btn.Click()
                    $iconField = $null
                    do
                    {
                        Start-Sleep -Milliseconds 500
                        try
                        {
                            $dlgField = $browser.FindElement([OpenQA.Selenium.By]::XPath("//div[@role='dialog' and @aria-label='$($btn.text)']"))
                            if ($dlgField)
                            {
                                $grpField = $dlgField.FindElement([OpenQA.Selenium.By]::XPath(".//div[@role='menubar']"))
                                if ($grpField)
                                {
                                    $iconField = $grpField.FindElement([OpenQA.Selenium.By]::XPath(".//button"))
                                }
                            }
                        } catch {}
                    } while ($null -eq $iconField)
                    $iconField.Click()
                    
                    $inputField = $null
                    do
                    {
                        Start-Sleep -Milliseconds 500
                        try
                        {
                            $dlgFields = $browser.FindElements([OpenQA.Selenium.By]::XPath("//div[@role='dialog']"))
                            $dlgField2 = $dlgFields | Where-Object { $_ -ne $dlgField }
                            if ($dlgField)
                            {
                                $inputField = $dlgField2.FindElement([OpenQA.Selenium.By]::XPath(".//input[@role='combobox']"))
                            }
                        } catch {}
                    } while ($null -eq $inputField)

                    Start-Sleep -Milliseconds 500
                    $existFields = $dlgField2.FindElements([OpenQA.Selenium.By]::XPath("//div[contains(@class,'ms-PickerPersona-container')]"))
                    $existFound = $existFields | where { $_.Text -like "*$($emailAddressToAdd)*" }

                    if (-Not $existFound) {
                        Write-Host "  configuring"
                        $body = $browser.FindElement([OpenQA.Selenium.By]::XPath("//body"))
                        $body.SendKeys("`t")
                        $body.SendKeys("`t")
                        $inputField.SendKeys("$emailAddressToAdd")

                        $suggField = $null
                        do
                        {
                            Start-Sleep -Milliseconds 500
                            try
                            {
                                $sugCField = $browser.FindElement([OpenQA.Selenium.By]::XPath("//div[contains(@class,'ms-Suggestions-container')]"))
                                if ($sugCField)
                                {
                                    $suggField = $sugCField.FindElement([OpenQA.Selenium.By]::XPath("//div[contains(@class,'ms-Suggestions-item')]"))
                                }
                            } catch {}
                        } while ($null -eq $suggField)
                        $suggField.Click()

                        if ($btn.Text -like "*Reply-all storm detected*")
                        {
                            $valueField = $dlgField2.FindElement([OpenQA.Selenium.By]::XPath(".//input[@type='number']"))
                            $valueField.SendKeys("`b`b`b`b`b`b`b`b`b`b`b20")
                        }

                        $weiter = $null
                        do
                        {
                            Start-Sleep -Milliseconds 500
                            try
                            {
                                $weiter = $dlgField2.FindElement([OpenQA.Selenium.By]::XPath(".//button[@aria-label='Weiter']"))
                            } catch {}
                        } while ($null -eq $weiter)
                        $weiter.Click()

                        $absenden = $null
                        do
                        {
                            Start-Sleep -Milliseconds 500
                            try
                            {
                                $absenden = $dlgField2.FindElement([OpenQA.Selenium.By]::XPath(".//button[@aria-label='Absenden']"))
                            } catch {}
                        } while ($null -eq $absenden)
                        $absenden.Click()

                        $fertig = $null
                        do
                        {
                            Start-Sleep -Milliseconds 500
                            try
                            {
                                $fertig = $dlgField2.FindElement([OpenQA.Selenium.By]::XPath(".//button[@aria-label='Fertig']"))
                            } catch {}
                        } while ($null -eq $fertig)
                        $fertig.Click()
                        $proceed = $false
                        $somethingChanged = $true
                    }
                    else {
                        $abbrechen = $null
                        do
                        {
                            Start-Sleep -Milliseconds 500
                            try
                            {
                                $abbrechen = $dlgField2.FindElement([OpenQA.Selenium.By]::XPath(".//button[@aria-label='Abbrechen']"))
                            } catch {}
                        } while ($null -eq $abbrechen)
                        $abbrechen.Click()
                    }

                    $msgBtn = $dlgField.FindElement([OpenQA.Selenium.By]::XPath("//button[@type='button' and @aria-label='Schließen']"))
                    $msgBtn.Click()
                }
            }

        }

    } while ($somethingChanged)

    <#LoginTo-IPPS
    $protAlerts = Get-ProtectionAlert
    foreach($protAlert in $protAlerts)
    {
        #$protAlert = $protAlerts[9]
        Write-Host "Checking alert $($protAlert.Name)" -ForegroundColor $CommandInfo
        $actUsers = @(([string[]]$protAlert.NotifyUser) | Foreach-Object { $_.toLower() })
        if ($actUsers -notcontains $emailAddress.ToLower())
        {
            Write-Host "Adding $($emailAddress)"
            $actUsers += $emailAddress
            if ($protAlert.IsSystemRule)
            {
                Write-Warning "  Can't change system rule"
                Write-Warning "  See https://github.com/MicrosoftDocs/office-docs-powershell/issues/3433"
            }
            else
            {
                Set-ProtectionAlert -Identity $protAlert.DistinguishedName -NotifyUser $actUsers
            }
        }
    }#>
}
catch
{
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 3) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}
finally
{
    #DisconnectFrom-EXOandIPPS
    Close-SeleniumBrowser -browser $browser
}

#Stopping Transscript
Stop-Transcript
