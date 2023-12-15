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

Start-Transcript -Path "\\server\ExchangeExport\Logs\$([Guid]::NewGuid()).log" -Force
Add-Type -assembly system.web.extensions
$jsonSerializer = new-object system.web.script.serialization.javascriptSerializer
$usr = [Environment]::UserName.ToLower()
$dmn = [Environment]::UserDomainName.ToLower()
$comp = [Environment]::MachineName.ToLower()
$outlook = New-Object -comObject Outlook.Application
$psts = $outlook.Session.Stores | Where-Object { ($_.FilePath.ToLower() -like '*.pst')}
$osts = $outlook.Session.Stores | Where-Object { ($_.FilePath.ToLower() -like '*.ost')}
$accnts = $outlook.Session.Accounts
$result = @{usr = $usr;dmn = $dmn;comp = $comp;accnts = @();osts = @(); psts = @()}
foreach ($pst in $psts)
{
    $result.psts += @{
        DisplayName = $pst.DisplayName
        FilePath = $pst.FilePath
    }
}
foreach ($ost in $osts)
{
    $result.osts += @{
        DisplayName = $ost.DisplayName
        FilePath = $ost.FilePath
    }
}
foreach ($accnt in $accnts)
{
    $result.accnts += @{
        DisplayName = $accnt.DisplayName
        AccountType = $accnt.AccountType
        UserName = $accnt.UserName
        SmtpAddress = $accnt.SmtpAddress
    }
}
$json = $jsonSerializer.Serialize($result)
$json | Set-Content -Path "\\server\ExchangeExport\$($dmn)-$($usr)-$($comp).json" -Force
$json
Stop-Transcript
