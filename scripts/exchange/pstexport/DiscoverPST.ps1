Start-Transcript -Path "\\server\ExchangeExport\Logs\$([Guid]::NewGuid()).log" -Force
Add-Type -assembly system.web.extensions
$jsonSerializer = new-object system.web.script.serialization.javascriptSerializer
$usr = [Environment]::UserName.ToLower()
$dmn = [Environment]::UserDomainName.ToLower()
$comp = [Environment]::MachineName.ToLower()
$outlook = New-Object -comObject Outlook.Application
$psts = $outlook.Session.Stores | where { ($_.FilePath.ToLower() -like '*.pst')}
$osts = $outlook.Session.Stores | where { ($_.FilePath.ToLower() -like '*.ost')}
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
