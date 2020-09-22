$ExportUsers = @(
    "cloud.test@alyaconsulting.ch",
    "first.last@alyaconsulting.ch"
)

$Cmd = Get-Command -Name New-MailboxExportRequest -ErrorAction SilentlyContinue
if (-Not $Cmd)
{
    $Cmd = Get-Command -Name New-MailboxExportRequest -ErrorAction SilentlyContinue
    if (-Not $Cmd)
    {
        Write-Host "You are not running in an Exchange PowerShell!" -ForegroundColor Red
        Return
    }
    else
    {
        $usr = [Environment]::UserName.ToLower()
        New-ManagementRoleAssignment –Role "Mailbox Import Export" –User $usr
        Write-Host "We had to add your account to the export role in exchange. Please close and restart session to make your role active." -ForegroundColor Red
        Return
    }
}

foreach ($ExportUser in $ExportUsers)
{
    Write-Host "Exporting $ExportUser"
    New-MailboxExportRequest -Name $ExportUser -Mailbox $ExportUser -FilePath "\\server\ExchangeExport\ServerExports\$($ExportUser).pst"
}

$AllDone = $false
Write-Host "Exporting" -NoNewline
while(-Not $AllDone)
{
    $AllDone = $true
    foreach ($ExportUser in $ExportUsers)
    {
        $Req = Get-MailboxExportRequest -Name $ExportUser
        if ($Req -eq "Queued" -or $Req -eq "InProgress")
        {
            $AllDone = $false
        }
    }
    Write-Host "." -NoNewline
    Start-Sleep -Seconds 10
}
Write-Host ""
Get-MailboxExportRequest
