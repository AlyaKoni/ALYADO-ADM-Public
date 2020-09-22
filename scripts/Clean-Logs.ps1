$LogPath = "$PSScriptRoot\..\_logs"
$Logs = Get-ChildItem -Path $LogPath -Recurse -Force -File
$OldLogs = $Logs | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-60)}
foreach($log in $OldLogs)
{
    Write-Host "Removing $($log.FullName)"
    Remove-Item -Path $log.FullName -Force
}
