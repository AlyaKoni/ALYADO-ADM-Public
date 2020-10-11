$allSessions = Find-CopySessions
$unfinishedSessions = $allSessions | Where-Object { $_.HasEnded -eq $False }
$finishedSessions = $allSessions | Where-Object { $_.HasEnded -eq $True }

Write-Output "Finished sessions:"
Write-Output "==================`n"
$finishedSessions

Write-Output "Unfinished sessions:"
Write-Output "====================`n"
$unfinishedSessions
