$thresholdCpuUsage = 10 # %, 0 to disable
$thresholdDiskUsage = 10 # %, 0 to disable
$thresholdNetUsage = 200 # Kb/s, 0 to disable
$activeProcessList = @("ProcessNameToCheckFor1", "ProcessNameToCheckFor2") # if one of these processes ist found, the client will be marked as active. Use ProcessName given by output from Get-Process
$numSamples = 3 # if you run the script every 10 minutes, the vm will be stopped after numSamples*10 minutes idle time

Start-Sleep -Seconds 5 # Scheduler and PowerShell start cool down

$cpuUsage = (Get-CimInstance win32_processor | Measure-Object -Property LoadPercentage -Average).Average
$diskUsage = 100-(Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk | where { $_.Name -eq "_Total"}).PercentIdleTime
$sampleCount = 0
$actBandwidth = do {
    $sampleCount ++
    (Get-CimInstance -Query "Select BytesTotalPersec from Win32_PerfFormattedData_Tcpip_NetworkInterface" | Select-Object BytesTotalPerSec | where {$_.BytesTotalPerSec -gt 0}).BytesTotalPerSec
} while ($sampleCount -le 10)
$netUsage = [math]::round(($actBandwidth | Measure-Object -Average).average, 2) / 1024 * 8
$hasActiveUser = $false
$actUsers = ((quser) -replace '^[> ]', '') -replace '\s{2,}', '¬'
foreach($actUser in $actUsers)
{
    $state = $actUser.Split("¬")[3]
    if ($state -eq "Aktiv" -or $state -eq "Active")
    {
        $hasActiveUser = $true
        break
    }
}
$hasActiveProcess = $false
foreach($processName in $activeProcessList)
{
    $proc = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($proc)
    {
        $hasActiveProcess = $true
        break
    }
}

$scriptDir = $PSScriptRoot
$logFile = "$scriptDir\CheckComputerActivityLog.csv"
$stateFile = "$scriptDir\CheckComputerActivityAct.csv"
$actDate = Get-Date

if (-Not (Test-Path $logFile))
{
    Add-Content -Path $logFile -Value '"date","cpuUsage","diskUsage","netUsage","hasActiveProcess","hasActiveUser","decision"'
}
Add-Content -Path $logFile -Value "`"$($actDate.ToString("s"))`",`"$($cpuUsage)`",`"$($diskUsage)`",`"$([int]$netUsage)`",`"$($hasActiveProcess)`",`"$($hasActiveUser)`",`"`""

if ((Test-Path $stateFile))
{
    $states = @(Import-Csv -Delimiter "," -Path $stateFile -Encoding UTF8 -ErrorAction SilentlyContinue)
}
else
{
    $states = @()
}
$states += [pscustomobject]@{
    date = $actDate.ToString("s")
    cpuUsage = $cpuUsage
    diskUsage = $diskUsage
    netUsage = [int]$netUsage
    hasActiveProcess = $hasActiveProcess
    hasActiveUser = $hasActiveUser
}
$states | Select -Last $numSamples | Export-Csv -Delimiter "," -Path $stateFile -Encoding UTF8 -Force -NoTypeInformation
$states = @(Import-Csv -Delimiter "," -Path $stateFile -Encoding UTF8 -ErrorAction SilentlyContinue)

if ($states.Count -eq $numSamples)
{
    $haveToShotdown = $true
    foreach($state in $states)
    {
        if ([int]$state.cpuUsage -gt $thresholdCpuUsage -or [int]$state.diskUsage -gt $thresholdDiskUsage -or [int]$state.netUsage -gt $thresholdNetUsage -or $state.hasActiveProcess -eq "True" -or $state.hasActiveUser -eq "True")
        {
            $haveToShotdown = $false
            break
        }
    }
    if (-Not $haveToShotdown)
    {
        Write-Host "Computer is active"
    }
    else
    {
        Write-Warning "Computer is inactive, will shutdown now"
        Add-Content -Path $logFile -Value "`"$($actDate.ToString("s"))`",`"100`",`"100`",`"100000`",`"True`",`"True`",`"Shutdown`""
        Add-Content -Path $stateFile -Value "`"$($actDate.ToString("s"))`",`"100`",`"100`",`"100000`",`"True`",`"True`""
        #place here VM shutdown part, as an example a call to a webhook
        #Invoke-WebRequest -Method POST -Uri UriToStopThisVm
    }
}
else
{
    Write-Host "Computer is active"
}
