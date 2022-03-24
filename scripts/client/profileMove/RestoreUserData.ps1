#Preparation
$userName = $env:USERNAME
$hostName = $env:COMPUTERNAME
$localAppData = $env:LOCALAPPDATA
$appData = $env:APPDATA
if (-Not $PSScriptRoot)
{
	$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
}
$userHostDir = "$PSScriptRoot\$userName\$hostName"
if (-Not (Test-Path $userHostDir))
{
    Write-Host "No saved user data found." -ForegroundColor Red
    $hosts = Get-ChildItem -Path "$PSScriptRoot\$userName"
    if ($hosts.Length -gt 1)
    {
        $hostDir = $hosts | Out-GridView -Title 'Select settings to be restored' -OutputMode Single
        if (-Not $hostDir) { exit }
        $hostName = $hostDir.Name
        $userHostDir = "$PSScriptRoot\$userName\$hostName"
    }
    else
    {
        $hostName = $hosts[0].Name
        $userHostDir = "$PSScriptRoot\$userName\$hostName"
    }
}
$timeString = (Get-Date).ToString("yyyyMMddHHmmss")
Start-Transcript -Path "$userHostDir\RestoreUserData-$timeString.log" | Out-Null

#Restoring MRU
Write-Host "MRU Restore" -ForegroundColor Cyan
$mrus = Get-ChildItem -Path "$userHostDir\Microsoft\RegistryMRU" -Filter "*.reg"
foreach($mru in $mrus)
{
    Write-Host "  Importing $($mru.FullName)"
    reg import "$($mru.FullName)"
}

#Restoring Taskbar
Write-Host "Taskbar Restore" -ForegroundColor Cyan
$taskbarDir = "$userHostDir\Microsoft\TaskBar"
if (Test-Path $taskbarDir)
{
    if (-Not (Test-Path "$appData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"))
    {
        $null = New-Item -Path "$appData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $taskbarDir "$appData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
}
else
{
    Write-Host "  No taskbar shortcuts found in $taskbarDir"
}

#Restoring Signatures
Write-Host "Outlook Signatures Restore" -ForegroundColor Cyan
$signaturesDir = "$userHostDir\Microsoft\Signatures"
if (Test-Path $signaturesDir)
{
    if (-Not (Test-Path "$appData\Microsoft\Signatures"))
    {
        $null = New-Item -Path "$appData\Microsoft\Signatures" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $signaturesDir "$appData\Microsoft\Signatures"
}
else
{
    Write-Host "  No signatures found in $signaturesDir"
}

#Restoring Firefox
Write-Host "Firefox Backup" -ForegroundColor Cyan
$firefoxDir = "$userHostDir\Firefox"
if (Test-Path $firefoxDir)
{
    do
    {
        $process = Get-Process -Name "Firefox.exe" -ErrorAction SilentlyContinue
        if ($process)
        {
            Write-Warning "Bitte den Firefox Browser schliessen!"
            pause
        }
    }
    while ($process -ne $null)
    if (-Not (Test-Path "$appData\Mozilla\Firefox"))
    {
        $null = New-Item -Path "$appData\Mozilla\Firefox" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $firefoxDir "$appData\Mozilla\Firefox"
}
else
{
    Write-Host "  No Firefox configuration found in $firefoxDir"
}

#Restoring Edge
Write-Host "Edge Restore" -ForegroundColor Cyan
$edgeDir = "$userHostDir\Edge"
if (Test-Path $edgeDir)
{
    do
    {
        $process = Get-Process -Name "edge.exe" -ErrorAction SilentlyContinue
        if ($process)
        {
            Write-Warning "Bitte den Edge Browser schliessen!"
            pause
        }
    }
    while ($process -ne $null)
    if (-Not (Test-Path "$localAppData\Microsoft\Edge\User Data"))
    {
        $null = New-Item -Path "$localAppData\Microsoft\Edge\User Data" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $edgeDir "$localAppData\Microsoft\Edge\User Data"
}
else
{
    Write-Host "  No Edge configuration found in $edgeDir"
}

#Restoring Chrome
Write-Host "Chrome Restore" -ForegroundColor Cyan
$chromeDir = "$userHostDir\Chrome"
if (Test-Path $chromeDir)
{
    do
    {
        $process = Get-Process -Name "chrome.exe" -ErrorAction SilentlyContinue
        if ($process)
        {
            Write-Warning "Bitte den Chrome Browser schliessen!"
            pause
        }
    }
    while ($process -ne $null)
    if (-Not (Test-Path "$localAppData\Google\Chrome\User Data"))
    {
        $null = New-Item -Path "$localAppData\Google\Chrome\User Data" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $chromeDir "$localAppData\Google\Chrome\User Data"
}
else
{
    Write-Host "  No Chrome configuration found in $chromeDir"
}

Stop-Transcript
