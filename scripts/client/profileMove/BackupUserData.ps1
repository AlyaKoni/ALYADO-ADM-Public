#Preparation
$clientHasOndeDriveBackup = $false
$userName = $env:USERNAME
$hostName = $env:COMPUTERNAME
$localAppData = $env:LOCALAPPDATA
$appData = $env:APPDATA
$userprofile = $env:USERPROFILE
if (-Not $PSScriptRoot)
{
	$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
}
$userHostDir = "$PSScriptRoot\$userName\$hostName"
if (-Not (Test-Path $userHostDir))
{
    $null = New-Item -Path $userHostDir -ItemType Directory -Force
}
$timeString = (Get-Date).ToString("yyyyMMddHHmmss")
Start-Transcript -Path "$userHostDir\BackupUserData-$timeString.log" | Out-Null

#Backup Downloads
Write-Host "Downloads Backup" -ForegroundColor Cyan
$downloadsDir = "$userprofile\Downloads"
if (Test-Path $downloadsDir)
{
    if (-Not (Test-Path "$userHostDir\Downloads"))
    {
        $null = New-Item -Path "$userHostDir\Downloads" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $downloadsDir "$userHostDir\Downloads"
}
else
{
    Write-Host "  No Downloads dir found"
}

#Backup Music
Write-Host "Music Backup" -ForegroundColor Cyan
$musicDir = "$userprofile\Music"
if (Test-Path $musicDir)
{
    if (-Not (Test-Path "$userHostDir\Music"))
    {
        $null = New-Item -Path "$userHostDir\Music" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $musicDir "$userHostDir\Music"
}
else
{
    Write-Host "  No Music dir found"
}

#Backup Videos
Write-Host "Videos Backup" -ForegroundColor Cyan
$videosDir = "$userprofile\Videos"
if (Test-Path $downloadsDir)
{
    if (-Not (Test-Path "$userHostDir\Videos"))
    {
        $null = New-Item -Path "$userHostDir\Videos" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $videosDir "$userHostDir\Videos"
}
else
{
    Write-Host "  No Videos dir found"
}

if (-Not $clientHasOndeDriveBackup)
{

    #Backup Desktop
    Write-Host "Desktop Backup" -ForegroundColor Cyan
    $desktopDir = "$userprofile\Desktop"
    if (Test-Path $desktopDir)
    {
        if (-Not (Test-Path "$userHostDir\Desktop"))
        {
            $null = New-Item -Path "$userHostDir\Desktop" -ItemType Directory -Force
        }
        robocopy /mir /r:1 /w:1 /xj $desktopDir "$userHostDir\Desktop"
    }
    else
    {
        Write-Host "  No Desktop dir found"
    }

    #Backup Documents
    Write-Host "Documents Backup" -ForegroundColor Cyan
    $documentsDir = "$userprofile\Documents"
    if (Test-Path $documentsDir)
    {
        if (-Not (Test-Path "$userHostDir\Documents"))
        {
            $null = New-Item -Path "$userHostDir\Documents" -ItemType Directory -Force
        }
        robocopy /mir /r:1 /w:1 /xj $documentsDir "$userHostDir\Documents"
    }
    else
    {
        Write-Host "  No Documents dir found"
    }

    #Backup Pictures
    Write-Host "Pictures Backup" -ForegroundColor Cyan
    $picturesDir = "$userprofile\Pictures"
    if (Test-Path $picturesDir)
    {
        if (-Not (Test-Path "$userHostDir\Pictures"))
        {
            $null = New-Item -Path "$userHostDir\Pictures" -ItemType Directory -Force
        }
        robocopy /mir /r:1 /w:1 /xj $picturesDir "$userHostDir\Pictures"
    }
    else
    {
        Write-Host "  No Pictures dir found"
    }

}

#Backup Chrome
Write-Host "Chrome Backup" -ForegroundColor Cyan
$chromeDir = "$localAppData\Google\Chrome\User Data"
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
    if (-Not (Test-Path "$userHostDir\Chrome"))
    {
        $null = New-Item -Path "$userHostDir\Chrome" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $chromeDir "$userHostDir\Chrome"

    $pathToJsonFile = "$chromeDir\Default\Bookmarks"
    if (Test-Path "$pathToJsonFile")
    {
        $htmlOut = "$userHostDir\Chrome\ChromeBookmarks.html"
        $htmlHeader = @"
<!DOCTYPE NETSCAPE-Bookmark-file-1>
<!--This is an automatically generated file.
    It will be read and overwritten.
    Do Not Edit! -->
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<Title>Bookmarks</Title>
<H1>Bookmarks</H1>
<DL><p>
"@
        $htmlHeader | Out-File -FilePath $htmlOut -Force -Encoding utf8
        Function Get-BookmarkFolder
        {
            [cmdletbinding()]
            Param(
                [Parameter(Position=0,ValueFromPipeline=$True)]
                $Node
            )
            Process 
            {
                foreach ($child in $node.children) 
                {
                    $da = [math]::Round([double]$child.date_added / 1000000)
                    $dm = [math]::Round([double]$child.date_modified / 1000000)
                    if ($child.type -eq 'Folder') 
                    {
                        "    <DT><H3 FOLDED ADD_DATE=`"$($da)`">$($child.name)</H3>" | Out-File -FilePath $htmlOut -Append -Force -Encoding utf8
                        "       <DL><p>" | Out-File -FilePath $htmlOut -Append -Force -Encoding utf8
                        Get-BookmarkFolder $child
                        "       </DL><p>" | Out-File -FilePath $htmlOut -Append -Force -Encoding utf8
                    }
                    else 
                    {
                        "       <DT><a href=`"$($child.url)`" ADD_DATE=`"$($da)`">$($child.name)</a>" | Out-File -FilePath $htmlOut -Append -Encoding utf8
                    }
                }
            }
        }
        $data = Get-content $pathToJsonFile -Encoding UTF8 | out-string | ConvertFrom-Json
        $sections = $data.roots.PSObject.Properties | select -ExpandProperty name
        ForEach ($entry in $sections)
        {
            $data.roots.$entry | Get-BookmarkFolder
        }
        "</DL>" | Out-File -FilePath $htmlOut -Append -Force -Encoding utf8
    }
    else
    {
        Write-Host "  No bookmarks found to be migrated"
    }
}
else
{
    Write-Host "  No Chrome configuration found in $chromeDir"
}

#Backup Edge
Write-Host "Edge Backup" -ForegroundColor Cyan
$edgeDir = "$localAppData\Microsoft\Edge\User Data"
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
    if (-Not (Test-Path "$userHostDir\Edge"))
    {
        $null = New-Item -Path "$userHostDir\Edge" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $edgeDir "$userHostDir\Edge"
}
else
{
    Write-Host "  No Edge configuration found in $edgeDir"
}

#Backup Firefox
Write-Host "Firefox Backup" -ForegroundColor Cyan
$firefoxDir = "$appData\Mozilla\Firefox"
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
    if (-Not (Test-Path "$userHostDir\Firefox"))
    {
        $null = New-Item -Path "$userHostDir\Firefox" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $firefoxDir "$userHostDir\Firefox"
}
else
{
    Write-Host "  No Firefox configuration found in $firefoxDir"
}

#Backup Signatures
Write-Host "Outlook Signatures Backup" -ForegroundColor Cyan
$signaturesDir = "$appData\Microsoft\Signatures"
if (Test-Path $signaturesDir)
{
    if (-Not (Test-Path "$userHostDir\Microsoft\Signatures"))
    {
        $null = New-Item -Path "$userHostDir\Microsoft\Signatures" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $signaturesDir "$userHostDir\Microsoft\Signatures"
}
else
{
    Write-Host "  No signatures found in $signaturesDir"
}

#Backup Taskbar
Write-Host "Taskbar Backup" -ForegroundColor Cyan
$taskbarDir = "$appData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
if (Test-Path $taskbarDir)
{
    if (-Not (Test-Path "$userHostDir\Microsoft\TaskBar"))
    {
        $null = New-Item -Path "$userHostDir\Microsoft\TaskBar" -ItemType Directory -Force
    }
    robocopy /mir /r:1 /w:1 /xj $taskbarDir "$userHostDir\Microsoft\TaskBar"
}
else
{
    Write-Host "  No taskbar shortcuts found in $taskbarDir"
}

#Backup MRU
Write-Host "MRU Backup" -ForegroundColor Cyan
$mruTools = @("Word","Excel","PowerPoint","OneNote","Visio")
if (-Not (Test-Path "$userHostDir\Microsoft\RegistryMRU"))
{
    $null = New-Item -Path "$userHostDir\Microsoft\RegistryMRU" -ItemType Directory -Force
}
foreach($mruTool in $mruTools)
{
    Write-Host "  HKCU:\SOFTWARE\Microsoft\Office\16.0\$mruTool"
    #$mruTool = $mruTools[0]
    $regp = Get-Item "HKCU:\SOFTWARE\Microsoft\Office\16.0\$mruTool\File MRU" -ErrorAction SilentlyContinue
    if ($regp)
    {
        reg export "HKCU\SOFTWARE\Microsoft\Office\16.0\$mruTool\File MRU" "$userHostDir\Microsoft\RegistryMRU\MRU-$($mruTool)-File.reg" /y
    }
    $regp = Get-Item "HKCU:\SOFTWARE\Microsoft\Office\16.0\$mruTool\User MRU" -ErrorAction SilentlyContinue
    if ($regp)
    {
        $ids = Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Office\16.0\$mruTool\User MRU"
        foreach ($id in $ids)
        {
            reg export "HKCU\SOFTWARE\Microsoft\Office\16.0\$mruTool\User MRU" "$userHostDir\Microsoft\RegistryMRU\MRU-$($mruTool)-User-$($id.PSChildName).reg" /y
        }
    }
}

Stop-Transcript
