$ftpUrl = "ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC"
Write-Host "    Downloading files from $ftpUrl"

$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "Content"
if (-Not (Test-Path $contentRoot))
{
    $tmp = New-Item -Path $contentRoot -ItemType Directory -Force
}

$FTPRequest = [System.Net.FtpWebRequest]::Create($ftpUrl)
$FTPRequest.Method = [System.Net.WebRequestMethods+FTP]::ListDirectoryDetails
$FTPRequest.UseBinary = $False
$FTPRequest.KeepAlive = $False
$FTPResponse = $FTPRequest.GetResponse()
$ResponseStream = $FTPResponse.GetResponseStream()
$StreamReader = New-Object System.IO.Streamreader $ResponseStream
$DirListing = (($StreamReader.ReadToEnd()) -split [Environment]::NewLine)
$StreamReader.Close()
#$DirListing = $DirListing[2..($DirListing.Length-2)]
$FTPResponse.Close()
$parentDirs = @()
foreach ($CurLine in $DirListing)
{
    $LineTok = ($CurLine -split '\ +')
    $CurDir = $LineTok[8..($LineTok.Length-1)]
    $DirBool = $LineTok[0].StartsWith("d")
    If ($DirBool)
    {
        $parentDirs += $CurDir
    }
}
$parentDirs = $parentDirs | Sort-Object -Descending
$lastExeDir = $null
$lastExeFile = $null
$lastPatchDir = $null
$lastPatchFile = $null
foreach ($CurDir in $parentDirs)
{
    Write-Host "    Searching dir $CurDir"
    $attempts = 10
    while ($attempts -ge 0)
    {
        try {
            do {
                try {
                    $FTPRequest = [System.Net.FtpWebRequest]::Create("$ftpUrl/$CurDir")
                    $FTPRequest.Method = [System.Net.WebRequestMethods+FTP]::ListDirectoryDetails
                    $FTPRequest.UseBinary = $False
                    $FTPRequest.KeepAlive = $False
                    $FTPResponse = $FTPRequest.GetResponse()
                    $ResponseStream = $FTPResponse.GetResponseStream()
                    $StreamReader = New-Object System.IO.Streamreader $ResponseStream
                    $SubListing = (($StreamReader.ReadToEnd()) -split [Environment]::NewLine)
                    $StreamReader.Close()
                    $FTPResponse.Close()
                } catch {
                    $StatusCode = $_.Exception.Response.StatusCode.value__
                    if ($StatusCode -eq 429) {
                        Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                        Start-Sleep -Seconds 45
                    }
                    else {
                        try { Write-Host ($_.Exception | ConvertTo-Json -Depth 3) -ForegroundColor $CommandError } catch {}
						Write-Host ($_.Exception) -ForegroundColor $CommandError
                        throw
                    }
                }
            } while ($StatusCode -eq 429)
            $attempts = -1
        } catch {
            Write-Host "Catched exception $($_.Exception.Message)" -ForegroundColor $CommandError
            Write-Host "Retrying $attempts times" -ForegroundColor $CommandError
            $attempts--
            if ($attempts -lt 0) { throw }
            Start-Sleep -Seconds 10
        }
    }
    foreach ($CurLine in $SubListing)
    {
        $LineTok = ($CurLine -split '\ +')
        $CurFile = $LineTok[$LineTok.Length-1]
        $DirBool = $LineTok[0].StartsWith("d")
        if (-Not $lastExeDir -and $CurFile.Contains("MUI.exe"))
        {
            Write-Host "    Found exe in $CurDir/$CurFile"
            $lastExeDir = $CurDir
            $lastExeFile = $CurFile
            if ($lastPatchDir) { break }
        }
        if (-Not $lastPatchDir -and $CurFile.Contains("MUI.msp"))
        {
            Write-Host "    Found patch in $CurDir/$CurFile"
            $lastPatchDir = $CurDir
            $lastPatchFile = $CurFile
            if ($lastExeDir) { break }
        }
    }
}

if (-Not (Test-Path (Join-Path $contentRoot $lastExeFile)))
{
    Write-Host "    Downloading $ftpUrl/$lastExeDir/$lastExeFile"
    $attempts = 10
    while ($attempts -ge 0)
    {
        $attempts = 10
        try {
            do {
                try {
                    $webclient = New-Object System.Net.WebClient
                    $webclient.DownloadFile("$ftpUrl/$lastExeDir/$lastExeFile", (Join-Path $contentRoot $lastExeFile))
                } catch {
                    $StatusCode = $_.Exception.Response.StatusCode.value__
                    if ($StatusCode -eq 429) {
                        Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                        Start-Sleep -Seconds 45
                    }
                    else {
                        try { Write-Host ($_.Exception | ConvertTo-Json -Depth 3) -ForegroundColor $CommandError } catch {}
						Write-Host ($_.Exception) -ForegroundColor $CommandError
                        throw
                    }
                }
            } while ($StatusCode -eq 429)
            $attempts = -1
        } catch {
            Write-Host "Catched exception $($_.Exception.Message)" -ForegroundColor $CommandError
            Write-Host "Retrying $attempts times" -ForegroundColor $CommandError
            $attempts--
            if ($attempts -lt 0) { throw }
            Start-Sleep -Seconds 10
        }
    }
}
if (-Not (Test-Path (Join-Path $contentRoot $lastPatchFile)))
{
    Write-Host "    Downloading $ftpUrl/$lastPatchDir/$lastPatchFile"
    $attempts = 10
    while ($attempts -ge 0)
    {
        try {
            do {
                try {
                    $webclient = New-Object System.Net.WebClient
                    $webclient.DownloadFile("$ftpUrl/$lastPatchDir/$lastPatchFile", (Join-Path $contentRoot $lastPatchFile))
                } catch {
                    $StatusCode = $_.Exception.Response.StatusCode.value__
                    if ($StatusCode -eq 429) {
                        Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                        Start-Sleep -Seconds 45
                    }
                    else {
                        try { Write-Host ($_.Exception | ConvertTo-Json -Depth 3) -ForegroundColor $CommandError } catch {}
						Write-Host ($_.Exception) -ForegroundColor $CommandError
                        throw
                    }
                }
            } while ($StatusCode -eq 429)
            $attempts = -1
        } catch {
            Write-Host "Catched exception $($_.Exception.Message)" -ForegroundColor $CommandError
            Write-Host "Retrying $attempts times" -ForegroundColor $CommandError
            $attempts--
            if ($attempts -lt 0) { throw }
            Start-Sleep -Seconds 10
        }
    }
}

$tmpPath = (Join-Path $contentRoot "Tmp")
& "$(Join-Path $contentRoot $lastExeFile)" -sfx_o"$tmpPath" -sfx_ne
do
{
    Start-Sleep -Seconds 5
    $process = Get-Process -Name $lastExeFile.Replace(".exe","") -ErrorAction SilentlyContinue

} while ($process)
Move-Item -Path (Join-Path $tmpPath "AcroRead.msi") -Destination $contentRoot -Force
Move-Item -Path (Join-Path $tmpPath "Data1.cab") -Destination $contentRoot -Force
Remove-Item -Path $tmpPath -Recurse -Force
Remove-Item -Path (Join-Path $contentRoot $lastExeFile) -Force
