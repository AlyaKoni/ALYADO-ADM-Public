Write-Host "    Preparing version"
$packageRoot = "$PSScriptRoot"
$versionFile = Join-Path $packageRoot "version.json"
if ((Test-Path $versionFile))
{
    $versionObj = Get-Content -Path $versionFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $version = [Version]$versionObj.version
}
else
{
    $versionObj = @{}
    $versionObj.version = "1.0"
    $version = [Version]$versionObj.version
}
Write-Host "      actual: $version"

$camStudioRoot = "C:\Program Files\CamStudio 2.7"
$recorderExe = Join-Path $camStudioRoot "Recorder.exe"
$exeFile = Get-Item -Path $recorderExe -ErrorAction SilentlyContinue
if ($exeFile)
{
    $version = [Version]$exeFile.VersionInfo.FileVersion
}
else
{
    throw "Can't find CamStudio Recorder '$($recorderExe)' to check actual version"
}

Write-Host "      new: $version"
$versionObj.version = $version.ToString()
$versionObj | ConvertTo-Json | Set-Content -Path $versionFile -Encoding UTF8 -Force
