$rootDir = $PSScriptRoot
$dirs = Get-ChildItem -Path $rootDir -Directory
foreach ($dir in $dirs)
{
    Write-Host "Cleaning $($dir.Name)"
    if ((Test-Path (Join-Path $dir.FullName "Content")))
    {
        $tmp = Remove-Item -Path (Join-Path $dir.FullName "Content") -Recurse -Force
    }
    # Uncomment following block, if package directory should not be cleared
    if ((Test-Path (Join-Path $dir.FullName "Package")))
    {
        $tmp = Remove-Item -Path (Join-Path $dir.FullName "Package") -Recurse -Force
    }
    if ((Test-Path (Join-Path $dir.FullName "version.json")))
    {
        $tmp = Remove-Item -Path (Join-Path $dir.FullName "version.json") -Force
    }
    if ($dir.Name -eq "LocalPrinters")
    {
        $zipDir = Join-Path $dir.FullName "ContentZip"
        $zdirs = Get-ChildItem -Path $zipDir -Directory
        foreach ($zdir in $zdirs)
        {
            $tmp = Remove-Item -Path $zdir.FullName -Recurse -Force
        }
    }
    if ($dir.Name -eq "AzInfoProtection")
    {
        $scriptDir = Join-Path $dir.FullName "Scripts"
        $todelPath = Join-Path $scriptDir "ServiceLocation.txt"
        $todelFile = Get-Item -Path $todelPath -ErrorAction SilentlyContinue
        if ($todelFile)
        {
            Remove-Item -Path $todelPath -Force
        }
    }
}
