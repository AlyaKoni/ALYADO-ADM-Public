$rootDir = $PSScriptRoot

function Remove-OneDriveItemRecursive
{
    [cmdletbinding()]
    param(
        [string] $Path
    )
    if ($Path -and (Test-Path -LiteralPath $Path))
    {
        $Items = Get-ChildItem -LiteralPath $Path -File -Recurse
        foreach ($Item in $Items)
        {
            try
            {
                $Item.Delete()
            } catch
            {
                throw "Remove-OneDriveItemRecursive - Couldn't delete $($Item.FullName), error: $($_.Exception.Message)"
            }
        }
        $Items = Get-ChildItem -LiteralPath $Path -Directory -Recurse | Sort-object -Property { $_.FullName.Length } -Descending
        foreach ($Item in $Items)
        {
            try
            {
                $Item.Delete()
            } catch
            {
                throw "Remove-OneDriveItemRecursive - Couldn't delete $($Item.FullName), error: $($_.Exception.Message)"
            }
        }
        try
        {
            (Get-Item -LiteralPath $Path).Delete()
        } catch
        {
            throw "Remove-OneDriveItemRecursive - Couldn't delete $($Path), error: $($_.Exception.Message)"
        }
    } else
    {
        Write-Warning "Remove-OneDriveItemRecursive - Path $Path doesn't exists. Skipping. "
    }
}

$dirs = Get-ChildItem -Path $rootDir -Directory
foreach ($dir in $dirs)
{
    Write-Host "Cleaning $($dir.Name)"
    if ((Test-Path (Join-Path $dir.FullName "Content")) -or (Test-Path (Join-Path $dir.FullName "Content.deleteMe")))
    {
        $tmp = Remove-OneDriveItemRecursive -Path (Join-Path $dir.FullName "Content")
    }
    # Uncomment following block, if package directory should not be cleared
    if ((Test-Path (Join-Path $dir.FullName "Package")) -or (Test-Path (Join-Path $dir.FullName "Package.deleteMe")))
    {
        $tmp = Remove-OneDriveItemRecursive -Path (Join-Path $dir.FullName "Package")
    }
    <#if ($dir.Name -eq "LocalPrinters" -or $dir.Name -eq "LocalPrinters_unused")
    {
        $zipDir = Join-Path $dir.FullName "ContentZip"
        if ((Test-Path $zipDir))
        {
            $zdirs = Get-ChildItem -Path $zipDir -Directory
            foreach ($zdir in $zdirs)
            {
                $tmp = Remove-OneDriveItemRecursive -Path $zdir.FullName
            }
        }
    }#>
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
    if ($dir.Name -eq "AcroRdrDC")
    {
        $todelPath = Join-Path $dir.FullName "version.json"
        $todelFile = Get-Item -Path $todelPath -ErrorAction SilentlyContinue
        if ($todelFile)
        {
            Remove-Item -Path $todelPath -Force
        }
    }
}
