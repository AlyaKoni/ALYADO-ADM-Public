$rootDir = $PSScriptRoot
$dirs = Get-ChildItem -Path $rootDir -Directory
foreach ($dir in $dirs)
{
    Write-Host "Checking $($dir.Name)"
    $downloadShortcut = Get-Item -Path (Join-Path $dir.FullName "Download.url") -ErrorAction SilentlyContinue
    if ($downloadShortcut)
    {
        $content = $downloadShortcut | Get-Content -Raw -Encoding UTF8
        [regex]$regex = "URL=.*"
        $downloadUrl = [regex]::Match($content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value.Substring(4)
        $downloadUpdateScript = Get-Item -Path (Join-Path $dir.FullName "DownloadLinkUpdate.ps1") -ErrorAction SilentlyContinue
        if ($downloadUpdateScript)
        {
            & "$($downloadUpdateScript.FullName)"
            $content = $downloadShortcut | Get-Content -Raw -Encoding UTF8
            $newDownloadUrl = [regex]::Match($content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value.Substring(4)
            if ($downloadUrl -ne $newDownloadUrl)
            {
                Write-Host "  Updated"
            }
        }
    }
}
