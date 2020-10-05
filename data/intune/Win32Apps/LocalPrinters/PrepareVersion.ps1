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

if ($version.Revision -gt -1)
{
    $version = [version]::New($version.Major,$version.Minor+1,$version.Build,$version.Revision)
}
else
{
    if ($version.Build -gt -1)
    {
        $version = [version]::New($version.Major,$version.Minor+1,$version.Build)
    }
    else
    {
        if ($version.Minor -gt -1)
        {
            $version = [version]::New($version.Major,$version.Minor+1)
        }
        else
        {
            $version = [version]::New($version.Major+1)
        }
    }
}
Write-Host "      to: $version"
$versionObj.version = $version.ToString()
$versionObj | ConvertTo-Json | Set-Content -Path $versionFile -Encoding UTF8 -Force
