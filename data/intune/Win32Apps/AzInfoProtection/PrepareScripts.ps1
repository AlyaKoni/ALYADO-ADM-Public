. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1
if (-Not $AlyaAipApiServiceLocation -or $AlyaAipApiServiceLocation -eq "PleaseSpecify" -or [string]::IsNullOrEmpty($AlyaAipApiServiceLocation))
{
    . $PSScriptRoot\..\..\..\..\scripts\aip\Get-AIPServiceLocation.ps1
    Write-Warning "To get rid of the login screen, specify following service location in the variable AlyaAipApiServiceLocation in the script data\ConfigureEnv.ps1"
    $serviceLocation
}
else
{
    $serviceLocation = $AlyaAipApiServiceLocation
}
if (-Not $serviceLocation -or $serviceLocation -eq "PleaseSpecify" -or [string]::IsNullOrEmpty($serviceLocation))
{
    throw "Can't find the service location of your aip service"
}
$serviceLocation | Set-Content -Path "$PSScriptRoot\Scripts\ServiceLocation.txt"
