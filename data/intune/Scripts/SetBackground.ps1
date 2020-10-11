$path = [Environment]::GetFolderPath("ApplicationData") + "\AlyaConsulting\Background"
if (-Not (Test-Path $path))
{
    New-Item -ItemType Directory -Force -Path $path | Out-Null
}
$localFile = "$path\DesktopBackgroundH.jpg"
Start-BitsTransfer -Source "https://alyapinfstrg001.blob.core.windows.net/images/DesktopBackgroundH.jpg" -Destination $localFile
Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name wallpaper -value $localFile
rundll32.exe user32.dll, UpdatePerUserSystemParameters
kill -n explorer
