Dism /Online /Cleanup-Image /CheckHealth
Dism /Online /Cleanup-Image /RestoreHealth
sfc /scannow

regsvr32 softpub.dll /s
regsvr32 wintrust.dll /s
regsvr32 initpki.dll /s
regsvr32 mssip32.dll /s

Get-AppxPackage -allusers Microsoft.WindowsStore | Foreach-Object {Add-AppxPackage -DisableDevelopmentMode -Register “$($_.InstallLocation)\AppXManifest.xml”}

del /s "%LOCALAPPDATA%\Packages\Microsoft.WindowsStore_8wekyb3d8bbwe\LocalState\*.*"

wsreset
