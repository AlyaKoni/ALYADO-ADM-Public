rem Run OOBE Setup up to the network connection
rem Press Shift+F10
rem Enter following command in DOS prompt
OOBE\BYPASSNRO
rem After the reboot choose "I don't have internet in the network dialog"

rem Alternative option:
rem reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v BypassNRO /t REG_DWORD /d 1 /f
rem shutdown /r /t 0
