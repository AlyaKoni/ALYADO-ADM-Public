takeown /f C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC /r /d y
icacls C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC /grant administrators:F /t
start C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC
echo Please delete all fodlers
pause
