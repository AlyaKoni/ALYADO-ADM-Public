cd /d %~dp0

.\FSLogixAppsSetup.exe /allusers /quiet

pause

set fslogixRoot=C:\Program Files\FSLogix\Apps
copy /y "%fslogixRoot%\frxtray.exe" "%AllUsersProfile%\Start Menu\Programs\Startup"
net localgroup "FSLogix ODFC Exclude List" %USERNAME% /add
net localgroup "FSLogix Profile Exclude List" %USERNAME% /add

pause
