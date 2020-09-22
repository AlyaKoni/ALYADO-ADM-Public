echo Make sure windows search service is running
pause

cd /d %~dp0
.\Setup.exe /configure "configuration-ledermann-wvd.xml"
