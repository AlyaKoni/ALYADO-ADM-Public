echo Make sure windows search service is running
pause

cd /d %~dp0
.\Setup.exe /configure "office_wvd_deploy_config.xml"
