rem
rem Attention: Replace % with %% in SAS token!
rem
set SASToken="https://Any"
"C:\PathToAzCopy\azcopy_windows_amd64_10.14.1\azcopy.exe" copy "%~dp0*" %SASToken%
pause
