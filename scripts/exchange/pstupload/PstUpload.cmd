rem
rem Attention: Replace % with %% in SAS token!
rem
set SASToken="https://xyz.blob.core.windows.net/ingestiondata?sv=2015-04-05&sr=c&si=IngestionSasForAzCopy2021%%3D&se=2021-10-07T08%%3A30%%3A15Z"
"C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\azcopy.exe" /Source:"%~dp0" /Dest:%SASToken% /S /Y
pause
