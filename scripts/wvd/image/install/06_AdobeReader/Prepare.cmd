cd /d %~dp0
AcroRdrDC2000620042_en_US.exe -sfx_o"%~dp0\AcroRdrDC_en_US" -sfx_ne
cd /d %~dp0AcroRdrDC_en_US
copy ..\AcroRead.mst . /y

pause
