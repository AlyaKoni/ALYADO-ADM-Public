cd /d %~dp0AcroRdrDC_en_US

msiexec /i AcroRead.msi TRANSFORMS="AcroRead.mst" /qn /L*v installMsi.log
msiexec /update AcroRdrDCUpd2000620042.msp /qn /L*v installMsp.log

pause
