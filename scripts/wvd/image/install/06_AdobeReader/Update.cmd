cd /d %~dp0AcroRdrDC_en_US

msiexec /update AcroRdrDCUpd2000920065.msp /qn /L*v installMsp.log
msiexec /update AcroRdrDCUpd2000920065_MUI.msp /qn /L*v installMsp_MUI.log

pause
