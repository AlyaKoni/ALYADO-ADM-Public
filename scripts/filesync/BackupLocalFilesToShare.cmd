set BackupDrive=P:
set BackupPath=P:\
set MountPath=\\srv-zdc-001\user-homes\%USERNAME%

@echo off
:Restart
set hadError=0
if not exist %BackupPath% goto :TryP
if not exist %BackupPath%Backup_%COMPUTERNAME% mkdir %BackupPath%Backup_%COMPUTERNAME%

if exist "%HOMEDRIVE%%HOMEPATH%\Documents" goto :EN
goto :DE

:EN
call :CopyDir Desktop
call :CopyDir Documents
call :CopyDir Music
call :CopyDir Pictures
call :CopyDir Videos
call :CopyDir Favorites
call :CopyDir Links
if %hadError% == 1 goto :EOF
echo.
echo.
echo Ihre Daten wurden erfolgreich in folgendes Verzeichnis gesichert:
echo %BackupPath%Backup_%COMPUTERNAME%
echo.
echo.
goto :EOF

:DE
call :CopyDir Desktop
call :CopyDir Dokumente
call :CopyDir Musik
call :CopyDir Bilder
call :CopyDir Videos
call :CopyDir Favoriten
call :CopyDir Links
if %hadError% == 1 goto :EOF
echo.
echo.
echo Ihre Daten wurden erfolgreich in folgendes Verzeichnis gesichert:
echo %BackupPath%Backup_%COMPUTERNAME%
echo.
echo.
goto :EOF


:CopyDir
set actDir=%1
echo.
echo ==============================================
echo Kopiere lokales Verzeichnis %actDir%
if not exist "%BackupPath%Backup_%COMPUTERNAME%\%actDir%" mkdir "%BackupPath%Backup_%COMPUTERNAME%\%actDir%"
robocopy /R:10 /W:10 /MT:4 /MIR /COPYALL /DCOPY:DAT /SECFIX /TIMFIX /XJ "%HOMEDRIVE%%HOMEPATH%\%actDir%" "%BackupPath%Backup_%COMPUTERNAME%\%actDir%"
if errorlevel 4 call :CopyError
goto :EOF

:TryP
echo Verknuepfe Laufwerk %BackupDrive%
net use %BackupDrive% %MountPath%
if not exist %BackupPath% goto :NoP
goto :Restart
goto :EOF

:NoP
echo.
echo Fehler:
echo   Bei Ihnen fehlt das Laufwerk %BackupPath%
echo   Bitte kontaktieren Sie per E-Mail:
echo     konrad.brunner@alayaconsulting.ch
echo.
echo.
pause
goto :EOF

:CopyError
set hadError=1
echo.
echo Fehler:
echo   Fehler beim kopieren des Verzeichnisses: %actDir%
echo   Bitte beenden Sie alle laufenden Applikationen
echo      und versuchen Sie es noch einmal
echo   Wenn dies nicht hilft, starten Sie den Rechner neu
echo      und versuchen Sie es noch einmal bevor Sie eine Applikation starten
echo   Falls das Problem bestehen bleibt, kontaktieren Sie bitte per E-Mail:
echo     konrad.brunner@alayaconsulting.ch
echo.
echo.
pause
goto :EOF
