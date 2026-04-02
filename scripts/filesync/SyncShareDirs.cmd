rem 
rem ACHTUNG: Encoding muss OEM 850 sein !!
rem 

date /t >>%~dp0copyLog.txt

robocopy /R:10 /W:10 /MT:4 /MIR /COPYALL /DCOPY:DAT /SECFIX /TIMFIX \\server\d$\sourceDir E:\shares\DestDir 2>&1 1>>%~dp0copyLog.txt
robocopy /R:10 /W:10 /MT:4 /MIR /COPYALL /DCOPY:DAT /SECFIX /TIMFIX \\server\d$\sourceDir E:\shares\DestDir 2>&1 1>>%~dp0copyLog.txt
