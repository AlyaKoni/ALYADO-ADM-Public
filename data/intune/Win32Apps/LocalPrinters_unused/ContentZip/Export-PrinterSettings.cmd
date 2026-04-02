cd /d %~dp0
rundll32 printui.dll,PrintUIEntry /Ss /n "YourPrinterName" /a YourPrinterName.dat m f g p


UI Management Tool:
%WinDir%\System32\PrintBrmUi.exe
Export:
%WinDir%\System32\Spool\Tools\Printbrm.exe -b -f Printserverconfig.printerexport
Extract:
%WinDir%\System32\Spool\Tools\Printbrm.exe -r -d Folder -f File.printerExport
Import:
%WinDir%\System32\Spool\Tools\Printbrm.exe -r -f File.printerExport



$printer=get-ciminstance win32_printer -Filter "name like '%printername%'"
$printer
$printer | get-cimassociatedinstance 
$printer | get-cimassociatedinstance -ResultClassName Win32_PrinterDriver
$printer=get-WmiObject Win32_Printer -Filter "name like '%printername%'"
$printer
$printer | %{get-wmiobject -query ("associators of {"+$_.Path+"}")}
$printer | %{get-wmiobject -query ("associators of {"+$_.Path+"} where ResultClass=Win32_PrinterDriver")}


