md %appdata%\microsoft\signatures\
del %appdata%\microsoft\signatures\*.* /y
copy \\server\sigs\%USERNAME%.htm %appdata%\microsoft\signatures /y
REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail\ /v EditorPreference /t REG_DWORD /d 131072 /f
REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Common\MailSettings\ /v NewSignature /t REG_EXPAND_SZ /d %USERNAME% /f
REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\14.0\Common\MailSettings\ /v NewSignature /t REG_EXPAND_SZ /d %USERNAME% /f
REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Common\MailSettings\ /v ReplySignature /t REG_EXPAND_SZ /d %USERNAME% /f
REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\14.0\Common\MailSettings\ /v ReplySignature /t REG_EXPAND_SZ /d %USERNAME% /f
