#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/Library/Logs/ch.alyaconsulting.office.outlookfont.log 2>&1

echo "$(date) : installing ch.alyaconsulting.office.outlookfont"

defFont="Arial"
defSize="11.0pt"
defColor="black"

runDir=$pwd
alyaDir="/Library/Alya"
agentsDir="/Library/LaunchAgents"
scriptsDir="/Library/Scripts"
logsDir="/Library/Logs/Alya"
officeOutlookFontDir="$alyaDir/OfficeOutlookFont"
officeOutlookFontUrl="https://raw.githubusercontent.com/pbowden-msft/OutlookFontPoke/master"
officeOutlookFontReg="$officeOutlookFontUrl/OutlookFontPoke"
officeOutlookFontScript="$officeOutlookFontUrl/TemplateRegDB.reg"

echo "$(date) : preparing directories"
[ -d $alyaDir ] || mkdir $alyaDir
chmod 755 $alyaDir
[ -d $officeOutlookFontDir ] || mkdir $officeOutlookFontDir
chmod 755 $officeOutlookFontDir
[ -d $logsDir ] || mkdir $logsDir
chmod 777 $logsDir

echo "$(date) : downloading OutlookFontPoke"
cd $officeOutlookFontDir
curl -O $officeOutlookFontReg
curl -O $officeOutlookFontScript
chmod 755 "OutlookFontPoke"
cd $runDir

echo "$(date) : creating apply script"
cat > /tmp/ch.alyaconsulting.office.outlookfont.tmp <<- EOF
#!/bin/bash
# send command to OutlookFontPoke by Paul Bowden https://github.com/pbowden-msft/OutlookFontPoke
echo "\$(date) : running ch.alyaconsulting.office.outlookfont"
loggedInUser=\$( scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ { print \$3 }' )
#echo "loggedInUser : \$loggedInUser"
#echo "whoami : \$(whoami)"
#su \$loggedInUser -c "cd $officeOutlookFontDir && ./OutlookFontPoke '$defFont' '$defSize' '$defColor'"
sudo -u \$loggedInUser bash -c "cd $officeOutlookFontDir && ./OutlookFontPoke '$defFont' '$defSize' '$defColor'"
echo "\$(date) : done ch.alyaconsulting.office.outlookfont"
EOF

if ! cmp -s "/tmp/ch.alyaconsulting.office.outlookfont.tmp" "$scriptsDir/ch.alyaconsulting.office.outlookfont.sh"; then
    cp "/tmp/ch.alyaconsulting.office.outlookfont.tmp" "$scriptsDir/ch.alyaconsulting.office.outlookfont.sh"
fi
chmod 755 $scriptsDir/ch.alyaconsulting.office.outlookfont.sh
xattr -d com.apple.provenance $scriptsDir/ch.alyaconsulting.office.outlookfont.sh
xattr -d com.apple.quarantine $scriptsDir/ch.alyaconsulting.office.outlookfont.sh
rm -f /tmp/ch.alyaconsulting.office.outlookfont.tmp

echo "$(date) : creating login agent"
cat > /tmp/ch.alyaconsulting.office.outlookfont.plist <<- EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" http://www.apple.com/DTDs/PropertyList-1.0.dtd>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ch.alyaconsulting.office.outlookfont</string>
    <key>Program</key>
    <string>$scriptsDir/ch.alyaconsulting.office.outlookfont.sh</string>
    <key>ProgramArguments</key>
    <array/>
    <key>WorkingDirectory</key>
    <string>$logsDir</string>
    <key>StandardOutPath</key>
    <string>$logsDir/ch.alyaconsulting.office.outlookfont.stdout</string>
    <key>StandardErrorPath</key>
    <string>$logsDir/ch.alyaconsulting.office.outlookfont.stderr</string>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>5</integer>
    <key>Nicer</key>
    <integer>1</integer>
</dict>
</plist>
EOF

if ! cmp -s "/tmp/ch.alyaconsulting.office.outlookfont.plist" "$agentsDir/ch.alyaconsulting.office.outlookfont.plist"; then
    cp "/tmp/ch.alyaconsulting.office.outlookfont.plist" "$agentsDir/ch.alyaconsulting.office.outlookfont.plist"
fi
chmod 644 $agentsDir/ch.alyaconsulting.office.outlookfont.plist
xattr -d com.apple.provenance $agentsDir/ch.alyaconsulting.office.outlookfont.plist
xattr -d com.apple.quarantine $agentsDir/ch.alyaconsulting.office.outlookfont.plist
rm -f /tmp/ch.alyaconsulting.office.outlookfont.plist

echo "$(date) : loading plist file"
launchctl load $agentsDir/ch.alyaconsulting.office.outlookfont.plist

echo "$(date) : starting plist file"
launchctl start $agentsDir/ch.alyaconsulting.office.outlookfont.plist

echo "$(date) : done ch.alyaconsulting.office.outlookfont"

exit 0
