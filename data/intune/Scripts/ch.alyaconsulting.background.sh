#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/Library/Logs/ch.alyaconsulting.background.log 2>&1

echo "$(date) : installing ch.alyaconsulting.background"

runDir=$pwd
alyaDir="/Library/Alya"
agentsDir="/Library/LaunchAgents"
scriptsDir="/Library/Scripts"
logsDir="/Library/Logs/Alya"
backgroundsDir="$alyaDir/Backgrounds"
dekstopBackgroundUrl=https://alyainfpstrg001.blob.core.windows.net/corporate/backgrounds/Hintergrund_3000_2000.jpg
dekstopBackgroundName=$(basename $dekstopBackgroundUrl)

echo "$(date) : preparing directories"
[ -d $alyaDir ] || mkdir $alyaDir
chmod 755 $alyaDir
[ -d $backgroundsDir ] || mkdir $backgroundsDir
chmod 755 $backgroundsDir
[ -d $logsDir ] || mkdir $logsDir
chmod 777 $logsDir

echo "$(date) : downloading background image"
cd $backgroundsDir
curl -O $dekstopBackgroundUrl
cd $runDir

echo "$(date) : creating apply script"
cat > $scriptsDir/ch.alyaconsulting.background.sh <<- EOF
#!/bin/bash
echo "\$(date) : running ch.alyaconsulting.background"
dekstopBackground="$backgroundsDir/$dekstopBackgroundName"
osascript -e 'tell application "System Events" to tell every desktop to set picture to "'"\$dekstopBackground"'"'
#killall Dock
echo "\$(date) : done ch.alyaconsulting.background"
EOF
chmod 755 $scriptsDir/ch.alyaconsulting.background.sh
xattr -d com.apple.provenance $scriptsDir/ch.alyaconsulting.background.sh

echo "$(date) : creating login agent"
cat > $agentsDir/ch.alyaconsulting.background.plist <<- EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" http://www.apple.com/DTDs/PropertyList-1.0.dtd>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ch.alyaconsulting.background</string>
    <key>Program</key>
    <string>$scriptsDir/ch.alyaconsulting.background.sh</string>
    <key>ProgramArguments</key>
    <array/>
    <key>WorkingDirectory</key>
    <string>$logsDir</string>
    <key>StandardOutPath</key>
    <string>$logsDir/ch.alyaconsulting.background.stdout</string>
    <key>StandardErrorPath</key>
    <string>$logsDir/ch.alyaconsulting.background.stderr</string>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>0</integer>
    <key>Nicer</key>
    <integer>1</integer>
</dict>
</plist>
EOF
chmod 644 $agentsDir/ch.alyaconsulting.background.plist
xattr -d com.apple.provenance $agentsDir/ch.alyaconsulting.background.plist

echo "$(date) : loading plist file"
launchctl load $agentsDir/ch.alyaconsulting.background.plist

echo "$(date) : ltarting plist file"
launchctl start $agentsDir/ch.alyaconsulting.background.plist

echo "$(date) : done ch.alyaconsulting.background"

exit 0