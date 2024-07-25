#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/Library/Logs/ch.alyaconsulting.background.log 2>&1

echo "$(date) : installing ch.alyaconsulting.background"

dekstopBackgroundUrl="https://alyainfpstrg001.blob.core.windows.net/corporate/backgrounds/Hintergrund_3000_2000.jpg"

runDir=$pwd
alyaDir="/Library/Alya"
agentsDir="/Library/LaunchAgents"
scriptsDir="/Library/Scripts"
logsDir="/Library/Logs/Alya"
backgroundsDir="$alyaDir/Backgrounds"
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

if [[ -f $scriptsDir/ch.alyaconsulting.background.sh ]];then
    rm -f $scriptsDir/ch.alyaconsulting.background.sh
fi

echo "$(date) : creating apply script"
cat > /tmp/ch.alyaconsulting.background.tmp <<- EOF
#!/usr/bin/swift
import Foundation
import AppKit
let date = Date()
print( "\(Date()) : running ch.alyaconsulting.background")
let ws = NSWorkspace.shared
let uri = URL(string: "file://$backgroundsDir/$dekstopBackgroundName")
for _ in 1...10 {
    for screen in NSScreen.screens {
        let actUrl = ws.desktopImageURL(for: screen)
        if (actUrl?.path != uri?.path) {
            print( "Screen \(screen) setting background to \(uri!.path)")
            guard var options = ws.desktopImageOptions(for: screen) else {
                try! ws.setDesktopImageURL(uri!, for: screen)
                continue
            }
            //options[.imageScaling] = NSNumber(value: NSImageScaling.scaleAxesIndependently.rawValue) // fill
            options[.imageScaling] = NSNumber(value: NSImageScaling.scaleProportionallyUpOrDown.rawValue) // fit
            //options[.imageScaling] = NSNumber(value: NSImageScaling.scaleNone.rawValue) // center
            options[.allowClipping] = true
            try! ws.setDesktopImageURL(uri!, for: screen, options: options)
        }
    }
    sleep(30)
}
print( "\(Date()) : done ch.alyaconsulting.background")
EOF

if ! cmp -s "/tmp/ch.alyaconsulting.background.tmp" "$scriptsDir/ch.alyaconsulting.background.swift"; then
    cp "/tmp/ch.alyaconsulting.background.tmp" "$scriptsDir/ch.alyaconsulting.background.swift"
fi
chmod 755 $scriptsDir/ch.alyaconsulting.background.swift
xattr -d com.apple.provenance $scriptsDir/ch.alyaconsulting.background.swift
xattr -d com.apple.quarantine $scriptsDir/ch.alyaconsulting.background.swift
rm -f /tmp/ch.alyaconsulting.background.tmp

echo "$(date) : creating login agent"
cat > /tmp/ch.alyaconsulting.background.plist <<- EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" http://www.apple.com/DTDs/PropertyList-1.0.dtd>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ch.alyaconsulting.background</string>
    <key>Program</key>
    <string>$scriptsDir/ch.alyaconsulting.background.swift</string>
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

if ! cmp -s "/tmp/ch.alyaconsulting.background.plist" "$agentsDir/ch.alyaconsulting.background.plist"; then
    cp "/tmp/ch.alyaconsulting.background.plist" "$agentsDir/ch.alyaconsulting.background.plist"
fi
chmod 644 $agentsDir/ch.alyaconsulting.background.plist
xattr -d com.apple.provenance $agentsDir/ch.alyaconsulting.background.plist
xattr -d com.apple.quarantine $agentsDir/ch.alyaconsulting.background.plist
rm -f /tmp/ch.alyaconsulting.background.plist

echo "$(date) : loading plist file"
launchctl load $agentsDir/ch.alyaconsulting.background.plist

echo "$(date) : starting plist file"
launchctl start $agentsDir/ch.alyaconsulting.background.plist

echo "$(date) : done ch.alyaconsulting.background"

exit 0
