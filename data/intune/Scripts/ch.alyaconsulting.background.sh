#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/Library/Logs/ch.alyaconsulting.background.log 2>&1

echo "$(date) : installing ch.alyaconsulting.background"

dekstopBackgroundUrl="https://hhaginfpstrg000.blob.core.windows.net/backgrounds/DesktopDefault.jpg"

runDir=$pwd
alyaDir="/Library/Alya"
agentsDir="/Library/LaunchAgents"
scriptsDir="/Library/Scripts"
logsDir="/Library/Alya/Logs"
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

echo "$(date) : removing old bash script version"
if [[ -f $scriptsDir/ch.alyaconsulting.background.sh ]];then
    rm -f $scriptsDir/ch.alyaconsulting.background.sh
fi

echo "$(date) : checking CommandLineTools installtion"
if ! [[ -d /Library/Developer/CommandLineTools ]]; then
    echo "CommandLineTools not found"
    tempFile="/tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress"
    touch $tempFile
    PROD=$(softwareupdate -l | grep "\*.*Command Line" | tail -n 1 | sed 's/^[^C]* //')
    if [[ -n "$PROD" ]]; then
        echo "Installing over softwareupdate '$PROD'"
        softwareupdate -i "$PROD" --verbose
        xcode-select --switch /Library/Developer/CommandLineTools
    else
        echo "NBot able to get CommandLineTools with softwareupdate"
    fi
    rm -f $tempFile
else
    echo "CommandLineTools already installed"
fi
if ! [[ -d /Library/Developer/CommandLineTools ]]; then
    echo "CommandLineTools still not found"
    echo "Installing over xcode-select"
    xcode-select --install
    sleep 1
    # TODO access needed? inject with pfile? Accessibility > sshd-keygen-wrapper
    # /usr/libexec/sshd-keygen-wrapper, PPPC Utility
    osascript <<EOD
tell application "System Events"
    tell process "Install Command Line Developer Tools"
    keystroke return
    click button "Agree" of window "License Agreement"
    end tell
end tell
EOD
fi
toolsPath=$(xcode-select -p)
echo "$(date) : command line tools: $toolsPath"

echo "$(date) : fixing modulemap if required"
if [[ -f /Library/Developer/CommandLineTools/usr/include/swift/module.modulemap ]]; then
	osv=`sw_vers --productVersion | awk -F'[^0-9]+' '{ print $1 }'`
	if [[ $osv -ge 15 ]]; then
		echo "$(date) : implementing swift fix for 15 and higher"
		mv /Library/Developer/CommandLineTools/usr/include/swift/module.modulemap /Library/Developer/CommandLineTools/usr/include/swift/module.modulemap.orig
	fi
fi

echo "$(date) : creating apply script"
cat > /tmp/ch.alyaconsulting.background.tmp <<- EOF
#!/usr/bin/swift
import Foundation
import AppKit
let date = Date()
let uuid = UUID().uuidString
var msg = ""
let logFile = URL(string: "file:///Library/Alya/Logs/ch.alyaconsulting.background-\(uuid).log")
msg = "\(Date()) : running ch.alyaconsulting.background"
print( msg )
do { try msg.write(to: logFile!, atomically: true, encoding: String.Encoding.utf8) } catch {}
let ws = NSWorkspace.shared
let uri = URL(string: "file:///Library/Alya/Backgrounds/DesktopDefaultHHAG.jpg")
for _ in 1...10 {
    for screen in NSScreen.screens {
        let actUrl = ws.desktopImageURL(for: screen)
        if (actUrl?.path != uri?.path) {
            msg = "Screen \(screen) setting background to \(uri!.path)"
            print( msg )
            do { try msg.write(to: logFile!, atomically: true, encoding: String.Encoding.utf8) } catch {}
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
msg = "\(Date()) : done ch.alyaconsulting.background"
print( msg )
do { try msg.write(to: logFile!, atomically: true, encoding: String.Encoding.utf8) } catch {}
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
