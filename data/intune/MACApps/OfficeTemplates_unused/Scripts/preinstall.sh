#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/Library/Logs/ch.alyaconsulting.office.templates.preinstall.log 2>&1

echo "$(date) : pre installing ch.alyaconsulting.office.templates"

echo "$(date) : preparing directories"
installDir="/Library/Application Support/Microsoft"
[ -d "$installDir" ] || mkdir "$installDir"
chmod 755 "$installDir"
[ -d "$installDir/Office365" ] || mkdir "$installDir/Office365"
chmod 755 "$installDir/Office365"
[ -d "$installDir/Office365/User Content.localized" ] || mkdir "$installDir/Office365/User Content.localized"
chmod 755 "$installDir/Office365/User Content.localized"
[ -d "$installDir/Office365/User Content.localized/Templates.localized" ] || mkdir "$installDir/Office365/User Content.localized/Templates.localized"
chmod 755 "$installDir/Office365/User Content.localized/Templates.localized"

echo "$(date) : done ch.alyaconsulting.office.templates.preinstall"

exit 0
