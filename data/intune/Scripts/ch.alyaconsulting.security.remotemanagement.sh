#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/Library/Logs/ch.alyaconsulting.security.remotemanagement.log 2>&1

echo "$(date) : starting ch.alyaconsulting.security.remotemanagement"

/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop
echo "$(date) : Remote Management will be fully disabled after reboot or is already disabled. Closing script..."

echo "$(date) : done ch.alyaconsulting.security.remotemanagement"

exit 0