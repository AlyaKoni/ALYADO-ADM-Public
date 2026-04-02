#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/Library/Logs/ch.alyaconsulting.security.remotelogin.log 2>&1

echo "$(date) : starting ch.alyaconsulting.security.remotelogin"

echo Yes | /usr/sbin/systemsetup -setremotelogin off
echo ""
echo "$(date) : Remote Login is now disabled or already disabled. Closing script..."

echo "$(date) : done ch.alyaconsulting.security.remotelogin"

exit 0