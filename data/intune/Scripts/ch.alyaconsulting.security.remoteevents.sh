#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/Library/Logs/ch.alyaconsulting.security.remoteevents.log 2>&1

echo "$(date) : starting ch.alyaconsulting.security.remoteevents"

/usr/sbin/systemsetup -setremoteappleevents off 2> /dev/null
echo "$(date) : Remote Apple Events is now disabled or already disabled. Closing script..."

echo "$(date) : done ch.alyaconsulting.security.remoteevents"

exit 0