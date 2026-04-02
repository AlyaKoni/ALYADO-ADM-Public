#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/Library/Logs/ch.alyaconsulting.security.homefolder.log 2>&1

echo "$(date) : starting ch.alyaconsulting.security.homefolder"

IFS=$'\n'
for userDirs in $( /usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d ! \( -perm 700 -o -perm 711 \) | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest" ); do
    /bin/chmod og-rwx "$userDirs"
done
unset IFS
echo  "$(date) : User's Home Folders are now secured or already secured. Closing script..."
 
echo "$(date) : done ch.alyaconsulting.security.homefolder"

exit 0