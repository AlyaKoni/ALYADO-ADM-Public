#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/Library/Logs/ch.alyaconsulting.security.localadmin.log 2>&1

echo "$(date) : starting ch.alyaconsulting.security.localadmin"

uniqueid="993"
username="AlyaAdmin"

urle () { [[ "${1}" ]] || return 1; local LANG=C i x; for (( i = 0; i < ${#1}; i++ )); do x="${1:i:1}"; [[ "${x}" == [a-zA-Z0-9.~_-] ]] && echo -n "${x}" || printf '%%%02X' "'${x}"; done; echo; }

if id $username >/dev/null 2>&1; then
        echo "Local admin already exists."
else
        echo "Local admin does not exists. Creating it now."

        password=$(cat /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9-!@#$%&*()_+' | fold -w 24 | sed 1q)
        hostname=$(hostname)

        # Example calculated password and recovery in PowerShell
        #echo -n "_$hostname-" | md5
        #PowerShell: ([System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes("_$hostname-")))).replace("-","").ToLower()

        # Send password over the internet
        #pwdurl="https://servername/api/SendPassword"
        #passworde=$(urle $password)
        #hostnamee=$(urle $hostname)
        #curl "$pwdurl?pw=$passworde&hn=$hostnamee"
        #if [[ $? != 0 ]]; then
        #    echo "Not able to send password"
        #    exit 1
        #fi

        dscl . -create /Users/$username # Creates the user
        dscl . -create /Users/$username UserShell /bin/bash # Sets Default Shell could be bash
        dscl . -create /Users/$username RealName $username # Sets Displayname for the account
        dscl . -create /Users/$username UniqueID $uniqueid #Unique Local ID
        dscl . -create /Users/$username PrimaryGroupID 20 # 20 for admin accounts 80 for standard accounts
        dscl . -create /Users/$username NFSHomeDirectory /Users/$username # Creates account home directory
        dscl . -passwd /Users/$username $password # Sets PW
        dscl . -append /Groups/admin GroupMembership $username # Adds to local admin group
        dscl . -create /Users/$username IsHidden 1 #Hides the user from the login screen

fi
 
echo "$(date) : done ch.alyaconsulting.security.localadmin"

exit 0