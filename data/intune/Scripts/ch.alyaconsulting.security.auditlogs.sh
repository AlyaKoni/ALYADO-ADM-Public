#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/Library/Logs/ch.alyaconsulting.security.auditlogs.log 2>&1

echo "$(date) : starting ch.alyaconsulting.security.auditlogs"

if [[ ! -e /etc/security/audit_control ]] && [[ -e /etc/security/audit_control.example ]];then
  /bin/cp /etc/security/audit_control.example /etc/security/audit_control
fi

/bin/launchctl enable system/com.apple.auditd
/bin/launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.auditd.plist
/usr/sbin/audit -i
echo  "$(date) : Security Auditing is enabled for devices running macOS Sonoma. Continuing..."
 
/usr/sbin/chown -R root:wheel /etc/security/audit_control
/bin/chmod -R o-rw /etc/security/audit_control
/usr/sbin/chown -R root:wheel /var/audit/
/bin/chmod -R o-rw /var/audit/
echo  "$(date) : Access to audit records is now controlled or already controlled. Closing script..."

echo "$(date) : done ch.alyaconsulting.security.auditlogs"

exit 0