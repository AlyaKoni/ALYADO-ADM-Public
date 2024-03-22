#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/Library/Logs/ch.alyaconsulting.customattribute.cputype.log 2>&1

echo "$(date) : starting ch.alyaconsulting.customattribute.cputype"

processor=$(/usr/sbin/sysctl -n machdep.cpu.brand_string)
echo $processor >&3

echo "$(date) : done ch.alyaconsulting.customattribute.cputype"

exit 0