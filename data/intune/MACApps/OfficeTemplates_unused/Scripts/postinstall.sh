﻿#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/Library/Logs/ch.alyaconsulting.office.templates.postinstall.log 2>&1

echo "$(date) : post installing ch.alyaconsulting.office.templates"

echo "$(date) : done ch.alyaconsulting.office.templates.postinstall"

exit 0
