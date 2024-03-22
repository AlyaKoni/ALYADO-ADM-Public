#!/bin/bash
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>>/Library/Logs/ch.alyaconsulting.customattribute.defenderrunning.log 2>&1

echo "$(date) : starting ch.alyaconsulting.customattribute.defenderrunning"

processes=( "wdavdaemon_enterprise"
            "wdavdaemon_unprivileged"
            "wdavdaemon")

for proc in "${processes[@]}"; do
    if ! pgrep -x "$proc" >/dev/null; then
        echo "$(date) | [$proc] is not running"
        let missingProcCount=$missingProcCount+1
    fi
done

if [[ $missingProcCount -gt 0 ]]; then
    echo "Defender missing [$missingProcCount] processes" >&3
else
    echo "Defender running" >&3
fi

echo "$(date) : done ch.alyaconsulting.customattribute.defenderrunning"

exit 0