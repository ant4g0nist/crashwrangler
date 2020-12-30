#!/bin/sh -x

export CW_CURRENT_CASE=$1
export CW_USE_GMAL=1
export CW_LOCK_FILE=dmg.tmp.lck

./exc_handler hdiutil attach -drivekey auto-fsck=NO "$1"
sleep 1
#fsck -y /dev/disk2s1

for ((i=2;i<=10;i+=1)); do
	hdiutil detach /dev/disk$i
done
sync
