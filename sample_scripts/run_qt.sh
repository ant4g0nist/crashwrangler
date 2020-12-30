#!/bin/sh -x

export CW_CURRENT_CASE=$1
export CW_USE_GMAL=1
export CW_LOCK_FILE="qt.tmp.lck"

if [ -f $CW_LOCK_FILE ]
then
	rm $CW_LOCK_FILE
fi

if [ -n "${CW_TIMEOUT+x}" ]; then
	echo Using timeout $CW_TIMEOUT
else
	CW_TIMEOUT=5
fi

./exc_handler "/Applications/QuickTime Player.app/Contents/MacOS/QuickTime Player" "$1" &
open -a 'quicktime player' "$1"
EXCPID=$! # get the PID for the last added background process

ruby -e "begin ; sleep $CW_TIMEOUT; Process.kill(\"USR1\", $EXCPID) if not File.exists?(\"$CW_LOCK_FILE\"); rescue; end" &

# wait for exc_handler to exit, and get exit value
wait $EXCPID
EXIT_VALUE=$?

# return exit value of exc_handler
exit $EXIT_VALUE