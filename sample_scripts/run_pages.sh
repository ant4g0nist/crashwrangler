#!/bin/sh -x

export CW_CURRENT_CASE=$1
export CW_USE_GMAL=1
export CW_LOCK_FILE="pages.tmp.lck"

if [ -f $CW_LOCK_FILE ]
then
	rm $CW_LOCK_FILE
fi

if [ -n "${CW_TIMEOUT+x}" ]; then
	echo Using timeout $CW_TIMEOUT
else
	CW_TIMEOUT=6
fi

cp "$1" template.pages/index.xml
./exc_handler "/Applications/iWork '08/Pages.app/Contents/MacOS/Pages" template.pages &
EXCPID=$! # get the PID for the last added background process

ruby -e "begin ; sleep $CW_TIMEOUT; Process.kill(\"USR1\", $EXCPID) if not File.exists?(\"$CW_LOCK_FILE\"); rescue; end" &

# wait for exc_handler to exit, and get exit value
wait $EXCPID
EXIT_VALUE=$?

# return exit value of exc_handler
exit $EXIT_VALUE