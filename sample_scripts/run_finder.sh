#!/bin/sh -x

export CW_CURRENT_CASE=$1

#This script is for fuzzing .DS_Store files

#make sure Finder doesn't get autorestarted when it quits or dies.
#defaults write com.apple.finder QuitMenuItem YES
#defaults write com.apple.loginwindow Finder /Applications/Utilities/Terminal.app

export CW_USE_GMAL=1
export CW_LOCK_FILE=finder.tmp.lck

if [ -f $CW_LOCK_FILE ]
then
	rm $CW_LOCK_FILE
fi

if [ -n "${CW_TIMEOUT+x}" ]; then
	echo Using timeout $CW_TIMEOUT
else
	CW_TIMEOUT=3
fi

./exc_handler "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder" &
EXCPID=$! # get the PID for the last added background process

#make sure the ./tmp directory exists before running this.
cp "$1" tmp/.DS_Store

open -a Finder tmp

ruby -e "begin ; sleep $CW_TIMEOUT; Process.kill(\"USR1\", $EXCPID) if not File.exists?(\"$CW_LOCK_FILE\"); rescue; end" &

# wait for exc_handler to exit, and get exit value
wait $EXCPID
EXIT_VALUE=$?

# return exit value of exc_handler
exit $EXIT_VALUE
