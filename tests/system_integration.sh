#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

if [ "$(uname -s)" != "Darwin" ]; then
	echo "system integration tests require macOS" >&2
	exit 77
fi

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runner="$project_dir/exc_handler"
crasher="$project_dir/crashwrite"
spinner="$project_dir/spin"
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/crashwrangler-system.XXXXXX")
label="com.crashwrangler.integration.$$"
domain="gui/$(id -u)"
plist="$test_dir/$label.plist"
loaded=0

cleanup() {
	if [ "$loaded" -eq 1 ]; then
		launchctl bootout "$domain/$label" >/dev/null 2>&1 || true
	fi
	rm -rf -- "$test_dir"
}
trap cleanup EXIT HUP INT TERM

run_crash_mode() {
	mode=$1
	set +e
	env "$mode=1" CW_NO_LOG=1 CW_QUIET=1 "$runner" "$crasher"
	result=$?
	set -e
	if [ "$result" -ne 111 ]; then
		echo "$mode returned $result, expected 111" >&2
		exit 1
	fi
}

run_crash_mode CW_NO_KILL_CHILD
run_crash_mode CW_FORWARD_CRASH_REPORTER

plist_buddy=/usr/libexec/PlistBuddy
"$plist_buddy" -c "Clear dict" "$plist"
"$plist_buddy" -c "Add :Label string $label" "$plist"
"$plist_buddy" -c "Add :ProgramArguments array" "$plist"
"$plist_buddy" -c "Add :ProgramArguments:0 string $runner" "$plist"
"$plist_buddy" -c "Add :ProgramArguments:1 string $crasher" "$plist"
"$plist_buddy" -c "Add :WorkingDirectory string $project_dir" "$plist"
"$plist_buddy" -c "Add :EnvironmentVariables dict" "$plist"
"$plist_buddy" -c "Add :EnvironmentVariables:CW_REGISTER_LAUNCHD_NAME string $label" "$plist"
"$plist_buddy" -c "Add :EnvironmentVariables:CW_LOG_PATH string $test_dir/launchd.crashlog.txt" "$plist"
"$plist_buddy" -c "Add :EnvironmentVariables:CW_LOCK_FILE string $test_dir/launchd.lck" "$plist"
"$plist_buddy" -c "Add :EnvironmentVariables:CW_QUIET string 1" "$plist"
"$plist_buddy" -c "Add :MachServices dict" "$plist"
"$plist_buddy" -c "Add :MachServices:$label bool true" "$plist"
"$plist_buddy" -c "Add :RunAtLoad bool true" "$plist"
"$plist_buddy" -c "Add :StandardOutPath string $test_dir/launchd.stdout" "$plist"
"$plist_buddy" -c "Add :StandardErrorPath string $test_dir/launchd.stderr" "$plist"

launchctl bootstrap "$domain" "$plist"
loaded=1
attempt=0
while [ ! -f "$test_dir/launchd.crashlog.txt" ] && [ "$attempt" -lt 100 ]; do
	sleep 0.1
	attempt=$((attempt + 1))
done
if [ ! -f "$test_dir/launchd.crashlog.txt" ]; then
	echo "launchd mode did not produce a crash log" >&2
	sed -n '1,40p' "$test_dir/launchd.stderr" >&2 || true
	exit 1
fi
case $(sed -n '1p' "$test_dir/launchd.crashlog.txt") in
	exception=EXC_BAD_ACCESS:*is_exploitable=yes:*) ;;
	*)
		echo "launchd mode produced an unexpected header" >&2
	sed -n '1p' "$test_dir/launchd.crashlog.txt" >&2
		exit 1
		;;
esac

if sudo -n true >/dev/null 2>&1; then
	"$spinner" &
	target=$!
	(sleep 1; kill -SEGV "$target") &
	set +e
	sudo -n env CW_ATTACH_PID="$target" CW_LOG_PATH="$test_dir/attach.crashlog.txt" \
		CW_LOCK_FILE="$test_dir/attach.lck" CW_QUIET=1 "$runner"
	result=$?
	set -e
	if [ "$result" -ne 111 ] || [ ! -f "$test_dir/attach.crashlog.txt" ]; then
		kill -9 "$target" >/dev/null 2>&1 || true
		echo "attach mode returned $result, expected 111 and a crash log" >&2
		exit 1
	fi
	echo "attach mode: passed"
else
	echo "attach mode: skipped (passwordless sudo is unavailable)"
fi

echo "forwarding mode: passed"
echo "no-kill mode: passed"
echo "launchd mode: passed"
