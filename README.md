# CrashWrangler

CrashWrangler is a set of tools used to determine if a crash is an exploitable security issue, and if a crash is a duplicate of another known crash.

The exploitability diagnosis is intended to be used when you have a reproducible test case, but the duplicate detection can be run on any crash log. CrashWrangler uses heuristics, and false positives and false negatives are possible. It's intended for quick assessment; a detailed manual inspection is the only way to be sure something is or isn't exploitable.

**NOTE:** A crash can only be a security issue if it is triggered by untrusted input. CrashWrangler does not try to determine whether or not the crash was triggered by untrusted input; this is up to the user.

If a crash is determined to be non-exploitable, it's recommended to run the test case again with `libgmalloc(3)` enabled, and see if the crash changes to one that is considered exploitable.

CrashWrangler does not send any data about your crash to Apple or anyone else. You can set `CW_NO_CRASH_REPORTER` to prevent forwarding crash info to the system CrashReporter.

Bugs and issues can be reported on this project's [GitHub repository](https://github.com/ant4g0nist/crashwrangler).

## Components

- **exc_handler** -- A Mach exception handler that executes a child process, catches exceptions in the child, and inspects the process state to determine if the crash was exploitable. Configured using environment variables (see [Environment Variables](#environment-variables) below).

- **bucket_logs.rb** and its helper **CW_CrashLog.rb** -- Determines which crashes are duplicates. It can examine logs from exc_handler or standard CrashReporter crash logs. Run with `-h` for usage.

- **analyze_log.rb** and its helper **CrashLog.rb** -- Analyzes a crash log for security implications statically, without needing to run the program.

- **sample_scripts/** -- Sample shell scripts that demonstrate how to run a test case in a few different applications.

You can run any of the Ruby scripts with the `-h` option to get more options.

Don't run these programs in a world-writable directory if you don't trust other users. They assume the current working directory is safe.

## Platform Support

- **macOS on Apple Silicon (arm64)** -- Primary target of this fork.
- The Makefile retains x86_64 build targets for older macOS versions (10.10--10.12), but these are untested in this fork.

### arm64 Behavioral Differences

- On arm64, integer division by zero does **not** raise `EXC_ARITHMETIC` (the hardware silently returns zero). Only floating-point exceptions may trigger it.
- Some runtime checks (e.g. `__builtin_trap`, `_FORTIFY_SOURCE`) use `brk` instructions instead of `abort()`, resulting in `EXC_BREAKPOINT` rather than `EXC_CRASH`.
- `__stack_chk_fail` may be mis-symbolicated by CoreSymbolication on arm64; CrashWrangler includes heuristic detection of corrupted return addresses in backtraces to compensate.

## Build & Install

### Prerequisites

- Xcode Command Line Tools (`xcode-select --install`)
- [Capstone](https://www.capstone-engine.org/) disassembly framework:

```sh
brew install capstone
```

If you installed capstone to a non-Homebrew location, edit the `BREW_PREFIX` line in the Makefile.

### Building

```sh
make
```

### Running the test suite (optional)

```sh
make tests && ruby test_suite.rb
```

### Installing

```sh
cp exc_handler *.rb [the directory where you are running test cases]
```

## Quick Start

### Testing one crash

Here's an example of using exc_handler to reproduce a crash and see if it's exploitable:

```sh
env CW_CURRENT_CASE=foo ./exc_handler "/Applications/QuickTime Player.app/Contents/MacOS/QuickTime Player" file_that_crashes.mov
```

It creates a log in `crashlogs/foo.crashlog.txt`.

When you look at the log, there's a header that looks like:

```
exception=EXC_BAD_ACCESS:signal=11:is_exploitable=yes:instruction_disassembly=str w0, [x1]:instruction_address=0x0000000100003f40:access_type=write:access_address=0x0000000041414141:
```

The most interesting field is `is_exploitable`.

### Checking for duplicates

Put the crash logs in a directory named `crashlogs`:

```sh
mkdir crashlogs
cp ~/Library/Logs/CrashReporter/* crashlogs
```

Run `bucket_logs.rb` (if the crash logs were generated using exc_handler, it will also tell you whether or not the crashes were exploitable):

```
./bucket_logs.rb

Crash at 0 + 16384 / start + 54
	exploitable=unknown: ./crashlogs/a.out_2009-04-10-173926_hostname.crash
	exploitable=unknown: ./crashlogs/a.out_2009-04-10-173919_hostname.crash

Crash at 0 + 23047272
	exploitable=unknown: ./crashlogs/Meeting Maker Calendar_2008-10-17-143822_hostname.crash
```

### Analyzing a log

If you have a reproducible crash, you're better off using exc_handler. But if you have a crash log for a non-reproducible crash, you can use `analyze_log.rb` to attempt to diagnose it:

```
$ ./analyze_log.rb crashlogs/crashread.crashlog.txt
exception_type=EXC_BAD_ACCESS:signal=SIGSEGV:is_exploitable= no:instruction_disassembly=ldr x0, [x1]:instruction_address=0x0000000100000f38:access_type=read:access_address=0x0000000041414141:
```

### Fuzzing

Here's an example of running file fuzzing on QuickTime movies:

1. Generate a bunch of fuzzed movie files in a directory.
2. For each file, run `sample_scripts/run_qt.sh [path to the file]`.
3. This automates running the movie files in QuickTime. For each crash, a log file named something like `crashlogs/00000000.mov.crashlog.txt` will be created.
4. When done, run `./bucket_logs.rb` and it will print out a list of the found crashes, with duplicates grouped together.

## Writing Automation Scripts

If you're using your own automation, the only thing you need to do is set the environment variable `CW_CURRENT_CASE` to the name of the test case being run:

```sh
export CW_CURRENT_CASE=$1
```

If you are going to kill the program, make sure the file named `cw.lck` (or the file specified by `CW_LOCK_FILE`) does not exist before you kill the program. The lock file exists only while a crash is being processed by CrashWrangler.

For smaller command-line programs where slow performance is not an issue, you can enable `libgmalloc(3)`:

```sh
env CW_USE_GMAL=1 ./exc_handler myprogram $1
```

## exc_handler Return Values

| Return value | Meaning |
|---|---|
| `0` | No crash |
| `-1` (255) | Error |
| `-2` | Externally generated signals (SIGINT, SIGHUP, SIGKILL) |
| Signal number | Crash, not exploitable (e.g. SIGSEGV = `11`) |
| Signal number + 100 | Crash, exploitable (e.g. exploitable SIGSEGV = `111`) |

## Crash Log Header Reference

This is the format for the header of logs generated by exc_handler.

Example:

```
exception=EXC_BAD_ACCESS:signal=11:is_exploitable= no:instruction_disassembly=str w0, [x1]:instruction_address=0x0000000100003f40:access_type=write:access_address=0x0000000000000000:
```

| Field | Values |
|---|---|
| `exception` | `EXC_BAD_ACCESS`, `EXC_BAD_INSTRUCTION`, `EXC_ARITHMETIC`, `EXC_CRASH`, `EXC_BREAKPOINT` |
| `signal` | Signal number (see `man signal`) |
| `is_exploitable` | `yes` or `no` |
| `instruction_disassembly` | Disassembly of the crashing instruction (filled for read, write, or `EXC_ARITHMETIC`) |
| `instruction_address` | Address of the crashing instruction |
| `access_type` | `read`, `write`, `exec`, `recursion`, or `unknown` (only for `EXC_BAD_ACCESS`) |
| `access_address` | Bad address that caused the crash (`0x0` if not `EXC_BAD_ACCESS`) |

## Exploitability Algorithm

The algorithm for determining exploitability:

**Exploitable if:**

- Crash on write instruction
- Crash executing an invalid address
- Crash calling an invalid address
- Illegal instruction exception
- Abort due to `-fstack-protector`, `_FORTIFY_SOURCE`, heap corruption detected
- Stack trace of crashing thread contains suspicious functions (malloc, free, szone_error, objc_msgSend, etc.)
- Corrupted return address detected in backtrace (arm64 heuristic for mis-symbolicated `__stack_chk_fail`)

**Not exploitable if:**

- Divide by zero exception (note: on arm64, integer div-by-zero does not raise an exception at all)
- Stack grows too large due to recursion
- Null dereference (read or write)
- Other abort
- Crash on read instruction (unless `CW_EXPLOITABLE_READS` is set)

## Environment Variables

| Variable | Description |
|---|---|
| `CW_CURRENT_CASE` | Arbitrary string identifier for the case currently being run. Used for generating the log name. Suitable for use when the program is killed and relaunched for each case. |
| `CW_CASE_FILE` | File holding the identifier for the current case. Takes precedence over `CW_CURRENT_CASE`. Suitable for long-running programs. |
| `CW_LOG_PATH` | Path for the log file. Takes precedence over both `CW_CURRENT_CASE` and `CW_CASE_FILE`. Useful for sending all logs to e.g. `/dev/null`. |
| `CW_LOG_DIR` | Directory to output crash logs to. Default: `./crashlogs` |
| `CW_LOCK_FILE` | Lock file path. Default: `cw.lck`. Only needed if running multiple automation sessions simultaneously. |
| `CW_PID_FILE` | If set, exc_handler writes the child PID to this file. Useful for targeting `kill` at a specific process instance. |
| `CW_ATTACH_PID` | PID of process to monitor for crashes. Requires running as root or having exc_handler setgid procmod. |
| `CW_USE_GMAL` | If set, use `libgmalloc(3)` plus `MALLOC_ALLOW_READS` and `MALLOC_FILL_SPACE` in the child process. |
| `CW_NO_KILL_CHILD` | If set, don't kill exc_handler's child with SIGKILL on exit. |
| `CW_QUIET` | If set, suppress stdout output unless there was an internal error. |
| `CW_EXPLOITABLE_READS` | If set, non-NULL read access violations are considered exploitable. Useful for C++ where reading an invalid object could indicate reading a vtable pointer from an invalid address. |
| `CW_REGISTER_LAUNCHD_NAME` | Name to register the exception port with launchd (or a stand-alone bootstrap name). For use with LaunchAgents/LaunchDaemons. |
| `CW_NO_CRASH_REPORTER` | If set, don't forward crash information to CrashReporter. |
| `CW_MACHINE_READABLE` | If set, add less output to the header of crash logs. |
| `CW_TIMEOUT` | Time to wait before killing the program. Used by automation scripts, not by exc_handler itself. |
| `CW_TEST_CASE_PATH` | Path to the test case being run. Only needed when the path differs from `CW_CURRENT_CASE`. |
| `CWE_*` | Any env var prefixed with `CWE_` has the prefix stripped and is set in the child process only. E.g. `CWE_DYLD_INSERT_LIBRARIES=foo.dylib` becomes `DYLD_INSERT_LIBRARIES=foo.dylib` in the child. |
| `CW_NO_LOG` | If set, don't write a crash log. Useful for testing. |
| `CW_IGNORE_FRAME_POINTER` | If set, don't flag exploitable based on frame/base pointer discrepancy. Set this if the target was built with `-fomit-frame-pointer`. |
| `CW_EXPLOITABLE_JIT` | If set, any crash outside of a known library or the main executable is considered exploitable. For programs with JIT-compiled code. |
| `CW_LOG_INFO` | If set, the value is included in the crash log. General-purpose mechanism for logging extra info. |

## Notes

CrashWrangler may malfunction if you have anything set in `~/Library/Preferences/com.apple.DebugSymbols.plist`. This preference would not normally exist; if you don't know what it is, don't worry about it.
