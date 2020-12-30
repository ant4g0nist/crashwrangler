CrashWrangler is a set of tools which are used to determine if a crash is an exploitable security issue, and if a crash is a duplicate of another known crash.
The exploitability diagnosis is intended to be used when you have a reproducible test case, but the duplicate detection can be run on any crash log.
It should be understood that CrashWrangler uses heuristics, and false positives and false negatives are possible.  It's intended for quick assessment; as always a detailed manual inspection is the only way to be sure something is or isn't exploitable. NOTE: a crash can only be a security issue if it is triggered by untrusted input.  CrashWrangler does not try to determine whether or not the crash was triggered by untrusted input; this is up to the user.

If a crash is determined to be non-exploitable, it's recommended to run the test case again with libgmalloc(3) on, and see if the crash changes to one that is considered to be exploitable.

CrashWrangler is supported on OS X 10.8 and later.

CrashWrangler does not send any data about your crash to Apple or anyone else.  Note that it does forward the information about the crash to CrashReporter, which is part of the OS, and as always it will send info to Apple if and only if you click the "Send to Apple" button in the Crash Reporter dialog.

Bugs can be reported on bugreporter.apple.com in the CrashWrangler Radar component.  

Aside from CrashReport_*.o, which contain proprietary code for creating crash logs, CrashWrangler is licensed as sample code and source code is included. 



========= INTRO =========
CrashWrangler consists of:
- A Mach exception handler named exc_handler which executes a child process, then catches exceptions in the child and inspects the process state of the child to try to determine if the crash was exploitable.     It's configured using environment variables.  See "Environment Variable Reference" later in this document for a list of them. exc_handler should be built on the same platform it's going to run on. e.g. building on Snow Leopard and running on Leopard won't work.

- bucket_logs.rb and its helper CW_CrashLog.rb, which determines which crashes are duplicates.  It can examine logs from exc_handler, or standard CrashReporter crash logs.  Run it with the -h option for usage.

- A number of sample shell scripts in the sample_scripts directory that demonstrate how to run a test case in a few different applications.

- analyze_log.rb and its helper CrashLog.rb, which can be used to analyze a log for security implications statically, without needing to run the program.


You can run any of the Ruby scripts with the -h option to get more options.

Don't run these programs in a world writable directory if you don't trust other users.  They make the assumption that the current working directory is safe.



========= Build / install =========
Depends on capstone. Please install capstone. 
I compiled capstone from sources. `make install` in capstone folder installs it to /usr/local/lib and /usr/local/include.
if you installed it in a different location, please modify Makefile on `line 21`

make
Optionally, make tests && ruby test_suite.rb
cp exc_handler *.rb [the directory where you are running test cases]
Note: for convenience, pre-built binaries are in the binaries subdirectory.  To use them, rename the one for your platform to exc_handler and use it as above.



========= Quick Start Examples: Testing one crash =========
Here's an example of using exc_handler to reproduce a crash and see if it's security.
env CW_CURRENT_CASE=foo ./exc_handler "/Applications/QuickTime Player.app/Contents/MacOS/QuickTime Player" file_that_crashes.mov

It creates a log in crashlogs/foo.crashlog.txt

When you look at the log, there's a header that looks like:
exception=EXC_BAD_ACCESS:signal=Segmentation fault:is_exploitable=yes:instruction_disassembly=movb	$CONSTANT,(%eax):instruction_address=0x0000000000001ffa:access_type=write:access_address=0x0000000061616161:

The most interesting is the is_exploitable field.




========= Quick Start Examples: Checking for duplicates =========
Put the crash logs in a directory named crashlogs.
Example:
mkdir crashlogs
cp ~/Library/Logs/CrashReporter/* crashlogs


Run bucket_logs.rb.  (Note: if the crash logs had been generated using exc_handler, then it would tell you whether or not the crashes were exploitable).
It will look like:

./bucket_logs.rb 


Crash at 0 + 16384 / start + 54
	exploitable=unknown: ./crashlogs/a.out_2009-04-10-173926_hostname.crash
	exploitable=unknown: ./crashlogs/a.out_2009-04-10-173919_hostname.crash

Crash at 0 + 23047272
	exploitable=unknown: ./crashlogs/Meeting Maker Calendar_2008-10-17-143822_hostname.crash

Crash at 0 + 1094795585
	exploitable=unknown: ./crashlogs/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_2009-04-08-141200_hostname.crash
	exploitable=unknown: ./crashlogs/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_2009-03-31-172930_hostname.crash

Crash at 0 + 2242207230
	exploitable=unknown: ./crashlogs/recursion_2009-02-12-171839_hostname.crash

Crash at 0 + 1364283728 / main + 48
	exploitable=unknown: ./crashlogs/crashexec_2009-02-05-145029_hostname.crash
	exploitable=unknown: ./crashlogs/crashexec_2009-02-05-144512_hostname.crash
	exploitable=unknown: ./crashlogs/crashexec_2008-10-28-142713_hostname.crash



========= Quick Start Examples: Analyzing a log =========
If you have a reproducible crash, you're better off using exc_handler.  But if you have a crash log for a non-reproducible crash, you can use analyze_logs.rb to attempt to diagnose it, and look at the is_exploitable field.

$ ./analyze_log.rb crashlogs/crashread.crashlog.txt 
exception_type=EXC_BAD_ACCESS:signal=SIGSEGV:is_exploitable= no:instruction_disassembly=movzbl (%rax),%eax:instruction_address=0x0000000100000f38:access_type=read:access_address=0x0000000041414141:



========= Quick Start Examples: Fuzzing =========

Here's an example of running file fuzzing on QuickTime movies.
Generate a bunch of fuzzed movie files in a directory.  

For each of the files, run sample_scripts/run_qt.sh [path to the file]

This will automate running the movie files in QuickTime. For each QuickTime crash, a log file named something like crashlogs/00000000.mov.crashlog.txt will be created.

When all of this is done, run 
./bucket_logs.rb

and it will print out a list of the found crashes, with duplicates grouped together.



========= Writing your own automation scripts =========

If you're using some other automation, the only thing you need to do is make sure to set the environment variable CW_CURRENT_CASE to the name of the test case being run, doing something like export CW_CURRENT_CASE=$1  

If you are going to kill the program, you need to make sure that the file named cw.lck (or the file which was specified by the CW_LOCK_FILE environment variable) does not exist before you kill the program. The lock file exists only if there was a crash, while the crash is being processed by CrashWrangler.

For smaller command line programs where slow performance is not an issue, you can do something like
env CW_USE_GMAL=1 ./exc_handler myprogram $1
which causes exc_handler to use libgmalloc(3).



========= exc_handler return values =========
No crash = 0
Error = -1 (which shows up as 255 in some shells)
Externally generated signals such as sigint, sighup, sigkill returns -2

If there was a crash and it was not exploitable, return the signal number which caused the crash, described in signal(2) manpage.
If there was a crash and it was exploitable, return the signal number which caused the crash + 100.

e.g. a non-exploitable SIGSEGV returns 11, while an exploitable SIGSEGV returns 111.


========= Crash Log Header reference =========
This is the format for the header of the logs generated by exc_handler.

Example:
       exception=EXC_BAD_ACCESS:signal=Bus error:is_exploitable= no:instruction_disassembly=stb	r0,(r2)
         :instruction_address=0x0000000000001fe0:access_type=write:access_address=0x0000000000000000:
        
        exception= (EXC_BAD_ACCESS|EXC_BAD_INSTRUCTION|EXC_ARITHMETIC|EXC_CRASH)
        signal= signal_number (see man signal)
        is_exploitable = (yes|no)
        instruction_disassembly = disassembly of the crashing instruction.  Will only be filled out for crashing on read, write,
          or EXC_ARITHMETIC.
        instruction_address = address of the crashing instruction
        access_type = (read|write|exec|recursion|unknown). Will only be filled out for EXC_BAD_ACCESS, otherwise will be ""
        access_address = bad address that caused the crash. If the exception was not EXC_BAD_ACCESS, it will be set to 0x0000000000000000



========= Exploitability algorithm =========

The algorithm for determining exploitability looks like this:

Exploitable if
	Crash on write instruction
	Crash executing invalid address
	Crash calling an invalid address
	Illegal instruction exception
	Abort due to -fstack-protector, _FORTIFY_SOURCE, heap corruption detected
	Stack trace of crashing thread contains certain functions such as malloc, free, szone_error, objc_MsgSend, etc.

Not exploitable if
	Divide by zero exception
	Stack grows too large due to recursion
	Null dereference(read or write)
	Other abort
	Crash on read instruction



========= Environment Variable Reference =========
CW_CURRENT_CASE: 
Some arbitrary string identifier for the case that's currently being run.
This is suitable for being used when the program is killed and relaunched for each case. This is used for generating the log name and recording which case caused the crash.

CW_CASE_FILE: 
A file that holds the identifier for the case that's currently being run.  If set, this takes precedence over CW_CURRENT_CASE.
This is suitable for being used with long running programs.

CW_LOG_PATH:
The path to use for the log file. If set, this takes precedence over the previous two variables.  This is useful if you just want to send all logs to e.g. /dev/null, or if you only cared about the last log.

CW_LOG_DIR: (Default ./crashlogs)
The directory to output crashlogs to.

CW_LOCK_FILE: (Default cw.lck)
The file to use as a lock.  You only need to set this if you're running more than one automation session on the same computer at the same time.

CW_PID_FILE: 
If set, exc_handler will write the pid of the fuzzed program to this file.  This can be used if you want to use kill instead of killall in your automation system.  For example if you want to run fuzzing on a program while allowing another instance of the program to be untouched, or if you want to run fuzzing on two instances of the same program.

CW_ATTACH_PID:
If set, use this pid as the process to monitor for crashes.  In order to use this, you need to be either running as root, or to have exc_handler setgid procmod.  
e.g. 
sudo chgrp procmod exc_handler
sudo chmod g+s exc_handler
env CW_ATTACH_PID=12313 CW_CURRENT_CASE=foo ./exc_handler
or 
sudo env CW_ATTACH_PID=12313 CW_CURRENT_CASE=foo ./exc_handler

CW_USE_GMAL:
If set, use libgmalloc(3) plus MALLOC_ALLOW_READS and MALLOC_FILL_SPACE in the child process.  This does NOT use libgmalloc in exc_handler itself. 

CW_NO_KILL_CHILD:
The default is to always kill exc_handler's child with SIGKILL when exc_handler exits.  If CW_NO_KILL_CHILD is set, this won't occur.

CW_QUIET:
If set, do not print anything to stdout unless there was an internal error.

CW_EXPLOITABLE_READS:
If set, non-NULL read access violations will be considered exploitable.  This may be desirable if you have a higher tolerance for false positives, and/or if the application is in C++, reading an invalid object could indicate the possibility of reading a vtable pointer from an invalid address.

CW_REGISTER_LAUNCHD_NAME:
If set, use this name to register the exception port with launchd (or a stand-alone bootstrap name if registering with launchd fails).  This will assist with using CrashWrangler on LaunchAgents/LaunchDaemons, which can not register their own Mach services after being exec'd by CrashWrangler.  
The LaunchAgent or LaunchDaemon can look up the exception port and set it in itself using the EXC_CRASH mask and (EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES) behavior.

CW_NO_CRASH_REPORTER:
If set, don't forward information about the crash to CrashReporter.

CW_MACHINE_READABLE:
If set, add less output to the header of crash logs generated by exc_handler.

CW_TIMEOUT:
Time to wait before killing the program.  Used only by automation scripts, not by exc_handler.

CW_TEST_CASE_PATH:
The path to the test case being run. If not set, the system will use the value from CW_CURRENT_CASE, CW_LOG_PATH, or the value in the file specified in CW_CASE_FILE. This is only used for logging, and is only needed in rare cases where the path to the test case is different.

CWE_*:
 If there are any environment variables prefixed with CWE_, delete the prefix and set the environment variable in the child.  This does not apply when using CW_ATTACH_PID or CW_REGISTER_LAUNCHD_NAME.
 
 e.g. CWE_DYLD_INSERT_LIBRARIES=foo.dylib
 -> DYLD_INSERT_LIBRARIES=foo.dylib will be set in the child but not in the exc_handler process.

CW_NO_LOG:
If set, don't write a crash log.  Useful for testing.

CW_IGNORE_FRAME_POINTER:
If set, don't assume that it's exploitable when the frame/base pointer is far away from the stack pointer.  You should set this if the program that you're running is compiled with -fomit-frame-pointer.

CW_EXPLOITABLE_JIT:
If set, any crash outside of a known library or the main executable should be considered exploitable.  These crashes would be expected to be in dynamically generated code such as a JIT, and assuming the JIT normally generates valid code, a crash in the JIT indicates memory corruption/use after free.

CW_LOG_INFO:
If set, put the value in a field in the crash log.  This is a general purpose mechanism for you to log whatever info you want in the generated crash log.

========= NOTES =========
CrashWrangler may malfunction if you have anything set in your ~/Library/Preferences/com.apple.DebugSymbols.plist.  This preference would not normally exist; if you don't know what it is, don't worry about it.
