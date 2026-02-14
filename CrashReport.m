/*
 * CrashReport.m — arm64 crash report generator
 *
 * Replacement for the precompiled CrashReport_Sierra.o / CrashReport_Yosemite.o
 * which were x86_64 only. Generates Apple CrashReporter-format crash logs using
 * the CoreSymbolication private framework for symbolication.
 */

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach/exception_types.h>
#import <mach/thread_act.h>
#import <mach/task_info.h>
#import <sys/sysctl.h>
#import <sys/proc_info.h>
#import <libproc.h>
#import <signal.h>
#import "CoreSymbolication.h"

/* ── signal name helper ─────────────────────────────────────────────── */

static const char *signal_name_for_signal(unsigned sig) {
    switch (sig) {
        case 1:  return "SIGHUP";
        case 2:  return "SIGINT";
        case 3:  return "SIGQUIT";
        case 4:  return "SIGILL";
        case 5:  return "SIGTRAP";
        case 6:  return "SIGABRT";
        case 7:  return "SIGEMT";
        case 8:  return "SIGFPE";
        case 9:  return "SIGKILL";
        case 10: return "SIGBUS";
        case 11: return "SIGSEGV";
        case 12: return "SIGSYS";
        default: return "SIG?";
    }
}

static const char *signal_name_for_exception(exception_type_t exc,
                                             mach_exception_data_type_t code0) {
    unsigned sig = (code0 >> 24) & 0xFF;
    if (sig) return signal_name_for_signal(sig);

    switch (exc) {
        case EXC_BAD_ACCESS:      return "SIGSEGV";
        case EXC_BAD_INSTRUCTION: return "SIGILL";
        case EXC_ARITHMETIC:      return "SIGFPE";
        case EXC_BREAKPOINT:      return "SIGTRAP";
        case EXC_CRASH:           return "SIGABRT";
        default:                  return "SIGKILL";
    }
}

static const char *exception_type_string(exception_type_t exc) {
    switch (exc) {
        case EXC_BAD_ACCESS:      return "EXC_BAD_ACCESS";
        case EXC_BAD_INSTRUCTION: return "EXC_BAD_INSTRUCTION";
        case EXC_ARITHMETIC:      return "EXC_ARITHMETIC";
        case EXC_EMULATION:       return "EXC_EMULATION";
        case EXC_SOFTWARE:        return "EXC_SOFTWARE";
        case EXC_BREAKPOINT:      return "EXC_BREAKPOINT";
        case EXC_SYSCALL:         return "EXC_SYSCALL";
        case EXC_MACH_SYSCALL:    return "EXC_MACH_SYSCALL";
        case EXC_RPC_ALERT:       return "EXC_RPC_ALERT";
        case EXC_CRASH:           return "EXC_CRASH";
        default:                  return "UNKNOWN";
    }
}

static const char *kern_code_string(mach_exception_data_type_t code) {
    switch (code) {
        case 1:  return "KERN_INVALID_ADDRESS";
        case 2:  return "KERN_PROTECTION_FAILURE";
        default: return NULL;
    }
}

/* ── CrashReport interface ──────────────────────────────────────────── */

@interface CrashReport : NSObject {
    task_t                      _task;
    exception_type_t            _exceptionType;
    mach_exception_data_type_t  _codes[2];
    mach_msg_type_number_t      _codeCount;
    thread_t                    _thread;
    thread_state_flavor_t       _threadStateFlavor;
    arm_thread_state64_t        _threadState;
    mach_msg_type_number_t      _threadStateCount;

    /* Derived. */
    exception_type_t            _realException;
    mach_exception_data_type_t  _realCode[2];
    unsigned int                _signal;
    pid_t                       _pid;
    char                        _procPath[PROC_PIDPATHINFO_MAXSIZE];
    char                        _procName[256];

    CSSymbolicatorRef           _symbolicator;
    NSString                   *_reportString;
}
- (id)initWithTask:(task_t)task
     exceptionType:(exception_type_t)anExceptionType
     exceptionCode:(mach_exception_data_t)anExceptionCode
exceptionCodeCount:(mach_msg_type_number_t)anExceptionCodeCount
            thread:(thread_t)thread
 threadStateFlavor:(thread_state_flavor_t)aThreadStateFlavor
       threadState:(thread_state_data_t)aThreadState
  threadStateCount:(mach_msg_type_number_t)aThreadStateCount;
@end

/* ── implementation ─────────────────────────────────────────────────── */

@implementation CrashReport

- (id)initWithTask:(task_t)task
     exceptionType:(exception_type_t)anExceptionType
     exceptionCode:(mach_exception_data_t)anExceptionCode
exceptionCodeCount:(mach_msg_type_number_t)anExceptionCodeCount
            thread:(thread_t)thread
 threadStateFlavor:(thread_state_flavor_t)aThreadStateFlavor
       threadState:(thread_state_data_t)aThreadState
  threadStateCount:(mach_msg_type_number_t)aThreadStateCount {
    self = [super init];
    if (!self) return nil;

    _task              = task;
    _exceptionType     = anExceptionType;
    _codeCount         = anExceptionCodeCount > 2 ? 2 : anExceptionCodeCount;
    memcpy(_codes, anExceptionCode, _codeCount * sizeof(mach_exception_data_type_t));
    _thread            = thread;
    _threadStateFlavor = aThreadStateFlavor;
    _threadStateCount  = aThreadStateCount;

    /* Copy thread state — exc_handler.m already extracts the arm_thread_state64_t
       from the unified state before calling write_crashlog, so aThreadState points
       directly at the 64-bit state, not the unified wrapper. */
    memcpy(&_threadState, aThreadState, sizeof(arm_thread_state64_t));

    /* Decode EXC_CRASH multiplexed codes (see exc_handler.m). */
    _realException = (_codes[0] >> 20) & 0x0F;
    _signal        = (_codes[0] >> 24) & 0xFF;
    _realCode[0]   = _codes[0] & ~(0x00000000FFF00000ULL);
    _realCode[1]   = _codes[1];
    if (_realException == 0)
        _realException = EXC_CRASH;

    /* Process info. */
    pid_for_task(task, &_pid);
    memset(_procPath, 0, sizeof(_procPath));
    proc_pidpath(_pid, _procPath, sizeof(_procPath));
    /* Derive process name from path. */
    const char *slash = strrchr(_procPath, '/');
    strlcpy(_procName, slash ? slash + 1 : _procPath, sizeof(_procName));

    /* Symbolicator. */
    _symbolicator = CSSymbolicatorCreateWithTask(task);

    _reportString = nil;
    return self;
}

- (void)dealloc {
    if (!CSIsNull(_symbolicator))
        CSRelease(_symbolicator);
    [_reportString release];
    [super dealloc];
}

/* ── helpers ────────────────────────────────────────────────────────── */

- (NSString *)_headerSection {
    NSMutableString *s = [NSMutableString string];

    /* Process line. */
    [s appendFormat:@"Process:         %s [%d]\n", _procName, _pid];
    [s appendFormat:@"Path:            %s\n", _procPath];

    /* Code Type. */
    [s appendString:@"Code Type:       ARM-64 (Native)\n"];

    /* OS Version — e.g. "macOS 26.2 (25C56)" */
    {
        char osver[64] = {0};
        size_t len = sizeof(osver);
        sysctlbyname("kern.osproductversion", osver, &len, NULL, 0);

        char osbuild[64] = {0};
        len = sizeof(osbuild);
        sysctlbyname("kern.osversion", osbuild, &len, NULL, 0);

        [s appendFormat:@"OS Version:      macOS %s (%s)\n", osver, osbuild];
    }

    [s appendString:@"\n"];
    return s;
}

- (NSString *)_exceptionSection {
    NSMutableString *s = [NSMutableString string];

    const char *excStr  = exception_type_string(_realException);
    const char *sigName = signal_name_for_exception(_realException, _codes[0]);
    [s appendFormat:@"Exception Type:  %s (%s)\n", excStr, sigName];

    /* Exception Codes line. */
    if (_realException == EXC_BAD_ACCESS) {
        const char *kernStr = kern_code_string(_realCode[0]);
        if (kernStr) {
            [s appendFormat:@"Exception Codes: %s at 0x%016llx\n",
             kernStr, (unsigned long long)_realCode[1]];
        } else {
            [s appendFormat:@"Exception Codes: 0x%016llx, 0x%016llx\n",
             (unsigned long long)_realCode[0], (unsigned long long)_realCode[1]];
        }
    } else {
        [s appendFormat:@"Exception Codes: 0x%016llx, 0x%016llx\n",
         (unsigned long long)_realCode[0], (unsigned long long)_realCode[1]];
    }

    [s appendString:@"\n"];
    return s;
}

/* Walk frames for one thread using frame-pointer chaining.
   Returns array of NSString* lines. */
- (NSArray *)_backtraceForThread:(thread_t)thr
                       isCrashed:(BOOL)crashed
                     threadIndex:(unsigned)idx {
    NSMutableArray *lines = [NSMutableArray array];

    /* Get thread state. */
    arm_thread_state64_t state;
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr;

    if (thr == _thread) {
        /* Use the thread state we were given (more accurate at crash time). */
        memcpy(&state, &_threadState, sizeof(state));
    } else {
        kr = thread_get_state(thr, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
        if (kr != KERN_SUCCESS) return lines;
    }

    uint64_t pc = (uint64_t)state.__pc;
    uint64_t fp = (uint64_t)state.__fp;
    uint64_t lr = (uint64_t)state.__lr;

    /* Frame 0 = pc. */
    unsigned frameNum = 0;
    uint64_t addresses[512];
    addresses[frameNum++] = pc;

    /* Frame 1 = lr (if non-zero and different from pc). */
    if (lr != 0 && lr != pc) {
        addresses[frameNum++] = lr;
    }

    /* Walk fp chain. Each frame is [saved_fp, saved_lr]. */
    uint64_t currentFP = fp;
    while (frameNum < 512 && currentFP != 0) {
        /* Read [saved_fp, saved_lr] from target task memory. */
        uint64_t frame[2] = {0, 0};
        mach_vm_size_t outSize = 0;
        kr = mach_vm_read_overwrite(_task, (mach_vm_address_t)currentFP,
                                    sizeof(frame), (mach_vm_address_t)frame,
                                    &outSize);
        if (kr != KERN_SUCCESS || outSize < sizeof(frame))
            break;

        uint64_t savedLR = frame[1];
        if (savedLR == 0) break;

        /* Strip PAC bits — mask to 48-bit user-space address. */
        savedLR &= 0x0000FFFFFFFFFFFFULL;

        addresses[frameNum++] = savedLR;
        currentFP = frame[0];

        /* Detect obviously invalid fp (not aligned, zero, going backwards). */
        if (currentFP == 0 || (currentFP & 0x7) != 0)
            break;
    }

    /* Symbolicate and format each frame. */
    for (unsigned i = 0; i < frameNum; i++) {
        uint64_t addr = addresses[i];
        const char *symName  = NULL;
        const char *ownerName = "???";
        uint64_t offset = 0;

        if (!CSIsNull(_symbolicator)) {
            CSSymbolRef sym = CSSymbolicatorGetSymbolWithAddressAtTime(
                _symbolicator, addr, kCSNow);
            if (!CSIsNull(sym)) {
                symName = CSSymbolGetName(sym);
                CSRange range = CSSymbolGetRange(sym);
                offset = addr - range.location;

                CSSymbolOwnerRef owner = CSSymbolGetSymbolOwner(sym);
                if (!CSIsNull(owner)) {
                    ownerName = CSSymbolOwnerGetName(owner);
                }
            } else {
                /* No symbol — try to at least get the image name. */
                /* We'll just output a numeric offset. */
            }
        }

        if (symName) {
            [lines addObject:[NSString stringWithFormat:
                @"%-4u%-35s 0x%016llx %s + %llu",
                i, ownerName, (unsigned long long)addr, symName,
                (unsigned long long)offset]];
        } else {
            [lines addObject:[NSString stringWithFormat:
                @"%-4u%-35s 0x%016llx 0x%llx + %llu",
                i, ownerName, (unsigned long long)addr,
                (unsigned long long)addr, 0ULL]];
        }
    }

    return lines;
}

- (NSString *)_threadsSection {
    NSMutableString *s = [NSMutableString string];

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t threadCount = 0;
    kern_return_t kr = task_threads(_task, &threads, &threadCount);
    if (kr != KERN_SUCCESS) {
        [s appendString:@"(unable to enumerate threads)\n"];
        return s;
    }

    unsigned crashedIdx = 0;
    for (unsigned i = 0; i < threadCount; i++) {
        if (threads[i] == _thread) { crashedIdx = i; break; }
    }

    for (unsigned i = 0; i < threadCount; i++) {
        BOOL crashed = (threads[i] == _thread);
        if (crashed)
            [s appendFormat:@"Thread %u Crashed:\n", i];
        else
            [s appendFormat:@"Thread %u:\n", i];

        NSArray *frames = [self _backtraceForThread:threads[i]
                                          isCrashed:crashed
                                        threadIndex:i];
        for (NSString *line in frames) {
            [s appendFormat:@"%@\n", line];
        }
        [s appendString:@"\n"];
    }

    /* Register state for crashed thread. */
    [s appendFormat:@"Thread %u crashed with ARM Thread State (64-bit):\n", crashedIdx];
    arm_thread_state64_t *ts = &_threadState;

    /* x0-x28 */
    for (int r = 0; r < 29; r++) {
        [s appendFormat:@"    x%d: 0x%016llx", r,
         (unsigned long long)ts->__x[r]];
        if (r % 4 == 3 || r == 28) [s appendString:@"\n"];
    }
    [s appendFormat:@"    fp: 0x%016llx", (unsigned long long)ts->__fp];
    [s appendFormat:@"    lr: 0x%016llx\n", (unsigned long long)ts->__lr];
    [s appendFormat:@"    sp: 0x%016llx", (unsigned long long)ts->__sp];
    [s appendFormat:@"    pc: 0x%016llx\n", (unsigned long long)ts->__pc];
    [s appendFormat:@"  cpsr: 0x%08x\n", ts->__cpsr];
    [s appendString:@"\n"];

    /* Clean up thread ports. */
    for (unsigned i = 0; i < threadCount; i++) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)threads,
                       threadCount * sizeof(thread_act_t));

    return s;
}

- (NSString *)_binaryImagesSection {
    NSMutableString *s = [NSMutableString string];
    [s appendString:@"Binary Images:\n"];

    if (CSIsNull(_symbolicator)) return s;

    CSSymbolicatorForeachSymbolOwnerAtTime(_symbolicator, kCSNow,
        ^int(CSSymbolOwnerRef owner) {
            unsigned long long base = CSSymbolOwnerGetBaseAddress(owner);
            /* Use a reasonable default size since CSSymbolOwnerGetRange
               may not be available. We output the base address for both
               start and end — the Ruby parser only uses the base. */
            unsigned long long end = base + 0xfff;
            const char *name = CSSymbolOwnerGetName(owner);
            const char *path = CSSymbolOwnerGetPath(owner);

            CSUUIDBytes uuid = CSSymbolOwnerGetCFUUIDBytes(owner);

            [s appendFormat:
                @"       0x%llx - 0x%llx  %s "
                @"<%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X> %s\n",
                base, end,
                name ? name : "???",
                uuid.byte0,  uuid.byte1,  uuid.byte2,  uuid.byte3,
                uuid.byte4,  uuid.byte5,  uuid.byte6,  uuid.byte7,
                uuid.byte8,  uuid.byte9,  uuid.byte10, uuid.byte11,
                uuid.byte12, uuid.byte13, uuid.byte14, uuid.byte15,
                path ? path : "???"];

            return 0; /* continue iteration */
        });

    return s;
}

- (NSString *)description {
    if (_reportString) return _reportString;

    NSMutableString *report = [NSMutableString string];
    [report appendString:[self _headerSection]];
    [report appendString:[self _exceptionSection]];
    [report appendString:[self _threadsSection]];
    [report appendString:[self _binaryImagesSection]];

    _reportString = [report copy];
    return _reportString;
}

@end
