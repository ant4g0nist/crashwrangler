//! macOS live crash capture. All interfaces here are supplied by libSystem or
//! CoreSymbolication; the only compiled non-Rust code is MIG's generated server.

use crate::arm64::{self, AccessKind};
use crate::crash::{CrashEvent, Exploitability, Frame};
use std::env;
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Mutex, OnceLock};

type MachPort = c_uint;
type KernReturn = c_int;
type MachCount = c_uint;
type MachVmAddress = u64;
type MachVmSize = u64;

const KERN_SUCCESS: KernReturn = 0;
const KERN_FAILURE: KernReturn = 5;
const MACH_PORT_RIGHT_RECEIVE: c_int = 1;
const MACH_PORT_RIGHT_PORT_SET: c_int = 3;
const MACH_MSG_TYPE_MAKE_SEND: c_int = 20;
const EXC_CRASH: c_int = 10;
const EXC_MASK_CRASH: c_uint = 1 << EXC_CRASH;
const EXC_MASK_ALL: c_uint = 0x7fff_ffff;
const EXCEPTION_STATE_IDENTITY: c_int = 3;
const MACH_EXCEPTION_CODES: c_uint = 0x8000_0000;
const ARM_THREAD_STATE64: c_int = 6;
const SIGKILL: c_int = 9;
const O_NOFOLLOW: c_int = 0x0000_0100;
const KCS_NOW: c_uint = 0x8000_0000;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ArmThreadState64 {
    x: [u64; 29],
    fp: u64,
    lr: u64,
    sp: u64,
    pc: u64,
    cpsr: u32,
    pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CsTypeRef {
    cpp_data: *mut c_void,
    cpp_object: *mut c_void,
}

#[repr(C)]
struct CsRange {
    location: u64,
    length: u64,
}

type Demux = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;

unsafe extern "C" {
    static mach_task_self_: MachPort;

    fn mach_port_allocate(task: MachPort, right: c_int, name: *mut MachPort) -> KernReturn;
    fn mach_port_insert_right(
        task: MachPort,
        name: MachPort,
        poly: MachPort,
        poly_poly: c_int,
    ) -> KernReturn;
    fn mach_port_deallocate(task: MachPort, name: MachPort) -> KernReturn;
    fn mach_port_move_member(task: MachPort, member: MachPort, after: MachPort) -> KernReturn;
    fn mach_msg_server_once(
        demux: Demux,
        max_size: c_uint,
        receive_name: MachPort,
        options: c_uint,
    ) -> KernReturn;
    fn mach_exc_server(input: *mut c_void, output: *mut c_void) -> c_int;
    fn mach_vm_read_overwrite(
        target: MachPort,
        address: MachVmAddress,
        size: MachVmSize,
        data: MachVmAddress,
        out_size: *mut MachVmSize,
    ) -> KernReturn;
    fn task_set_exception_ports(
        task: MachPort,
        mask: c_uint,
        port: MachPort,
        behavior: c_int,
        flavor: c_int,
    ) -> KernReturn;
    fn task_for_pid(target: MachPort, pid: c_int, task: *mut MachPort) -> KernReturn;
    fn task_get_special_port(task: MachPort, which: c_int, port: *mut MachPort) -> KernReturn;
    fn bootstrap_check_in(
        bootstrap_port: MachPort,
        service_name: *const c_char,
        service_port: *mut MachPort,
    ) -> KernReturn;
    fn pid_for_task(task: MachPort, pid: *mut c_int) -> KernReturn;
    fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffer_size: c_uint) -> c_int;
    fn sysctlbyname(
        name: *const c_char,
        old: *mut c_void,
        old_len: *mut usize,
        new: *mut c_void,
        new_len: usize,
    ) -> c_int;
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn pthread_sigmask(how: c_int, set: *const c_uint, old_set: *mut c_uint) -> c_int;

    fn posix_spawnattr_init(attributes: *mut *mut c_void) -> c_int;
    fn posix_spawnattr_destroy(attributes: *mut *mut c_void) -> c_int;
    fn posix_spawnattr_setexceptionports_np(
        attributes: *mut *mut c_void,
        mask: c_uint,
        port: MachPort,
        behavior: c_int,
        flavor: c_int,
    ) -> c_int;
    fn posix_spawnp(
        pid: *mut c_int,
        path: *const c_char,
        actions: *const *mut c_void,
        attributes: *const *mut c_void,
        argv: *const *mut c_char,
        envp: *const *mut c_char,
    ) -> c_int;

    fn CSSymbolicatorCreateWithTask(task: MachPort) -> CsTypeRef;
    fn CSSymbolicatorGetSymbolWithAddressAtTime(
        symbolicator: CsTypeRef,
        address: u64,
        time: c_uint,
    ) -> CsTypeRef;
    fn CSSymbolGetName(symbol: CsTypeRef) -> *const c_char;
    fn CSSymbolGetRange(symbol: CsTypeRef) -> CsRange;
    fn CSSymbolGetSymbolOwner(symbol: CsTypeRef) -> CsTypeRef;
    fn CSSymbolOwnerGetName(owner: CsTypeRef) -> *const c_char;
    fn CSSymbolOwnerGetBaseAddress(owner: CsTypeRef) -> u64;
    fn CSIsNull(reference: CsTypeRef) -> u8;
    fn CSRelease(reference: CsTypeRef);
}

struct Runtime {
    outcome: Mutex<Option<Result<LiveCrash, String>>>,
}

struct LiveCrash {
    event: CrashEvent,
    report: String,
    signal: u8,
}

#[derive(Clone, Copy)]
struct ExceptionPort {
    receive: MachPort,
    send: MachPort,
}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub fn run(arguments: &[String]) -> Result<u8, String> {
    let empty_signals = 0;
    check_posix(
        unsafe { pthread_sigmask(3, &empty_signals, ptr::null_mut()) },
        "pthread_sigmask",
    )?;
    let runtime = RUNTIME.get_or_init(|| Runtime {
        outcome: Mutex::new(None),
    });
    *runtime
        .outcome
        .lock()
        .map_err(|_| "runtime lock poisoned")? = None;

    let exception_port = if let Ok(service) = env::var("CW_REGISTER_LAUNCHD_NAME") {
        launchd_exception_port(&service)?
    } else {
        allocate_exception_port()?
    };
    debug(format_args!(
        "exception receive={} send={}",
        exception_port.receive, exception_port.send
    ));
    if let Ok(value) = env::var("CW_ATTACH_PID") {
        let pid = value
            .parse::<c_int>()
            .map_err(|_| "CW_ATTACH_PID must be a positive integer")?;
        attach(exception_port.send, pid)?;
        if arguments.is_empty() {
            return serve_one_exception(exception_port.receive, runtime);
        }
    }
    if arguments.is_empty() {
        if env::var_os("CW_REGISTER_LAUNCHD_NAME").is_some() {
            return serve_one_exception(exception_port.receive, runtime);
        }
        return Err("Usage: crashwrangler run <program> [arguments...]".to_owned());
    }

    let (program, argv, envp) = spawn_strings(arguments)?;
    let mut attributes: *mut c_void = ptr::null_mut();
    check_posix(
        unsafe { posix_spawnattr_init(&mut attributes) },
        "posix_spawnattr_init",
    )?;
    let behavior = (EXCEPTION_STATE_IDENTITY as u32 | MACH_EXCEPTION_CODES) as c_int;
    let setup = unsafe {
        posix_spawnattr_setexceptionports_np(
            &mut attributes,
            EXC_MASK_CRASH,
            exception_port.send,
            behavior,
            ARM_THREAD_STATE64,
        )
    };
    if let Err(error) = check_posix(setup, "posix_spawnattr_setexceptionports_np") {
        unsafe { posix_spawnattr_destroy(&mut attributes) };
        return Err(error);
    }

    let mut pid = 0;
    let spawn_result = unsafe {
        posix_spawnp(
            &mut pid,
            program.as_ptr(),
            ptr::null(),
            &attributes,
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };
    unsafe { posix_spawnattr_destroy(&mut attributes) };
    check_posix(spawn_result, "posix_spawnp")?;
    debug(format_args!("spawned pid {pid}"));

    if let Some(path) = env::var_os("CW_PID_FILE") {
        fs::write(path, pid.to_string())
            .map_err(|error| format!("writing CW_PID_FILE: {error}"))?;
    }

    std::thread::spawn(move || unsafe {
        debug(format_args!(
            "exception server waiting on {}",
            exception_port.receive
        ));
        let result = mach_msg_server_once(mach_exc_server, 8192, exception_port.receive, 0);
        debug(format_args!("exception server returned {result}"));
        let _ = mach_port_deallocate(mach_task_self_, exception_port.send);
    });

    let mut status = 0;
    if unsafe { waitpid(pid, &mut status, 0) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    debug(format_args!("waitpid status=0x{status:08x}"));

    let captured = runtime
        .outcome
        .lock()
        .map_err(|_| "runtime lock poisoned")?
        .take();
    remove_lock();
    if let Some(captured) = captured {
        let crash = captured?;
        emit_crash(&crash)?;
        let exploitable = crash.event.exploitability == Exploitability::Yes;
        return Ok(if exploitable {
            crash.signal.saturating_add(100)
        } else {
            crash.signal
        });
    }

    if wait_was_external_signal(status) {
        Ok(254)
    } else {
        Ok(0)
    }
}

fn launchd_exception_port(service: &str) -> Result<ExceptionPort, String> {
    let service = CString::new(service).map_err(|_| "launchd service name contains NUL")?;
    let task = unsafe { mach_task_self_ };
    let mut bootstrap = 0;
    check_mach(
        unsafe { task_get_special_port(task, 4, &mut bootstrap) },
        "task_get_bootstrap_port",
    )?;
    let mut receive = 0;
    check_mach(
        unsafe { bootstrap_check_in(bootstrap, service.as_ptr(), &mut receive) },
        "bootstrap_check_in",
    )?;
    let child = allocate_exception_port()?;
    let mut port_set = 0;
    check_mach(
        unsafe { mach_port_allocate(task, MACH_PORT_RIGHT_PORT_SET, &mut port_set) },
        "mach_port_allocate(port set)",
    )?;
    check_mach(
        unsafe { mach_port_move_member(task, receive, port_set) },
        "mach_port_move_member(launchd service)",
    )?;
    check_mach(
        unsafe { mach_port_move_member(task, child.receive, port_set) },
        "mach_port_move_member(child exceptions)",
    )?;
    Ok(ExceptionPort {
        receive: port_set,
        send: child.send,
    })
}

fn attach(exception_port: MachPort, pid: c_int) -> Result<(), String> {
    if pid <= 0 {
        return Err("CW_ATTACH_PID must be a positive integer".to_owned());
    }
    let mut task = 0;
    check_mach(
        unsafe { task_for_pid(mach_task_self_, pid, &mut task) },
        "task_for_pid (root or an appropriate entitlement may be required)",
    )?;
    let behavior = (EXCEPTION_STATE_IDENTITY as u32 | MACH_EXCEPTION_CODES) as c_int;
    check_mach(
        unsafe {
            task_set_exception_ports(
                task,
                EXC_MASK_CRASH,
                exception_port,
                behavior,
                ARM_THREAD_STATE64,
            )
        },
        "task_set_exception_ports",
    )
}

fn serve_one_exception(exception_port: MachPort, runtime: &Runtime) -> Result<u8, String> {
    check_mach(
        unsafe { mach_msg_server_once(mach_exc_server, 8192, exception_port, 0) },
        "mach_msg_server_once",
    )?;
    let captured = runtime
        .outcome
        .lock()
        .map_err(|_| "runtime lock poisoned")?
        .take();
    remove_lock();
    let captured = captured.ok_or("exception server returned without a crash")??;
    emit_crash(&captured)?;
    Ok(if captured.event.exploitability == Exploitability::Yes {
        captured.signal.saturating_add(100)
    } else {
        captured.signal
    })
}

fn allocate_exception_port() -> Result<ExceptionPort, String> {
    let task = unsafe { mach_task_self_ };
    let mut port = 0;
    check_mach(
        unsafe { mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &mut port) },
        "mach_port_allocate",
    )?;
    check_mach(
        unsafe { mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND) },
        "mach_port_insert_right",
    )?;
    Ok(ExceptionPort {
        receive: port,
        send: port,
    })
}

type SpawnData = (CString, Vec<*mut c_char>, Vec<*mut c_char>);

fn spawn_strings(arguments: &[String]) -> Result<SpawnData, String> {
    let mut argument_storage = Vec::with_capacity(arguments.len());
    for value in arguments {
        argument_storage.push(CString::new(value.as_str()).map_err(|_| "argument contains NUL")?);
    }
    let program = argument_storage[0].clone();

    let mut environment: Vec<(String, String)> = env::vars().collect();
    environment.retain(|(name, _)| !name.starts_with("CWE_"));
    for (name, value) in env::vars().filter(|(name, _)| name.starts_with("CWE_")) {
        environment.push((name[4..].to_owned(), value));
    }
    if env::var_os("CW_USE_GMAL").is_some() {
        environment.push(("MALLOC_FILL_SPACE".to_owned(), "1".to_owned()));
        environment.push((
            "DYLD_INSERT_LIBRARIES".to_owned(),
            "/usr/lib/libgmalloc.dylib".to_owned(),
        ));
    }
    let mut environment_storage = Vec::with_capacity(environment.len());
    for (name, value) in environment {
        environment_storage
            .push(CString::new(format!("{name}={value}")).map_err(|_| "environment contains NUL")?);
    }

    let mut argv: Vec<*mut c_char> = argument_storage
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect();
    argv.push(ptr::null_mut());
    let mut envp: Vec<*mut c_char> = environment_storage
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect();
    envp.push(ptr::null_mut());

    // The pointer arrays remain valid only while their backing C strings do. Leak
    // the small launch-only vectors; this process exits after one run command.
    std::mem::forget(argument_storage);
    std::mem::forget(environment_storage);
    Ok((program, argv, envp))
}

fn check_mach(result: KernReturn, operation: &str) -> Result<(), String> {
    if result == KERN_SUCCESS {
        Ok(())
    } else {
        Err(format!("{operation} failed with Mach error {result}"))
    }
}

fn check_posix(result: c_int, operation: &str) -> Result<(), String> {
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "{operation}: {}",
            std::io::Error::from_raw_os_error(result)
        ))
    }
}

fn debug(message: std::fmt::Arguments<'_>) {
    if env::var_os("CW_DEBUG").is_some() {
        eprintln!("CrashWrangler: {message}");
    }
}

fn wait_was_external_signal(status: c_int) -> bool {
    let signal = status & 0x7f;
    signal != 0 && signal != 0x7f && (signal < 4 || signal == 9 || signal > 12)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn catch_mach_exception_raise(
    _exception_port: MachPort,
    _thread: MachPort,
    _task: MachPort,
    _exception: c_int,
    _code: *const i64,
    _code_count: MachCount,
) -> KernReturn {
    KERN_FAILURE
}

#[unsafe(no_mangle)]
unsafe extern "C" fn catch_transfer_ports(
    _server: MachPort,
    exception_port: *mut MachPort,
    bootstrap_port: *mut MachPort,
) -> KernReturn {
    if !exception_port.is_null() {
        unsafe { *exception_port = 0 };
    }
    if !bootstrap_port.is_null() {
        unsafe { *bootstrap_port = 0 };
    }
    KERN_FAILURE
}

#[unsafe(no_mangle)]
unsafe extern "C" fn catch_mach_exception_raise_state_identity(
    _exception_port: MachPort,
    thread: MachPort,
    task: MachPort,
    exception: c_int,
    code: *const i64,
    code_count: MachCount,
    flavor: *mut c_int,
    old_state: *const u32,
    old_state_count: MachCount,
    new_state: *mut u32,
    new_state_count: *mut MachCount,
) -> KernReturn {
    debug(format_args!(
        "received exception={exception} codes={code_count} state_words={old_state_count}"
    ));
    if old_state.is_null() || new_state.is_null() || new_state_count.is_null() {
        return KERN_FAILURE;
    }
    let capacity = unsafe { *new_state_count };
    if old_state_count > capacity {
        return KERN_FAILURE;
    }
    unsafe {
        ptr::copy_nonoverlapping(old_state, new_state, old_state_count as usize);
        *new_state_count = old_state_count;
        if !flavor.is_null() {
            *flavor = ARM_THREAD_STATE64;
        }
    }

    let result = std::panic::catch_unwind(|| {
        capture_exception(
            task,
            thread,
            exception,
            code,
            code_count,
            old_state,
            old_state_count,
        )
    });
    let captured = match result {
        Ok(captured) => captured,
        Err(_) => Err("panic while capturing Mach exception".to_owned()),
    };
    if let Some(runtime) = RUNTIME.get() {
        if let Ok(mut outcome) = runtime.outcome.lock() {
            *outcome = Some(captured);
        }
    }

    let forward = env::var_os("CW_FORWARD_CRASH_REPORTER").is_some();
    if forward {
        let behavior = (EXCEPTION_STATE_IDENTITY as u32 | MACH_EXCEPTION_CODES) as c_int;
        unsafe {
            task_set_exception_ports(task, EXC_MASK_ALL, 0, behavior, ARM_THREAD_STATE64);
        }
    } else if env::var_os("CW_NO_KILL_CHILD").is_none() {
        let mut pid = 0;
        if unsafe { pid_for_task(task, &mut pid) } == KERN_SUCCESS && pid > 0 {
            unsafe { kill(pid, SIGKILL) };
        }
    }

    unsafe {
        let _ = mach_port_deallocate(mach_task_self_, task);
        let _ = mach_port_deallocate(mach_task_self_, thread);
    }
    if forward { KERN_FAILURE } else { KERN_SUCCESS }
}

fn capture_exception(
    task: MachPort,
    _thread: MachPort,
    exception: c_int,
    code: *const i64,
    code_count: MachCount,
    state_words: *const u32,
    state_count: MachCount,
) -> Result<LiveCrash, String> {
    create_lock()?;
    if exception != EXC_CRASH || code.is_null() || code_count == 0 || code_count > 2 {
        return Err("unexpected Mach exception payload".to_owned());
    }
    if state_count as usize * size_of::<u32>() < size_of::<ArmThreadState64>() {
        return Err("short arm64 thread state".to_owned());
    }
    let mut state = ArmThreadState64::default();
    unsafe {
        ptr::copy_nonoverlapping(
            state_words.cast::<u8>(),
            (&mut state as *mut ArmThreadState64).cast::<u8>(),
            size_of::<ArmThreadState64>(),
        );
    }
    // MIG packs variable-sized request members on four-byte boundaries. The
    // int64 exception codes therefore aren't guaranteed Rust's u64 alignment.
    let encoded = unsafe { ptr::read_unaligned(code) } as u64;
    let real_exception = ((encoded >> 20) & 0x0f) as c_int;
    let real_exception = if real_exception == 0 {
        EXC_CRASH
    } else {
        real_exception
    };
    let signal = ((encoded >> 24) & 0xff) as u8;
    let real_code = encoded & !0x0000_0000_fff0_0000;
    let access_address = if code_count > 1 {
        unsafe { ptr::read_unaligned(code.add(1)) as u64 }
    } else {
        0
    };

    let instruction_word = read_value::<u32>(task, state.pc).ok();
    let mut access_kind = if real_exception == 1 {
        instruction_word
            .map(arm64::classify)
            .unwrap_or(AccessKind::Unknown)
    } else {
        AccessKind::Unknown
    };
    if real_exception == 1 && access_address == state.pc {
        access_kind = AccessKind::Execute;
    }

    let symbolicator = Symbolicator::new(task);
    let mut frames = unwind(task, &state, &symbolicator);
    if frames.len() > 300 {
        access_kind = AccessKind::Recursion;
    }
    if frames.is_empty() {
        frames.push(Frame {
            module: "???".to_owned(),
            address: state.pc,
            module_offset: state.pc,
            function: "???".to_owned(),
            function_offset: 0,
        });
    }

    let mut pid = 0;
    check_mach(unsafe { pid_for_task(task, &mut pid) }, "pid_for_task")?;
    let process_path = process_path(pid);
    let process_name = Path::new(&process_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_owned();
    let signal_name = signal_name(signal, real_exception).to_owned();
    let exception_type = exception_name(real_exception).to_owned();
    let exception_code = match real_code {
        1 => "KERN_INVALID_ADDRESS".to_owned(),
        2 => "KERN_PROTECTION_FAILURE".to_owned(),
        value => format!("0x{value:016x}"),
    };
    let instruction = instruction_word
        .map(|word| format!(".long 0x{word:08x}"))
        .unwrap_or_default();

    let mut event = CrashEvent {
        process_name,
        process_path,
        architecture: "ARM-64".to_owned(),
        build_version: os_value("kern.osversion"),
        exception_type,
        signal: signal_name,
        exception_code,
        access_address: (real_exception == 1).then_some(access_address),
        instruction_address: state.pc,
        instruction,
        access_kind,
        frames,
        exploitability: Exploitability::Unknown,
        signature: String::new(),
    };
    event.finish_analysis();
    if event.access_kind == AccessKind::Read
        && event.access_address.unwrap_or(0) >= 32 * 1024
        && env::var_os("CW_EXPLOITABLE_READS").is_some()
    {
        event.exploitability = Exploitability::Yes;
    }
    if real_exception == 1
        && env::var_os("CW_IGNORE_FRAME_POINTER").is_none()
        && state.fp.abs_diff(state.sp) > 64 * 1024 * 1024
    {
        event.exploitability = Exploitability::Yes;
    }
    let report = format_report(&event, pid, &state);
    Ok(LiveCrash {
        event,
        report,
        signal,
    })
}

fn read_value<T: Copy + Default>(task: MachPort, address: u64) -> Result<T, KernReturn> {
    let mut value = T::default();
    let mut amount = 0;
    let result = unsafe {
        mach_vm_read_overwrite(
            task,
            address,
            size_of::<T>() as u64,
            (&mut value as *mut T) as u64,
            &mut amount,
        )
    };
    if result == KERN_SUCCESS && amount == size_of::<T>() as u64 {
        Ok(value)
    } else {
        Err(result)
    }
}

fn unwind(task: MachPort, state: &ArmThreadState64, symbolicator: &Symbolicator) -> Vec<Frame> {
    let mut addresses = vec![state.pc];
    if state.lr != 0 && state.lr != state.pc {
        addresses.push(state.lr & 0x0000_ffff_ffff_ffff);
    }
    let mut fp = state.fp;
    while addresses.len() < 512 && fp != 0 && fp & 7 == 0 {
        let Ok(frame) = read_value::<[u64; 2]>(task, fp) else {
            break;
        };
        if frame[1] == 0 || frame[0] == fp {
            break;
        }
        addresses.push(frame[1] & 0x0000_ffff_ffff_ffff);
        fp = frame[0];
    }
    addresses
        .into_iter()
        .map(|address| symbolicator.frame(address))
        .collect()
}

struct Symbolicator(CsTypeRef);

impl Symbolicator {
    fn new(task: MachPort) -> Self {
        Self(unsafe { CSSymbolicatorCreateWithTask(task) })
    }

    fn frame(&self, address: u64) -> Frame {
        if unsafe { CSIsNull(self.0) } != 0 {
            return unknown_frame(address);
        }
        let symbol = unsafe { CSSymbolicatorGetSymbolWithAddressAtTime(self.0, address, KCS_NOW) };
        if unsafe { CSIsNull(symbol) } != 0 {
            return unknown_frame(address);
        }
        let range = unsafe { CSSymbolGetRange(symbol) };
        let owner = unsafe { CSSymbolGetSymbolOwner(symbol) };
        let function =
            c_string(unsafe { CSSymbolGetName(symbol) }).unwrap_or_else(|| "???".to_owned());
        let (module, base) = if unsafe { CSIsNull(owner) } == 0 {
            (
                c_string(unsafe { CSSymbolOwnerGetName(owner) })
                    .unwrap_or_else(|| "???".to_owned()),
                unsafe { CSSymbolOwnerGetBaseAddress(owner) },
            )
        } else {
            ("???".to_owned(), 0)
        };
        Frame {
            module,
            address,
            module_offset: address.saturating_sub(base),
            function,
            function_offset: address.saturating_sub(range.location),
        }
    }
}

impl Drop for Symbolicator {
    fn drop(&mut self) {
        if unsafe { CSIsNull(self.0) } == 0 {
            unsafe { CSRelease(self.0) };
        }
    }
}

fn unknown_frame(address: u64) -> Frame {
    Frame {
        module: "???".to_owned(),
        address,
        module_offset: address,
        function: "???".to_owned(),
        function_offset: 0,
    }
}

fn c_string(value: *const c_char) -> Option<String> {
    (!value.is_null()).then(|| {
        unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned()
    })
}

fn process_path(pid: c_int) -> String {
    let mut buffer = vec![0_u8; 4096];
    let size = unsafe { proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as c_uint) };
    if size <= 0 {
        return "unknown".to_owned();
    }
    CStr::from_bytes_until_nul(&buffer)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_owned())
}

fn os_value(name: &str) -> String {
    let Ok(name) = CString::new(name) else {
        return "unknown".to_owned();
    };
    let mut buffer = [0_u8; 128];
    let mut length = buffer.len();
    if unsafe {
        sysctlbyname(
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut length,
            ptr::null_mut(),
            0,
        )
    } != 0
    {
        return "unknown".to_owned();
    }
    CStr::from_bytes_until_nul(&buffer)
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_owned())
}

fn exception_name(exception: c_int) -> &'static str {
    match exception {
        1 => "EXC_BAD_ACCESS",
        2 => "EXC_BAD_INSTRUCTION",
        3 => "EXC_ARITHMETIC",
        4 => "EXC_EMULATION",
        5 => "EXC_SOFTWARE",
        6 => "EXC_BREAKPOINT",
        7 => "EXC_SYSCALL",
        8 => "EXC_MACH_SYSCALL",
        9 => "EXC_RPC_ALERT",
        10 => "EXC_CRASH",
        _ => "UNKNOWN",
    }
}

fn signal_name(signal: u8, exception: c_int) -> &'static str {
    match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGEMT",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGBUS",
        11 => "SIGSEGV",
        12 => "SIGSYS",
        _ => match exception {
            1 => "SIGSEGV",
            2 => "SIGILL",
            3 => "SIGFPE",
            6 => "SIGTRAP",
            10 => "SIGABRT",
            _ => "SIGKILL",
        },
    }
}

fn format_report(event: &CrashEvent, pid: c_int, state: &ArmThreadState64) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "Process:         {} [{}]\n",
        event.process_name, pid
    ));
    output.push_str(&format!("Path:            {}\n", event.process_path));
    output.push_str("Code Type:       ARM-64 (Native)\n");
    output.push_str(&format!(
        "OS Version:      macOS {} ({})\n\n",
        os_value("kern.osproductversion"),
        event.build_version
    ));
    output.push_str(&format!(
        "Exception Type:  {} ({})\n",
        event.exception_type, event.signal
    ));
    if event.exception_type == "EXC_BAD_ACCESS" {
        output.push_str(&format!(
            "Exception Codes: {} at 0x{:016x}\n\n",
            event.exception_code,
            event.access_address.unwrap_or(0)
        ));
    } else {
        output.push_str(&format!("Exception Codes: {}\n\n", event.exception_code));
    }
    output.push_str("Thread 0 Crashed:\n");
    for (index, frame) in event.frames.iter().enumerate() {
        output.push_str(&format!(
            "{index:<4}{:<35} 0x{:016x} {} + {}\n",
            frame.module, frame.address, frame.function, frame.function_offset
        ));
    }
    output.push_str("\nThread 0 crashed with ARM Thread State (64-bit):\n");
    for (index, value) in state.x.iter().enumerate() {
        output.push_str(&format!("    x{index}: 0x{value:016x}"));
        if index % 4 == 3 || index == 28 {
            output.push('\n');
        }
    }
    output.push_str(&format!(
        "    fp: 0x{:016x}    lr: 0x{:016x}\n",
        state.fp, state.lr
    ));
    output.push_str(&format!(
        "    sp: 0x{:016x}    pc: 0x{:016x}\n",
        state.sp, state.pc
    ));
    output.push_str(&format!("  cpsr: 0x{:08x}\n\nBinary Images:\n", state.cpsr));
    output
}

fn create_lock() -> Result<(), String> {
    let path = env::var_os("CW_LOCK_FILE").unwrap_or_else(|| "./cw.lck".into());
    OpenOptions::new()
        .create(true)
        .write(true)
        .custom_flags(O_NOFOLLOW)
        .mode(0o600)
        .open(path)
        .map(|_| ())
        .map_err(|error| format!("creating lock file: {error}"))
}

fn remove_lock() {
    let path = env::var_os("CW_LOCK_FILE").unwrap_or_else(|| "./cw.lck".into());
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => eprintln!("removing lock file: {error}"),
    }
}

fn emit_crash(crash: &LiveCrash) -> Result<(), String> {
    let path = log_path()?;
    let header = live_header(crash);
    if env::var_os("CW_QUIET").is_none() {
        println!("log name is: {}\n---", path.display());
        println!("{header}");
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .custom_flags(O_NOFOLLOW)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("opening {}: {error}", path.display()))?;
    let current_case = current_case()?.unwrap_or_default();
    let test_case = env::var("CW_TEST_CASE_PATH").unwrap_or(current_case);
    let mut prologue = format!("{header}\nTest case was {test_case}\n");
    if let Ok(info) = env::var("CW_LOG_INFO") {
        prologue.push_str(&format!("LOG_INFO: {info}\n"));
    }
    prologue.push_str("\n\n");
    file.write_all(prologue.as_bytes())
        .and_then(|_| file.write_all(crash.report.as_bytes()))
        .map_err(|error| format!("writing {}: {error}", path.display()))
}

fn live_header(crash: &LiveCrash) -> String {
    format!(
        "exception={}:signal={}:is_exploitable={}:instruction_disassembly={}:instruction_address=0x{:016x}:access_type={}:access_address=0x{:016x}:",
        crash.event.exception_type,
        crash.signal,
        if crash.event.exploitability == Exploitability::Yes {
            "yes"
        } else {
            " no"
        },
        crash.event.instruction.replace(':', " "),
        crash.event.instruction_address,
        crash.event.access_kind.as_str(),
        crash.event.access_address.unwrap_or(0),
    )
}

fn current_case() -> Result<Option<String>, String> {
    if let Some(path) = env::var_os("CW_CASE_FILE") {
        return fs::read_to_string(path)
            .map(|value| Some(value.trim_end_matches(['\n', '\r']).to_owned()))
            .map_err(|error| format!("reading CW_CASE_FILE: {error}"));
    }
    Ok(env::var("CW_CURRENT_CASE").ok())
}

fn log_path() -> Result<PathBuf, String> {
    if env::var_os("CW_NO_LOG").is_some() {
        return Ok(PathBuf::from("/dev/null"));
    }
    if let Some(path) = env::var_os("CW_LOG_PATH") {
        return Ok(PathBuf::from(path));
    }
    let case = current_case()?.ok_or(
        "set CW_CURRENT_CASE, CW_CASE_FILE, or CW_LOG_PATH before running a crashing case",
    )?;
    let directory = env::var_os("CW_LOG_DIR").unwrap_or_else(|| "./crashlogs".into());
    if directory.is_empty() {
        return Err("CW_LOG_DIR must not be empty".to_owned());
    }
    fs::create_dir_all(&directory).map_err(|error| format!("creating CW_LOG_DIR: {error}"))?;
    let basename: String = case
        .chars()
        .map(|character| {
            if character == '/' || character == '.' {
                '_'
            } else {
                character
            }
        })
        .collect();
    Ok(Path::new(&directory).join(format!("{basename}.crashlog.txt")))
}
