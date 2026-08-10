use crate::arm64::AccessKind;
use crate::{ips, json};
use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exploitability {
    Yes,
    No,
    Unknown,
}

impl Exploitability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Unknown => "unknown",
        }
    }

    pub fn exit_code(self) -> u8 {
        match self {
            Self::Yes => 0,
            Self::No => 1,
            Self::Unknown => 2,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub module: String,
    pub address: u64,
    pub module_offset: u64,
    pub function: String,
    pub function_offset: u64,
}

#[derive(Clone, Debug)]
pub struct CrashEvent {
    pub process_name: String,
    pub process_path: String,
    pub architecture: String,
    pub build_version: String,
    pub exception_type: String,
    pub signal: String,
    pub exception_code: String,
    pub access_address: Option<u64>,
    pub instruction_address: u64,
    pub instruction: String,
    pub access_kind: AccessKind,
    pub frames: Vec<Frame>,
    pub exploitability: Exploitability,
    pub signature: String,
}

#[derive(Debug)]
pub struct Error(String);

impl Error {
    pub fn message(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

impl CrashEvent {
    pub fn from_path(path: &Path) -> Result<Self, Error> {
        let contents = fs::read_to_string(path)?;
        let mut event = if looks_like_ips(&contents) {
            ips::parse(&contents).map_err(|error| {
                Error::message(format!("malformed .ips report {}: {error}", path.display()))
            })?
        } else {
            parse_legacy(&contents).map_err(|error| {
                Error::message(format!(
                    "malformed crash report {}: {error}",
                    path.display()
                ))
            })?
        };
        event.finish_analysis();
        Ok(event)
    }

    pub fn finish_analysis(&mut self) {
        self.exploitability = classify(self);
        self.signature = signature(self);
    }

    pub fn machine_description(&self) -> String {
        format!(
            "exception_type={}:signal={}:is_exploitable={}:instruction_disassembly={}:instruction_address=0x{:016x}:access_type={}:access_address=0x{:016x}:",
            self.exception_type,
            self.signal,
            self.exploitability.as_str(),
            self.instruction.replace(':', " "),
            self.instruction_address,
            self.access_kind.as_str(),
            self.access_address.unwrap_or(0)
        )
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"process\":{{\"name\":{},\"path\":{},\"architecture\":{},\"build_version\":{}}},\"exception\":{{\"type\":{},\"signal\":{},\"code\":{},\"instruction_address\":\"0x{:016x}\",\"access_address\":\"0x{:016x}\",\"access_type\":{},\"instruction\":{}}},\"analysis\":{{\"is_exploitable\":{},\"signature\":{}}}}}",
            json::escape(&self.process_name),
            json::escape(&self.process_path),
            json::escape(&self.architecture),
            json::escape(&self.build_version),
            json::escape(&self.exception_type),
            json::escape(&self.signal),
            json::escape(&self.exception_code),
            self.instruction_address,
            self.access_address.unwrap_or(0),
            json::escape(self.access_kind.as_str()),
            json::escape(&self.instruction),
            json::escape(self.exploitability.as_str()),
            json::escape(&self.signature)
        )
    }
}

fn looks_like_ips(contents: &str) -> bool {
    let mut lines = contents.lines();
    matches!((lines.next(), lines.next()), (Some(first), Some(second)) if first.trim_start().starts_with('{') && second.trim_start().starts_with('{'))
}

fn parse_legacy(contents: &str) -> Result<CrashEvent, Error> {
    let header = contents.lines().next().unwrap_or_default();
    let process_line = find_line(contents, "Process:")?;
    let process_value = after_colon(process_line);
    let process_name = process_value
        .rsplit_once('[')
        .map(|(name, _)| name.trim())
        .unwrap_or(process_value)
        .to_owned();
    let process_path = after_colon(find_line(contents, "Path:")?).to_owned();
    let architecture = after_colon(find_line(contents, "Code Type:")?)
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .to_owned();
    let os_line = after_colon(find_line(contents, "OS Version:")?);
    let build_version = os_line
        .rsplit_once('(')
        .map(|(_, build)| build.trim_end_matches(')').trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    let exception_line = after_colon(find_line(contents, "Exception Type:")?);
    let exception_type = exception_line
        .split_whitespace()
        .next()
        .unwrap_or("EXC_CRASH")
        .to_owned();
    let signal = exception_line
        .split_once('(')
        .map(|(_, value)| value.trim_end_matches(')').to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    let codes_line = contents
        .lines()
        .find(|line| {
            line.trim_start().starts_with("Exception Codes:")
                || line.trim_start().starts_with("Exception Subtype:")
        })
        .ok_or_else(|| Error::message("missing exception codes"))?;
    let codes = after_colon(codes_line);
    let exception_code = codes
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .trim_end_matches(',')
        .to_owned();
    let access_address = hex_after(codes, " at ")
        .or_else(|| header_value(header, "access_address").and_then(parse_hex));
    let instruction_address = header_value(header, "instruction_address")
        .and_then(parse_hex)
        .or_else(|| find_register(contents, "pc"))
        .or_else(|| find_register(contents, "rip"))
        .unwrap_or(0);
    let instruction = header_value(header, "instruction_disassembly")
        .unwrap_or("unknown")
        .trim()
        .to_owned();
    let mut access_kind = header_value(header, "access_type")
        .map(access_kind_from_str)
        .unwrap_or(AccessKind::Unknown);
    if access_address == Some(instruction_address) && instruction_address != 0 {
        access_kind = AccessKind::Execute;
    }
    let frames = parse_legacy_frames(contents);
    if frames.len() > 300 {
        access_kind = AccessKind::Recursion;
    }

    Ok(CrashEvent {
        process_name,
        process_path,
        architecture,
        build_version,
        exception_type,
        signal,
        exception_code,
        access_address,
        instruction_address,
        instruction,
        access_kind,
        frames,
        exploitability: Exploitability::Unknown,
        signature: String::new(),
    })
}

fn find_line<'a>(contents: &'a str, name: &str) -> Result<&'a str, Error> {
    contents
        .lines()
        .find(|line| line.trim_start().starts_with(name))
        .ok_or_else(|| Error::message(format!("missing {name}")))
}

fn after_colon(line: &str) -> &str {
    line.split_once(':')
        .map(|(_, value)| value.trim())
        .unwrap_or("")
}

fn header_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    let marker = format!("{name}=");
    let start = header.find(&marker)? + marker.len();
    let end = header[start..].find(':')? + start;
    Some(&header[start..end])
}

fn parse_hex(value: &str) -> Option<u64> {
    u64::from_str_radix(value.trim().trim_start_matches("0x"), 16).ok()
}

fn hex_after(value: &str, marker: &str) -> Option<u64> {
    parse_hex(value.split_once(marker)?.1.split_whitespace().next()?)
}

fn find_register(contents: &str, register: &str) -> Option<u64> {
    for line in contents.lines() {
        for field in line.split_whitespace().collect::<Vec<_>>().windows(2) {
            if field[0].trim_end_matches(':') == register {
                if let Some(value) = parse_hex(field[1]) {
                    return Some(value);
                }
            }
        }
    }
    None
}

fn parse_legacy_frames(contents: &str) -> Vec<Frame> {
    let Some(start) = contents.find(" Crashed:\n") else {
        return Vec::new();
    };
    let stack = &contents[start + " Crashed:\n".len()..];
    let mut frames = Vec::new();
    for line in stack.lines() {
        if line.trim().is_empty() {
            break;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[0].parse::<usize>().is_err() {
            continue;
        }
        let module = fields[1].to_owned();
        let address = parse_hex(fields[2]).unwrap_or(0);
        let plus = fields.iter().rposition(|field| *field == "+");
        let (function, function_offset) = if let Some(index) = plus {
            (
                fields[3..index].join(" "),
                fields
                    .get(index + 1)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0),
            )
        } else {
            (fields[3..].join(" "), 0)
        };
        frames.push(Frame {
            module,
            address,
            module_offset: address,
            function,
            function_offset,
        });
    }
    frames
}

fn access_kind_from_str(value: &str) -> AccessKind {
    match value.trim() {
        "read" => AccessKind::Read,
        "write" => AccessKind::Write,
        "exec" => AccessKind::Execute,
        "recursion" => AccessKind::Recursion,
        _ => AccessKind::Unknown,
    }
}

fn classify(event: &CrashEvent) -> Exploitability {
    let jit = std::env::var_os("CW_EXPLOITABLE_JIT").is_some();
    if event
        .frames
        .first()
        .is_some_and(|frame| frame.module == "???")
        && jit
    {
        return Exploitability::Yes;
    }
    match event.exception_type.as_str() {
        "EXC_ARITHMETIC" => Exploitability::No,
        "EXC_BREAKPOINT" => {
            if !release_trap(event) && suspicious_stack(event) {
                Exploitability::Yes
            } else {
                Exploitability::No
            }
        }
        "EXC_BAD_INSTRUCTION" => Exploitability::No,
        _ if event.access_kind == AccessKind::Recursion => Exploitability::No,
        _ if suspicious_stack(event) => Exploitability::Yes,
        "EXC_CRASH" => {
            if corrupted_return_address(event) {
                Exploitability::Yes
            } else {
                Exploitability::No
            }
        }
        "EXC_BAD_ACCESS" => match event.access_kind {
            AccessKind::Execute => Exploitability::Yes,
            _ if event.access_address.unwrap_or(0) < 4096 * 8 => Exploitability::No,
            AccessKind::Read => {
                if std::env::var_os("CW_EXPLOITABLE_READS").is_some() {
                    Exploitability::Yes
                } else {
                    Exploitability::No
                }
            }
            AccessKind::Write => {
                if event.access_address == Some(0xbbad_beef) {
                    Exploitability::No
                } else {
                    Exploitability::Yes
                }
            }
            AccessKind::Recursion => Exploitability::No,
            AccessKind::Unknown => Exploitability::Unknown,
        },
        _ => Exploitability::Unknown,
    }
}

fn release_trap(event: &CrashEvent) -> bool {
    event.frames.iter().any(|frame| {
        matches!(
            frame.function.as_str(),
            "CFRelease" | "_CFRelease" | "CFRetain" | "_CFRetain"
        )
    })
}

fn suspicious_stack(event: &CrashEvent) -> bool {
    const NAMES: &[&str] = &[
        "__stack_chk_fail",
        "__chk_fail_overflow",
        "szone_error",
        "szone_free",
        "malloc",
        "calloc",
        "realloc",
        "free",
        "objc_msgSend",
        "mfm_free",
        "___chkstk_darwin",
        "WTFCrashWithSecurityImplication",
        "GMfree",
        "GMmalloc_zone_free",
        "GMrealloc",
        "fastMalloc",
        "fastFree",
    ];
    if event
        .frames
        .iter()
        .any(|frame| frame.function.contains("ABORTING_DUE_TO_OUT_OF_MEMORY"))
    {
        return false;
    }
    event
        .frames
        .iter()
        .any(|frame| NAMES.iter().any(|name| frame.function.contains(name)))
}

fn corrupted_return_address(event: &CrashEvent) -> bool {
    event
        .frames
        .iter()
        .filter(|frame| frame.module == "???")
        .any(|frame| {
            let address = frame.address;
            if address <= 0xffff {
                return false;
            }
            let bytes = address.to_le_bytes();
            let repeating = bytes
                .iter()
                .filter(|byte| **byte != 0 && **byte == bytes[0])
                .count();
            let high = address >> 48;
            repeating >= 3 || (high != 0 && high != 0xffff)
        })
}

fn signature(event: &CrashEvent) -> String {
    let Some(first) = event.frames.first() else {
        return "unknown".to_owned();
    };
    if event.access_kind == AccessKind::Recursion {
        return format!(
            "[Infinite recursion]^{}+{}",
            first.function, first.function_offset
        );
    }
    let primary_name = normalized_function(first);
    const MATCH_ANY_OFFSET: &[&str] = &[
        "memcpy",
        "memmove",
        "bcopy",
        "bzero",
        "WTFCrash",
        "WTFCrashWithSecurityImplication",
    ];
    let matched = MATCH_ANY_OFFSET
        .iter()
        .find(|name| primary_name.starts_with(**name));
    let mut output = if let Some(name) = matched {
        (*name).to_owned()
    } else {
        format!("{}+{}", primary_name, first.function_offset)
    };
    if system_module(&first.module) {
        if let Some(caller) = event
            .frames
            .iter()
            .skip(1)
            .find(|frame| !system_module(&frame.module))
        {
            let caller_name = normalized_function(caller);
            if caller_name != primary_name {
                output.push('^');
                output.push_str(&caller_name);
                output.push('+');
                output.push_str(&caller.function_offset.to_string());
            }
        }
    }
    output
}

fn normalized_function(frame: &Frame) -> String {
    if frame.function == "???" || frame.function.starts_with("0x") {
        format!("{}+0x{:x}", frame.module, frame.module_offset)
    } else {
        frame.function.clone()
    }
}

fn system_module(module: &str) -> bool {
    module == "???"
        || module == "dyld"
        || module.starts_with("libsystem_")
        || matches!(
            module,
            "libSystem.B.dylib"
                | "libobjc.A.dylib"
                | "libc++abi.dylib"
                | "libdispatch.dylib"
                | "libxpc.dylib"
                | "libgmalloc.dylib"
        )
}
