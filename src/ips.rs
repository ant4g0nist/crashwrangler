use crate::arm64::{self, AccessKind};
use crate::crash::{CrashEvent, Error, Exploitability, Frame};
use crate::json::{self, Value};

pub fn parse(contents: &str) -> Result<CrashEvent, Error> {
    let (metadata_text, payload_text) = contents
        .split_once('\n')
        .ok_or_else(|| Error::message("missing .ips payload"))?;
    let metadata = json::parse(metadata_text).map_err(|error| Error::message(error.to_string()))?;
    let payload = json::parse(payload_text).map_err(|error| Error::message(error.to_string()))?;

    let process_name = string(&payload, "procName")
        .or_else(|| string(&metadata, "app_name"))
        .unwrap_or("unknown")
        .to_owned();
    let process_path = string(&payload, "procPath")
        .unwrap_or(&process_name)
        .to_owned();
    let architecture = normalize_architecture(string(&payload, "cpuType").unwrap_or("ARM-64"));
    let os = payload.get("osVersion").unwrap_or(&Value::Null);
    let build_version = string(os, "build")
        .or_else(|| string(&metadata, "build_version"))
        .unwrap_or("unknown")
        .to_owned();
    let exception = payload.get("exception").unwrap_or(&Value::Null);
    let exception_type = string(exception, "type").unwrap_or("EXC_CRASH").to_owned();
    let signal = string(exception, "signal").unwrap_or("unknown").to_owned();
    let subtype = string(exception, "subtype");
    let codes = string(exception, "codes").unwrap_or("unknown");
    let exception_code = subtype
        .unwrap_or(codes)
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .trim_end_matches(',')
        .to_owned();
    let access_address = subtype
        .and_then(|value| value.split_once(" at ").map(|(_, address)| address))
        .and_then(parse_hex)
        .or_else(|| {
            exception
                .get("rawCodes")
                .and_then(Value::as_array)
                .and_then(|values| values.get(1))
                .and_then(Value::as_u64)
        });
    let faulting_thread = number(&payload, "faultingThread").unwrap_or(0) as usize;
    let threads = payload
        .get("threads")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::message("missing threads"))?;
    let thread = threads
        .get(faulting_thread)
        .ok_or_else(|| Error::message("invalid faultingThread"))?;
    let state = thread.get("threadState").unwrap_or(&Value::Null);
    let instruction_address = register(state, "pc");
    let esr = register(state, "esr");
    let images = payload
        .get("usedImages")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::message("missing usedImages"))?;
    let frames = parse_frames(thread, images);

    let mut access_kind =
        if exception_type == "EXC_BAD_ACCESS" && matches!((esr >> 26) & 0x3f, 0x24 | 0x25) {
            if esr & (1 << 6) == 0 {
                AccessKind::Read
            } else {
                AccessKind::Write
            }
        } else {
            instruction_word(&payload)
                .map(arm64::classify)
                .unwrap_or(AccessKind::Unknown)
        };
    if access_address == Some(instruction_address) && instruction_address != 0 {
        access_kind = AccessKind::Execute;
    }
    if frames.len() > 300 {
        access_kind = AccessKind::Recursion;
    }
    let instruction = if esr != 0 && exception_type == "EXC_BAD_ACCESS" {
        format!("{}\t.esr 0x{esr:08x}", access_kind.as_str())
    } else if let Some(word) = instruction_word(&payload) {
        format!("{}\t.inst 0x{word:08x}", access_kind.as_str())
    } else {
        "unknown".to_owned()
    };

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

fn string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn number(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn register(state: &Value, name: &str) -> u64 {
    state
        .get(name)
        .and_then(|entry| entry.get("value"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn normalize_architecture(value: &str) -> String {
    let lowercase = value.to_ascii_lowercase();
    if lowercase.contains("arm64") || lowercase.contains("arm-64") {
        "ARM-64".to_owned()
    } else if lowercase.contains("x86-64") || lowercase.contains("x86_64") {
        "X86-64".to_owned()
    } else {
        value.to_owned()
    }
}

fn parse_hex(value: &str) -> Option<u64> {
    u64::from_str_radix(value.trim().trim_start_matches("0x"), 16).ok()
}

fn parse_frames(thread: &Value, images: &[Value]) -> Vec<Frame> {
    thread
        .get("frames")
        .and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .map(|frame| {
            let image_index = number(frame, "imageIndex").unwrap_or(0) as usize;
            let image = images.get(image_index).unwrap_or(&Value::Null);
            let base = number(image, "base").unwrap_or(0);
            let module_offset = number(frame, "imageOffset").unwrap_or(0);
            Frame {
                module: string(image, "name").unwrap_or("???").to_owned(),
                address: if base == 0 {
                    module_offset
                } else {
                    base.saturating_add(module_offset)
                },
                module_offset,
                function: string(frame, "symbol").unwrap_or("???").to_owned(),
                function_offset: number(frame, "symbolLocation").unwrap_or(0),
            }
        })
        .collect()
}

fn instruction_word(payload: &Value) -> Option<u32> {
    let encoded = payload
        .get("instructionByteStream")?
        .get("atPC")?
        .as_str()?;
    let bytes = base64_decode(encoded)?;
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

fn base64_decode(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    let mut block = [0u8; 4];
    let mut count = 0;
    for byte in value.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if byte == b'=' {
            block[count] = 64;
        } else {
            block[count] = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => return None,
            };
        }
        count += 1;
        if count == 4 {
            output.push((block[0] << 2) | (block[1] >> 4));
            if block[2] != 64 {
                output.push((block[1] << 4) | (block[2] >> 2));
            }
            if block[3] != 64 {
                output.push((block[2] << 6) | block[3]);
            }
            count = 0;
        }
    }
    (count == 0).then_some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_base64() {
        assert_eq!(base64_decode("IAAA+Q==").unwrap(), [0x20, 0x00, 0x00, 0xf9]);
    }
}
