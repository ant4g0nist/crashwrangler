use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn historical_live_crash_corpus() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let runner = env!("CARGO_BIN_EXE_crashwrangler");
    let output =
        std::env::temp_dir().join(format!("crashwrangler-rust-corpus-{}", std::process::id()));
    fs::create_dir(&output).expect("create isolated corpus output directory");

    let cases = [
        ("abort", Some(("EXC_CRASH", "no"))),
        ("bad_func_call", Some(("EXC_BAD_ACCESS", "yes"))),
        ("cfrelease_null", Some(("dontcare", "no"))),
        ("cpp_crash", Some(("EXC_BAD_ACCESS", "yes"))),
        ("crashexec", Some(("EXC_BAD_ACCESS", "yes"))),
        ("crashread", Some(("EXC_BAD_ACCESS", "no"))),
        ("crashwrite", Some(("EXC_BAD_ACCESS", "yes"))),
        ("divzero", None),
        ("exploitable_jit", Some(("EXC_BAD_ACCESS", "yes"))),
        ("fastMalloc", Some(("EXC_BAD_ACCESS", "no"))),
        ("fortify_source_overflow", Some(("EXC_BREAKPOINT", "yes"))),
        ("illegal_libdispatch", Some(("EXC_BREAKPOINT", "no"))),
        ("illegalinstruction", Some(("EXC_BAD_INSTRUCTION", "yes"))),
        ("invalid_address_64", Some(("EXC_BAD_ACCESS", "yes"))),
        ("malloc_abort", Some(("EXC_BREAKPOINT", "yes"))),
        ("nocrash", None),
        ("nullderef", Some(("EXC_BAD_ACCESS", "no"))),
        ("objc_crash", Some(("EXC_BAD_ACCESS", "yes"))),
        ("read_and_write_instruction", Some(("EXC_BAD_ACCESS", "no"))),
        ("recursion", Some(("EXC_BAD_ACCESS", "no"))),
        ("recursive_write", Some(("EXC_BAD_ACCESS", "no"))),
        ("stack_buffer_overflow", Some(("EXC_CRASH", "yes"))),
        (
            "variable_length_stack_buffer",
            Some(("EXC_BAD_ACCESS", "yes")),
        ),
    ];

    let mut failures = Vec::new();
    for (name, expected) in cases {
        let log = output.join(format!("{name}.crashlog.txt"));
        let status = Command::new(runner)
            .arg(root.join(name))
            .env("CW_LOG_PATH", &log)
            .env("CW_CURRENT_CASE", name)
            .env("CW_EXPLOITABLE_JIT", "1")
            .env("CW_QUIET", "1")
            .status()
            .unwrap_or_else(|error| panic!("launching {name}: {error}"));

        match expected {
            None if status.success() && !log.exists() => {}
            Some((wanted_exception, wanted_exploitable)) if log.exists() => {
                let header = first_line(&log);
                let exception = field(&header, "exception").unwrap_or("missing");
                let exploitable = field(&header, "is_exploitable").unwrap_or("missing");
                if (wanted_exception != "dontcare" && exception != wanted_exception)
                    || exploitable != wanted_exploitable
                {
                    failures.push(format!(
                        "{name}: got ({exception}, {exploitable}), wanted ({wanted_exception}, {wanted_exploitable})"
                    ));
                }
            }
            _ => failures.push(format!(
                "{name}: status={status}, log_exists={}, expected={expected:?}",
                log.exists()
            )),
        }
    }

    let _ = fs::remove_dir_all(&output);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn first_line(path: &PathBuf) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn field<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    let start = header.find(&format!("{name}="))? + name.len() + 1;
    let end = header[start..].find(':')? + start;
    Some(header[start..end].trim())
}
