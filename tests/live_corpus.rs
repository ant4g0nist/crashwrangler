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
        ("abort", Some(("EXC_CRASH", "no")), false),
        ("bad_func_call", Some(("EXC_BAD_ACCESS", "yes")), false),
        ("badsyscall", Some(("EXC_CRASH", "no")), false),
        ("cfrelease_null", Some(("dontcare", "no")), false),
        ("cpp_crash", Some(("EXC_BAD_ACCESS", "yes")), false),
        ("crashexec", Some(("EXC_BAD_ACCESS", "yes")), false),
        ("crashread", Some(("EXC_BAD_ACCESS", "no")), false),
        ("crashwrite", Some(("EXC_BAD_ACCESS", "yes")), false),
        ("divzero", None, false),
        ("exploitable_jit", Some(("EXC_BAD_ACCESS", "yes")), true),
        ("fastMalloc", Some(("EXC_BAD_ACCESS", "no")), false),
        (
            "fortify_source_overflow",
            Some(("EXC_BREAKPOINT", "yes")),
            false,
        ),
        ("illegal_libdispatch", Some(("EXC_BREAKPOINT", "no")), false),
        (
            "illegalinstruction",
            Some(("EXC_BAD_INSTRUCTION", "yes")),
            false,
        ),
        ("invalid_address_64", Some(("EXC_BAD_ACCESS", "yes")), false),
        ("malloc_abort", Some(("EXC_BREAKPOINT", "yes")), false),
        ("nocrash", None, false),
        ("null_objc_msgSend", Some(("EXC_BAD_ACCESS", "no")), false),
        ("nullderef", Some(("EXC_BAD_ACCESS", "no")), false),
        ("objc_crash", Some(("EXC_BAD_ACCESS", "yes")), false),
        (
            "read_and_write_instruction",
            Some(("EXC_BAD_ACCESS", "no")),
            false,
        ),
        ("recursion", Some(("EXC_BAD_ACCESS", "no")), false),
        ("recursive_write", Some(("EXC_BAD_ACCESS", "no")), false),
        ("stack_buffer_overflow", Some(("EXC_CRASH", "yes")), false),
        (
            "variable_length_stack_buffer",
            Some(("EXC_BAD_ACCESS", "yes")),
            false,
        ),
    ];

    let mut failures = Vec::new();
    for (name, expected, jit) in cases {
        let log = output.join(format!("{name}.crashlog.txt"));
        let mut command = Command::new(runner);
        command
            .arg(root.join(name))
            .env("CW_LOG_PATH", &log)
            .env("CW_CURRENT_CASE", name)
            .env("CW_QUIET", "1")
            .env_remove("CW_EXPLOITABLE_JIT");
        if jit {
            command.env("CW_EXPLOITABLE_JIT", "1");
        }
        let status = command
            .status()
            .unwrap_or_else(|error| panic!("launching {name}: {error}"));

        match expected {
            None if status.success() && !log.exists() => {}
            Some((wanted_exception, wanted_exploitable)) if log.exists() => {
                let header = first_line(&log);
                let exception = field(&header, "exception").unwrap_or("missing");
                let exploitable = field(&header, "is_exploitable").unwrap_or("missing");
                let signal = field(&header, "signal")
                    .and_then(|value| value.parse::<i32>().ok())
                    .unwrap_or(-1);
                let wanted_status = signal + i32::from(wanted_exploitable == "yes") * 100;
                if (wanted_exception != "dontcare" && exception != wanted_exception)
                    || exploitable != wanted_exploitable
                    || status.code() != Some(wanted_status)
                {
                    failures.push(format!(
                        "{name}: got ({exception}, {exploitable}, {status}), wanted ({wanted_exception}, {wanted_exploitable}, exit {wanted_status})"
                    ));
                }
            }
            _ => failures.push(format!(
                "{name}: status={status}, log_exists={}, expected={expected:?}",
                log.exists()
            )),
        }
    }

    let human_log = output.join("human.crashlog.txt");
    let machine_log = output.join("machine.crashlog.txt");
    for (log, machine_readable) in [(&human_log, false), (&machine_log, true)] {
        let mut command = Command::new(runner);
        command
            .arg(root.join("crashwrite"))
            .env("CW_LOG_PATH", log)
            .env("CW_CURRENT_CASE", "header-mode")
            .env("CW_QUIET", "1")
            .env_remove("CW_MACHINE_READABLE");
        if machine_readable {
            command.env("CW_MACHINE_READABLE", "1");
        }
        let status = command.status().expect("launching header-mode probe");
        if status.code() != Some(111) {
            failures.push(format!("header-mode probe returned {status}, wanted 111"));
        }
    }
    let human = fs::read_to_string(&human_log).expect("read human-readable log");
    let machine = fs::read_to_string(&machine_log).expect("read machine-readable log");
    let summary = "CrashWrangler classified this EXC_BAD_ACCESS as yes";
    if !human.contains(summary) {
        failures.push("default log is missing its human-readable summary".to_owned());
    }
    if machine.contains(summary) {
        failures.push("CW_MACHINE_READABLE log contains a human-readable summary".to_owned());
    }
    if machine.contains("Test case was") || machine.contains("LOG_INFO:") {
        failures.push("CW_MACHINE_READABLE log contains human-readable metadata".to_owned());
    }

    let timeout_status = Command::new(runner)
        .arg(root.join("spin"))
        .env("CW_TIMEOUT", "1")
        .env("CW_NO_LOG", "1")
        .env("CW_QUIET", "1")
        .status()
        .expect("launching timeout probe");
    if timeout_status.code() != Some(254) {
        failures.push(format!(
            "CW_TIMEOUT probe returned {timeout_status}, wanted exit 254"
        ));
    }

    let invalid_timeout = Command::new(runner)
        .arg(root.join("nocrash"))
        .env("CW_TIMEOUT", "0")
        .status()
        .expect("launching invalid-timeout probe");
    if invalid_timeout.code() != Some(255) {
        failures.push(format!(
            "invalid CW_TIMEOUT returned {invalid_timeout}, wanted exit 255"
        ));
    }

    let env_output = output.join("child-environment.txt");
    let env_status = Command::new(runner)
        .arg(root.join("env_probe"))
        .arg(&env_output)
        .env("CW_PROBE", "parent-value")
        .env("CWE_CW_PROBE", "child-value")
        .env("CWE_CHILD_ONLY", "present")
        .env("CW_QUIET", "1")
        .status()
        .expect("launching child-environment probe");
    if !env_status.success() {
        failures.push(format!(
            "child-environment probe returned {env_status}, wanted success"
        ));
    } else {
        let child_environment =
            fs::read_to_string(&env_output).expect("read child-environment probe output");
        if child_environment
            != "CW_PROBE=child-value\nCHILD_ONLY=present\nCWE_CW_PROBE=<unset>\nMALLOC_FILL_SPACE=<unset>\nDYLD_INSERT_LIBRARIES=<unset>\n"
        {
            failures.push(format!(
                "unexpected child environment:\n{child_environment}"
            ));
        }
    }

    let gmalloc_output = output.join("gmalloc-environment.txt");
    let gmalloc_status = Command::new(runner)
        .arg(root.join("env_probe"))
        .arg(&gmalloc_output)
        .env("CW_USE_GMAL", "1")
        .env("CW_QUIET", "1")
        .status()
        .expect("launching Guard Malloc environment probe");
    if !gmalloc_status.success() {
        failures.push(format!(
            "Guard Malloc environment probe returned {gmalloc_status}, wanted success"
        ));
    } else {
        let gmalloc_environment =
            fs::read_to_string(&gmalloc_output).expect("read Guard Malloc probe output");
        if !gmalloc_environment.contains("MALLOC_FILL_SPACE=1\n")
            || !gmalloc_environment.contains("DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib\n")
        {
            failures.push(format!(
                "Guard Malloc child environment was incomplete:\n{gmalloc_environment}"
            ));
        }
    }

    let case_file = output.join("current-case.txt");
    fs::write(&case_file, "from.case/path\n").expect("write case-file probe");
    let pid_file = output.join("child.pid");
    let lock_file = output.join("custom.lck");
    let metadata_output = Command::new(runner)
        .arg(root.join("crashwrite"))
        .env("CW_CURRENT_CASE", "ignored-current-case")
        .env("CW_CASE_FILE", &case_file)
        .env("CW_LOG_DIR", &output)
        .env("CW_TEST_CASE_PATH", "/inputs/original-case")
        .env("CW_LOG_INFO", "worker=7")
        .env("CW_PID_FILE", &pid_file)
        .env("CW_LOCK_FILE", &lock_file)
        .env("CW_QUIET", "1")
        .output()
        .expect("launching metadata probe");
    if metadata_output.status.code() != Some(111) {
        failures.push(format!(
            "metadata probe returned {}, wanted 111",
            metadata_output.status
        ));
    }
    if !metadata_output.stdout.is_empty() {
        failures.push("CW_QUIET did not suppress stdout".to_owned());
    }
    let metadata_log = output.join("from_case_path.crashlog.txt");
    match fs::read_to_string(&metadata_log) {
        Ok(contents)
            if contents.contains("Test case was /inputs/original-case\n")
                && contents.contains("LOG_INFO: worker=7\n") => {}
        Ok(contents) => failures.push(format!(
            "case/log metadata was missing from generated log:\n{contents}"
        )),
        Err(error) => failures.push(format!(
            "CW_CASE_FILE/CW_LOG_DIR did not select {}: {error}",
            metadata_log.display()
        )),
    }
    if fs::read_to_string(&pid_file)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|pid| *pid > 0)
        .is_none()
    {
        failures.push("CW_PID_FILE did not contain a positive child PID".to_owned());
    }
    if lock_file.exists() {
        failures.push("CW_LOCK_FILE was left behind after capture".to_owned());
    }

    let exploitable_read_log = output.join("exploitable-read.crashlog.txt");
    let exploitable_read = Command::new(runner)
        .arg(root.join("crashread"))
        .env("CW_LOG_PATH", &exploitable_read_log)
        .env("CW_EXPLOITABLE_READS", "1")
        .env("CW_QUIET", "1")
        .status()
        .expect("launching exploitable-read probe");
    if exploitable_read.code() != Some(111)
        || field(&first_line(&exploitable_read_log), "is_exploitable") != Some("yes")
    {
        failures.push(format!(
            "CW_EXPLOITABLE_READS probe returned {exploitable_read}, wanted exploitable SIGSEGV"
        ));
    }

    let suppressed_log = output.join("must-not-exist.crashlog.txt");
    let no_log = Command::new(runner)
        .arg(root.join("crashwrite"))
        .env("CW_LOG_PATH", &suppressed_log)
        .env("CW_NO_LOG", "1")
        .env("CW_QUIET", "1")
        .status()
        .expect("launching no-log probe");
    if no_log.code() != Some(111) || suppressed_log.exists() {
        failures.push(format!(
            "CW_NO_LOG probe returned {no_log}, file_exists={}",
            suppressed_log.exists()
        ));
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
