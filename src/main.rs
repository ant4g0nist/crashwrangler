mod arm64;
mod crash;
mod ips;
mod json;
mod macos;

use std::env;
use std::process::ExitCode;

fn usage() {
    eprintln!(
        "Usage:\n  crashwrangler analyze [--json] <report>\n  crashwrangler bucket <directory>\n  crashwrangler run <program> [arguments...]"
    );
}

fn main() -> ExitCode {
    let mut args = env::args();
    let _program = args.next();
    let Some(command) = args.next() else {
        if env::var_os("CW_ATTACH_PID").is_some()
            || env::var_os("CW_REGISTER_LAUNCHD_NAME").is_some()
        {
            return commands::run(&[]);
        }
        usage();
        return ExitCode::from(2);
    };

    let remaining: Vec<String> = args.collect();
    match command.as_str() {
        "analyze" => commands::analyze(&remaining),
        "bucket" => commands::bucket(&remaining),
        "run" => commands::run(&remaining),
        "-h" | "--help" | "help" => {
            usage();
            ExitCode::SUCCESS
        }
        // Preserve exc_handler's historical interface: when the first argument
        // is not a CrashWrangler subcommand, treat it as the program to launch.
        _ => {
            let mut launch = Vec::with_capacity(remaining.len() + 1);
            launch.push(command);
            launch.extend(remaining);
            commands::run(&launch)
        }
    }
}

mod commands {
    use super::crash::CrashEvent;
    use std::fs;
    use std::path::Path;
    use std::process::ExitCode;

    pub fn analyze(args: &[String]) -> ExitCode {
        let json = args.iter().any(|arg| arg == "--json" || arg == "-j");
        let paths: Vec<&String> = args.iter().filter(|arg| !arg.starts_with('-')).collect();
        if paths.len() != 1 {
            eprintln!("Usage: crashwrangler analyze [--json] <report>");
            return ExitCode::from(2);
        }

        match CrashEvent::from_path(Path::new(paths[0])) {
            Ok(event) => {
                if json {
                    println!("{}", event.to_json());
                } else {
                    println!("{}", event.machine_description());
                }
                ExitCode::from(event.exploitability.exit_code())
            }
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::from(2)
            }
        }
    }

    pub fn bucket(args: &[String]) -> ExitCode {
        if args.len() != 1 {
            eprintln!("Usage: crashwrangler bucket <directory>");
            return ExitCode::from(2);
        }
        let root = Path::new(&args[0]);
        let mut paths = Vec::new();
        if let Err(error) = collect_reports(root, &mut paths) {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
        paths.sort();

        let mut buckets: std::collections::BTreeMap<String, Vec<(String, String)>> =
            std::collections::BTreeMap::new();
        for path in paths {
            match CrashEvent::from_path(&path) {
                Ok(event) => buckets.entry(event.signature.clone()).or_default().push((
                    event.exploitability.as_str().to_owned(),
                    path.display().to_string(),
                )),
                Err(error) => {
                    eprintln!("error parsing {}: {error}", path.display());
                    return ExitCode::from(2);
                }
            }
        }

        for (signature, crashes) in buckets {
            println!("\nCrash at {}", signature.replace('^', " / "));
            for (exploitability, path) in crashes {
                println!("\texploitable={exploitability}: {path}");
            }
        }
        ExitCode::SUCCESS
    }

    fn collect_reports(
        directory: &Path,
        output: &mut Vec<std::path::PathBuf>,
    ) -> std::io::Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            if path.is_dir() {
                collect_reports(&path, output)?;
            } else {
                let text = path.to_string_lossy();
                if text.ends_with(".ips")
                    || text.ends_with(".crash")
                    || text.ends_with(".crashlog.txt")
                {
                    output.push(path);
                }
            }
        }
        Ok(())
    }

    pub fn run(args: &[String]) -> ExitCode {
        match super::macos::run(args) {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::from(255)
            }
        }
    }
}
