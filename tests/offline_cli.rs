use std::path::Path;
use std::process::Command;

fn runner() -> Command {
    Command::new(env!("CARGO_BIN_EXE_crashwrangler"))
}

#[test]
fn analyzes_modern_ips_as_json() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = runner()
        .args(["analyze", "--json"])
        .arg(root.join("tests/fixtures/write_bad_access.ips"))
        .output()
        .expect("run analyzer");

    assert!(output.status.success());
    let json = String::from_utf8(output.stdout).expect("UTF-8 JSON");
    assert!(json.contains("\"access_type\":\"write\""));
    assert!(json.contains("\"is_exploitable\":\"yes\""));
    assert!(json.contains("\"signature\":\"write_fixture+16\""));
}

#[test]
fn analyzes_legacy_reports_and_returns_classification_status() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let execute = runner()
        .args(["analyze", "--json"])
        .arg(root.join("tests/fixtures/legacy_execute.crash"))
        .output()
        .expect("analyze standard legacy report");
    assert_eq!(execute.status.code(), Some(0));
    let execute_json = String::from_utf8(execute.stdout).expect("UTF-8 execute JSON");
    assert!(execute_json.contains("\"access_type\":\"exec\""));
    assert!(execute_json.contains("\"is_exploitable\":\"yes\""));

    let read = runner()
        .args(["analyze", "--json"])
        .arg(root.join("tests/fixtures/legacy_read.crashlog.txt"))
        .output()
        .expect("analyze CrashWrangler legacy report");
    assert_eq!(read.status.code(), Some(1));
    let read_json = String::from_utf8(read.stdout).expect("UTF-8 read JSON");
    assert!(read_json.contains("\"access_type\":\"read\""));
    assert!(read_json.contains("\"is_exploitable\":\"no\""));
}

#[test]
fn buckets_supported_report_formats_and_rejects_malformed_input() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory =
        std::env::temp_dir().join(format!("crashwrangler-offline-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create bucket fixture directory");
    std::fs::copy(
        root.join("tests/fixtures/legacy_execute.crash"),
        directory.join("execute.crash"),
    )
    .expect("copy legacy fixture");
    std::fs::copy(
        root.join("tests/fixtures/write_bad_access.ips"),
        directory.join("write.ips"),
    )
    .expect("copy ips fixture");

    let bucket = runner()
        .arg("bucket")
        .arg(&directory)
        .output()
        .expect("bucket reports");
    assert!(bucket.status.success());
    let stdout = String::from_utf8(bucket.stdout).expect("UTF-8 bucket output");
    assert!(stdout.contains("call_bad_address+12"));
    assert!(stdout.contains("write_fixture+16"));

    let malformed = directory.join("malformed.crash");
    std::fs::write(&malformed, "not a crash report\n").expect("write malformed fixture");
    let rejected = runner()
        .arg("analyze")
        .arg(&malformed)
        .output()
        .expect("reject malformed report");
    assert_eq!(rejected.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("malformed crash report"));

    std::fs::remove_dir_all(directory).expect("remove bucket fixture directory");
}
