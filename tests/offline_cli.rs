use std::path::Path;
use std::process::Command;

#[test]
fn analyzes_modern_ips_as_json() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new(env!("CARGO_BIN_EXE_crashwrangler"))
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
