use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(command: &mut Command, description: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("could not run {description}: {error}"));
    assert!(status.success(), "{description} failed with {status}");
}

fn main() {
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        panic!("CrashWrangler's live exception handler requires macOS");
    }
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("aarch64") {
        panic!("CrashWrangler v3 supports Apple Silicon (arm64) only");
    }

    let sdk = Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
        .unwrap_or_else(|error| panic!("could not locate the macOS SDK: {error}"));
    assert!(
        sdk.status.success(),
        "xcrun could not locate the macOS SDK: {}",
        String::from_utf8_lossy(&sdk.stderr).trim()
    );
    let definitions = PathBuf::from(
        String::from_utf8(sdk.stdout)
            .expect("the macOS SDK path is UTF-8")
            .trim(),
    )
    .join("usr/include/mach/mach_exc.defs");
    assert!(
        definitions.is_file(),
        "the macOS SDK does not contain {}",
        definitions.display()
    );

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let header = output.join("mach_excServer.h");
    let server = output.join("mach_excServer.c");
    let object = output.join("mach_excServer.o");

    run(
        Command::new("xcrun")
            .args(["--sdk", "macosx", "mig"])
            .arg("-header")
            .arg("/dev/null")
            .arg("-user")
            .arg("/dev/null")
            .arg("-sheader")
            .arg(&header)
            .arg("-server")
            .arg(&server)
            .arg(&definitions),
        "Apple MIG",
    );
    run(
        Command::new("xcrun")
            .args([
                "--sdk",
                "macosx",
                "clang",
                "-c",
                "-O2",
                "-mmacosx-version-min=11.0",
            ])
            .arg(&server)
            .arg("-o")
            .arg(&object),
        "Clang for Apple-generated MIG glue",
    );

    println!("cargo:rustc-link-arg={}", object.display());
    println!("cargo:rustc-link-search=framework=/System/Library/PrivateFrameworks");
    println!("cargo:rustc-link-lib=framework=CoreSymbolication");
}
