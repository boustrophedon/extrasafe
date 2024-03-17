use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use builtins::SystemIO;
use extrasafe::*;

// Tests to make sure we don't run into this issue
// https://github.com/rust-vmm/seccompiler/issues/42
// which we shouldn't (by design)

#[test]
/// Test multiple uses of the same syscall across different `RuleSets` don't cancel each other out.
fn different_rulesets_same_syscall() {
    SafetyContext::new()
        // First RuleSet: stdout, stderr
        .enable(
            SystemIO::nothing()
                .allow_read()
                .allow_stdout()
                .allow_stderr()
                .allow_metadata(),
        )
        .unwrap()
        .enable(
            // Second RuleSet: stderr only
            SystemIO::nothing()
                .allow_stderr()
                .allow_metadata()
                .allow_close(),
        )
        .unwrap()
        .apply_to_current_thread()
        .unwrap();

    // Try to write to stdout and stderr
    let res = writeln!(std::io::stdout(), "we can print to stdout");
    assert!(
        res.is_ok(),
        "failed to write to stdout: {:?}",
        res.unwrap_err()
    );
    let res = writeln!(std::io::stderr(), "we can print to stderr");
    assert!(
        res.is_ok(),
        "failed to write to stderr: {:?}",
        res.unwrap_err()
    );
}

fn create_testfile(path: &Path, filename: &str) -> File {
    let path = path.join(filename);
    let mut file = File::create(&path).unwrap();
    file.write_all(filename.as_bytes()).unwrap();
    // sync and close
    file.sync_all().unwrap();
    drop(file);

    // reopen for reading
    File::open(&path).unwrap()
}

#[test]
/// Same as above but with mask instead of == and also 3 rulesets
fn different_rulesets_same_syscall2() {
    // create tempdir
    let dir = tempfile::tempdir().unwrap();

    // Create 3 files, write to them

    let path = dir.path().to_path_buf();

    let mut file1 = create_testfile(&path, "testfile1.txt");
    let mut file2 = create_testfile(&path, "testfile2.txt");
    let mut file3 = create_testfile(&path, "testfile3.txt");

    // Add three different rulesets each allowing reads to a different file
    SafetyContext::new()
        .enable(SystemIO::nothing().allow_stdout().allow_stderr())
        .unwrap()
        .enable(SystemIO::nothing().allow_file_read(&file1))
        .unwrap()
        .enable(SystemIO::nothing().allow_file_read(&file2))
        .unwrap()
        .enable(SystemIO::nothing().allow_file_read(&file3))
        .unwrap()
        .apply_to_current_thread()
        .unwrap();

    let mut s = String::new();
    let res = file1.read_to_string(&mut s);
    assert!(res.is_ok(), "Failed to read file1: {:?}", res.unwrap_err());
    let res = file2.read_to_string(&mut s);
    assert!(res.is_ok(), "Failed to read file2: {:?}", res.unwrap_err());
    let res = file3.read_to_string(&mut s);
    assert!(res.is_ok(), "Failed to read file3: {:?}", res.unwrap_err());

    assert_eq!(s, "testfile1.txttestfile2.txttestfile3.txt");
}
