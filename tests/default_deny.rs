use std::fs::File;
use std::io::Write;

use tempfile::{tempdir, tempfile};

// NOTE: probably issues with running cargo test with --num-threads 1

#[test]
/// No files can be read by default
fn filesystem_no_read() {
    // create a temporary file and write to it

    let dir = tempdir().unwrap();
    let mut path = dir.path().to_path_buf();
    path.push("cannot_be_written_to.txt");

    let mut file = File::create(&path).unwrap();
    file.write_all(b"hello world").unwrap();
    file.sync_all().unwrap();
    drop(file);

    let res = extrasafe::SafetyContext::new()
        .apply_to_current_thread();
    assert!(res.is_ok(), "Extrasafe failed {:?}", res.unwrap_err());

    // try to read the file and fail
    let res = File::open(&path);
    assert!(res.is_err(), "opening file succeeded erroneously");

    let err = res.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied,
        "Error is not EPERM {:?}",
        err
    );
}

#[test]
/// No files can be written by default
fn filesystem_no_write() {
    // create a temporary file

    let mut file = tempfile().unwrap();

    let res = extrasafe::SafetyContext::new()
        .apply_to_current_thread();
    assert!(res.is_ok(), "Extrasafe failed {:?}", res.unwrap_err());

    // try to write to the file and fail
    let res = file.write_all(b"hello world");
    assert!(res.is_err(), "writing file succeeded erroneously");

    let err = res.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied,
        "Error is not EPERM {:?}",
        err
    );
}

#[test]
/// No files can be created by default
fn filesystem_no_create() {
    // create a temporary dir

    let dir = tempdir().unwrap();

    let res = extrasafe::SafetyContext::new()
        .apply_to_current_thread();
    assert!(res.is_ok(), "Extrasafe failed {:?}", res.unwrap_err());

    // try to create a file and fail
    let mut path = dir.path().to_path_buf();
    path.push("cannot_be_written_to.txt");

    let res = File::create(path);
    assert!(res.is_err(), "creating file succeeded erroneously");

    let err = res.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied,
        "Error is not EPERM {:?}",
        err
    );
}
