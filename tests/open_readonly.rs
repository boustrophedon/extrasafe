use extrasafe::*;
use extrasafe::builtins::SystemIO;

use std::fs::{File, OpenOptions};

use std::io::Write;

#[test]
fn allow_open_readonly() {
    // create tempdir
    let dir = tempfile::tempdir().unwrap();

    let mut path = dir.path().to_path_buf();
    path.push("open_me.txt");

    // Create file, write to it, close it
    let mut file = File::create(&path).unwrap();
    file.write_all(b"hello world").unwrap();
    file.sync_all().unwrap();
    drop(file);

    // Enable safetycontext

    SafetyContext::new()
        .enable(SystemIO::nothing()
            .allow_open_readonly()
            .allow_read()
            .allow_metadata()
            .allow_close()).unwrap()
        .apply_to_current_thread().unwrap();

    // Try to open for writing and fail
    let res = OpenOptions::new().read(true).write(true).open(&path);
    assert!(res.is_err(), "Successfully opened file for writing incorrectly");

    // Try to open for append and fail
    let res = OpenOptions::new().read(true).append(true).open(&path);
    assert!(res.is_err(), "Successfully opened file for append incorrectly");

    // Try to open for create and fail
    let res = OpenOptions::new().read(true).create(true).open(&path);
    assert!(res.is_err(), "Successfully opened file with create incorrectly");

    // Try to open for create_new and fail
    let mut new_path = dir.path().to_path_buf();
    new_path.push("new_path.txt");
    let res = OpenOptions::new().read(true).create_new(true).open(&new_path);
    assert!(res.is_err(), "Successfully opened file with create_new incorrectly");

    // open for read only and succeed
    let res = OpenOptions::new().read(true).write(false).open(&path);
    assert!(res.is_ok(), "Failed to open file for reading: {:?}", res.unwrap_err());
}
