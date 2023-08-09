#![cfg(feature = "landlock")]

use std::path::Path;

use std::io::{Read, Write};
use std::fs::{create_dir, read_dir, remove_dir, remove_file, File};

use extrasafe::builtins::SystemIO;

/// helper to check a file can be read
fn can_read_file(path: &Path, expected_data: &str) {
    let res = File::open(path);
    assert!(res.is_ok(), "Failed to open allowed file: {:?}", res.unwrap_err());

    let mut f = res.unwrap();
    let mut file_contents = String::new();
    let res = f.read_to_string(&mut file_contents);
    assert!(res.is_ok(), "Failed to read string: {:?}", res.unwrap_err());

    assert_eq!(expected_data, file_contents);
}

/// helper to check a file can be written to
fn can_write_file(path: &Path, write_data: &str) {
    let res = File::options().append(true).open(path);
    assert!(res.is_ok(), "Failed to open allowed file: {:?}", res.unwrap_err());

    let mut f = res.unwrap();

    let res = f.write_all(write_data.as_bytes());
    assert!(res.is_ok(), "failed to write to file: {:?}", res.unwrap_err());
    drop(f);

    // after writing the data, check we can read it back
    can_read_file(path, write_data);
}

/// helper to check a file cannot be opened
fn can_not_open_file(path: &Path) {
    let res = File::open(path);
    assert!(res.is_err(), "Incorrectly succeeded in opening file for reading");
}

// TODO: distinguish between not being able to remove dir due to not being empty vs denied via
// landlock
fn can_not_remove_dir(path: &Path) {
    let res = remove_dir(path);
    assert!(res.is_err(), "Incorrectly succeeded in removing dir");
}

#[test]
/// Test that a file can be read, and not read if it is not allowed
fn test_landlock_read_file() {
    let dir = tempfile::tempdir().unwrap();

    let allowed_file = dir.path().join("allowed.txt");
    let denied_file = dir.path().join("denied.txt");

    // create, write both
    let mut f = File::create(&allowed_file).unwrap();
    f.write_all(b"test allowed").unwrap();
    drop(f);
    let mut f = File::create(&denied_file).unwrap();
    f.write_all(b"test denied").unwrap(); // doesn't actually matter what we write
    drop(f);

    extrasafe::SafetyContext::new()
        .enable(
            SystemIO::nothing()
                .allow_read_path(&allowed_file)
            ).unwrap()
        .apply_to_current_thread().unwrap();

    // read allowed, fail to open denied
    can_read_file(&allowed_file, "test allowed");
    can_not_open_file(&denied_file);
}

#[test]
/// Test that files can be written to but not created in a specific directory
fn test_landlock_write_file() {
    let dir = tempfile::tempdir().unwrap();

    let allowed_file = dir.path().join("allowed.txt");
    let f = File::create(&allowed_file).unwrap();
    drop(f);

    extrasafe::SafetyContext::new()
        .enable(
            SystemIO::nothing()
                .allow_write_file(&dir)
                .allow_read_path(&dir)
            ).unwrap()
        .apply_to_current_thread().unwrap();

    can_write_file(&allowed_file, "test data");

    let denied_file = dir.path().join("denied.txt");
    let res = File::create(denied_file);
    assert!(res.is_err(), "Incorrectly succeeded in creating file");
}

#[test]
/// Test that file creation can be allowed in a specific directory, and not allowed in all others
fn test_landlock_create_file_in_path() {
    let dir_allowed = tempfile::tempdir().unwrap();
    let dir_denied = tempfile::tempdir().unwrap();

    let allowed_file = dir_allowed.path().join("allowed.txt");
    let denied_file = dir_denied.path().join("denied.txt");

    extrasafe::SafetyContext::new()
        .enable(
            SystemIO::nothing()
                .allow_create_in_dir(&dir_allowed)
            ).unwrap()
        .apply_to_current_thread().unwrap();

    // create succeeds in one directory, fails in other
    let res = File::create(allowed_file);
    assert!(res.is_ok(), "Failed to create file in allowed directory: {:?}", res.unwrap_err());

    let res = File::create(denied_file);
    assert!(res.is_err(), "Incorrectly suceeded in creating file in directory we did not allow");
}

#[test]
/// Test that files can be deleted
fn test_landlock_delete_file() {
    let dir_allowed = tempfile::tempdir().unwrap();
    let dir_denied = tempfile::tempdir().unwrap();

    let allowed_file = dir_allowed.path().join("allowed.txt");
    let denied_file = dir_denied.path().join("denied.txt");

    let f = File::create(&allowed_file).unwrap();
    drop(f);
    let f = File::create(&denied_file).unwrap();
    drop(f);

    extrasafe::SafetyContext::new()
        .enable(
            SystemIO::nothing()
                .allow_remove_file(&dir_allowed)
                .allow_list_dir(&dir_allowed)
            ).unwrap()
        .apply_to_current_thread().unwrap();

    let res = remove_file(&allowed_file);
    assert!(res.is_ok(), "Failed to remove file: {}", res.unwrap_err());

    let dir = read_dir(&dir_allowed).unwrap();
    assert_eq!(dir.collect::<Vec<_>>().len(), 0);

    let res = remove_file(&denied_file);
    assert!(res.is_err(), "Incorrectly succeeded in removing file that was not allowed");
}

#[test]
/// Test that files in a directory can be read, and not read if it is not allowed
fn test_landlock_read_dir() {
    let dir = tempfile::tempdir().unwrap();

    let allowed_subdir = dir.path().join("allowed");
    create_dir(&allowed_subdir).unwrap();
    let allowed_file = allowed_subdir.as_path().join("allowed.txt");
    let denied_file = dir.path().join("denied.txt");

    // create, write both
    let mut f = File::create(&allowed_file).unwrap();
    f.write_all(b"test allowed").unwrap();
    drop(f);
    let mut f = File::create(&denied_file).unwrap();
    f.write_all(b"test denied").unwrap(); // doesn't actually matter what we write
    drop(f);

    extrasafe::SafetyContext::new()
        .enable(
            SystemIO::nothing()
                .allow_read_path(allowed_subdir)
            ).unwrap()
        .apply_to_current_thread().unwrap();

    // read allowed, fail to open denied
    can_read_file(&allowed_file, "test allowed");
    can_not_open_file(&denied_file);
}

#[test]
/// Test that directory creation can be allowed in a specific directory, and not allowed in others
fn test_landlock_create_dir() {
    let dir_allowed = tempfile::tempdir().unwrap();
    let dir_denied = tempfile::tempdir().unwrap();

    extrasafe::SafetyContext::new()
        .enable(
            SystemIO::nothing()
                .allow_create_dir(&dir_allowed)
            ).unwrap()
        .apply_to_current_thread().unwrap();

    let allowed_subdir = dir_allowed.path().join("test_allowed");
    let res = create_dir(allowed_subdir);
    assert!(res.is_ok(), "Failed to create dir: {:?}", res.unwrap_err());

    let denied_subdir = dir_denied.path().join("test_denied");
    let res = create_dir(denied_subdir);
    assert!(res.is_err(), "Incorrectly succeeded in creating directory");
}

#[test]
/// Test that directory contents can be listed, and non-allowed ones fail
fn test_landlock_list_dir() {
    let dir_allowed = tempfile::tempdir().unwrap();
    let dir_denied = tempfile::tempdir().unwrap();

    let allowed_file = dir_allowed.path().join("allowed.txt");
    let f = File::create(allowed_file).unwrap();
    drop(f);

    extrasafe::SafetyContext::new()
        .enable(
            SystemIO::nothing()
                .allow_list_dir(&dir_allowed)
            ).unwrap()
        .apply_to_current_thread().unwrap();

    let res = read_dir(&dir_allowed);
    assert!(res.is_ok(), "Failed to list directory: {}", res.unwrap_err());

    let dir = res.unwrap();
    assert_eq!(dir.collect::<Vec<_>>().len(), 1);

    let res = read_dir(&dir_denied);
    assert!(res.is_err(), "Incorrectly succeeded in reading directory that was not allowed");
}

#[test]
/// Test that directory contents can be deleted, and non-allowed ones fail
fn test_landlock_delete_dir() {
    let dir_allowed = tempfile::tempdir().unwrap();
    let dir_denied = tempfile::tempdir().unwrap();

    let allowed_subdir = dir_allowed.path().join("allowed");
    let denied_subdir = dir_denied.path().join("denied");

    create_dir(&allowed_subdir).unwrap();
    create_dir(&denied_subdir).unwrap();

    extrasafe::SafetyContext::new()
        .enable(
            SystemIO::nothing()
                .allow_remove_dir(&dir_allowed)
                .allow_list_dir(&dir_allowed)
            ).unwrap()
        .apply_to_current_thread().unwrap();

    let res = remove_dir(&allowed_subdir);
    assert!(res.is_ok(), "Failed to remove directory: {}", res.unwrap_err());

    let res = remove_dir(&denied_subdir);
    assert!(res.is_err(), "Incorrectly succeeded in removing directory that was not allowed");

    // check dir is empty
    let mut dir = read_dir(&dir_allowed).unwrap();
    assert!(dir.next().is_none());
}

#[test]
/// Test several landlock rules in the same `RuleSet`
fn test_landlock_one_ruleset() {
    let dir_allowed = tempfile::tempdir().unwrap();
    let dir_denied = tempfile::tempdir().unwrap();

    let allowed_subdir = dir_allowed.path().join("allowed_ro");
    let allowed_subdir_write = dir_allowed.path().join("allowed_write");
    let denied_subdir = dir_denied.path().join("denied");

    create_dir(&allowed_subdir).unwrap();
    create_dir(&allowed_subdir_write).unwrap();
    create_dir(&denied_subdir).unwrap();

    extrasafe::SafetyContext::new()
        .enable(
            SystemIO::nothing()
                .allow_read_path(&allowed_subdir)
                .allow_list_dir(&allowed_subdir)
                .allow_create_in_dir(&allowed_subdir_write)
                .allow_list_dir(&allowed_subdir_write)
                .allow_read_path(&allowed_subdir_write)
                .allow_write_file(&allowed_subdir_write)
                .allow_remove_dir(&dir_allowed)
            ).unwrap()
        .apply_to_current_thread().unwrap();

    // create file in write dir
    let allowed_file = allowed_subdir_write.as_path().join("allowed.txt");
    let mut f = File::create(&allowed_file).unwrap();
    f.write_all(b"test allowed write directory").unwrap();
    drop(f);

    // check we can list ro directory
    let res = read_dir(&allowed_subdir);
    assert!(res.is_ok(), "Failed to list ro directory: {}", res.unwrap_err());
    let mut dir = res.unwrap();
    assert!(dir.next().is_none());

    // check we can list rw directory
    let res = read_dir(&allowed_subdir_write);
    assert!(res.is_ok(), "Failed to list rw directory: {}", res.unwrap_err());
    let dir = res.unwrap();
    assert_eq!(dir.collect::<Vec<_>>().len(), 1);

    // check we can remove ro directory (even though we can't write to it!)
    let res = remove_dir(&allowed_subdir);
    assert!(res.is_ok(), "Failed to remove ro directory: {}", res.unwrap_err());

    // check we can read file we wrote to
    can_read_file(&allowed_file, "test allowed write directory");

    // check we cannot remove "denied" subdirectory
    can_not_remove_dir(&denied_subdir);
}

#[test]
/// Test several landlock rules in the different `RuleSets`
fn test_landlock_different_rulesets() {
    let dir_allowed = tempfile::tempdir().unwrap();
    let dir_denied = tempfile::tempdir().unwrap();

    let allowed_subdir = dir_allowed.path().join("allowed_ro");
    let allowed_subdir_write = dir_allowed.path().join("allowed_write");
    let denied_subdir = dir_denied.path().join("denied");

    create_dir(&allowed_subdir).unwrap();
    create_dir(&allowed_subdir_write).unwrap();
    create_dir(&denied_subdir).unwrap();

    extrasafe::SafetyContext::new()
        .enable(
            SystemIO::nothing()
                .allow_list_dir(&allowed_subdir)
                .allow_read_path(&allowed_subdir)
                .allow_remove_dir(&dir_allowed)
                .allow_list_dir(&dir_allowed)
            ).unwrap()
        .enable(
            SystemIO::nothing()
                .allow_create_in_dir(&allowed_subdir_write)
                .allow_read_path(&allowed_subdir_write)
                .allow_write_file(&allowed_subdir_write)
            ).unwrap()
        .apply_to_current_thread().unwrap();

    // create file in write dir
    let allowed_file = allowed_subdir_write.as_path().join("allowed.txt");
    let mut f = File::create(&allowed_file).unwrap();
    f.write_all(b"test allowed write directory").unwrap();
    drop(f);

    // check we can list ro directory
    let res = read_dir(&allowed_subdir);
    assert!(res.is_ok(), "Failed to list ro directory: {}", res.unwrap_err());
    let mut dir = res.unwrap();
    assert!(dir.next().is_none());

    // check we can list rw directory
    let res = read_dir(&allowed_subdir_write);
    assert!(res.is_ok(), "Failed to list rw directory: {}", res.unwrap_err());
    let dir = res.unwrap();
    assert_eq!(dir.collect::<Vec<_>>().len(), 1);

    // check we can remove ro directory (even though we can't write to it!)
    let res = remove_dir(&allowed_subdir);
    assert!(res.is_ok(), "Failed to remove ro directory: {}", res.unwrap_err());

    // check we can read file we wrote to
    can_read_file(&allowed_file, "test allowed write directory");

    // check we cannot remove "denied" subdirectory
    can_not_remove_dir(&denied_subdir);
}

#[test]
/// Test extrasafe does not return an error when trying to use a nonexistant file with a landlock rule
fn test_nonexistant_file_no_error() {
    let dir = tempfile::tempdir().unwrap();
    let nonexistant = dir.path().join("bad");

    let res = extrasafe::SafetyContext::new()
        .enable(
            SystemIO::nothing()
                .allow_create_in_dir(nonexistant)
            ).unwrap()
        .landlock_only()
        .apply_to_current_thread();

    assert!(res.is_ok(), "Errored when passing nonexistant file to landlock rule: {:?} ", res.unwrap_err());
}

#[test]
/// Test extrasafe returns an error when trying to apply multiple rules to the same path
fn test_duplicate_path() {
    let dir = tempfile::tempdir().unwrap();

    let res = extrasafe::SafetyContext::new()
        .enable(
            SystemIO::nothing()
                .allow_create_in_dir(&dir)
            ).unwrap()
        .enable(
            SystemIO::nothing()
                .allow_create_in_dir(&dir)
            );

    assert!(res.is_err(), "Did not error on passing same dir in multiple rulesets");
    let err = res.unwrap_err();
    assert!(err.to_string().contains("The same path"));
    assert!(err.to_string().contains("was used in two different landlock rules."));
}
