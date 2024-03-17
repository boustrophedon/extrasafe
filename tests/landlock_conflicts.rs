#![cfg(feature = "landlock")]

use std::fs::{read_dir, File};

use extrasafe::builtins::SystemIO;

#[test]
/// Prevent the user from using seccomp rules with argument filters on "open" syscalls and landlock
/// rules at the same time.
fn landlock_with_seccomp_arg_filters_fails() {
    let path = tempfile::tempdir().unwrap();

    // same ruleset
    let res = extrasafe::SafetyContext::new().enable(
        SystemIO::nothing()
            .allow_open_readonly()
            .allow_list_dir(&path),
    );

    assert!(
        res.is_err(),
        "Enabling filter succeeded with landlock and seccomp arg-restricted open"
    );
    // TODO: seccomp/landlock clash error reporting
    // let err = res.unwrap_err();
    // assert_eq!(err.to_string().contains("xxx"));

    // different rulesets, landlock first
    let res = extrasafe::SafetyContext::new()
        .enable(SystemIO::nothing().allow_open_readonly())
        .unwrap()
        .enable(SystemIO::nothing().allow_read_path(&path));

    assert!(
        res.is_err(),
        "Enabling filter succeeded with landlock and seccomp arg-restricted open"
    );
    // TODO: seccomp/landlock clash error reporting
    // let err = res.unwrap_err();
    // assert!(err.to_string().contains("xxx"));

    // different rulesets, seccomp first
    let res = extrasafe::SafetyContext::new()
        .enable(SystemIO::nothing().allow_read_path(&path))
        .unwrap()
        .enable(SystemIO::nothing().allow_open_readonly());

    assert!(
        res.is_err(),
        "Enabling filter succeeded with landlock and seccomp arg-restricted open"
    );
    // TODO: seccomp/landlock clash error reporting
    // let err = res.unwrap_err();
    // assert!(err.to_string().contains("xxx"));
}

#[test]
/// Test seccomp rules do not get applied when using the `landlock_only` flag
fn landlock_only() {
    // Test that it errors if no rules are applied
    let res = extrasafe::SafetyContext::new()
        .landlock_only()
        .apply_to_current_thread();

    assert!(
        res.is_err(),
        "extrasafe did not error when applying with no seccomp or landlock rules"
    );
    let err = res.unwrap_err();
    assert!(err.to_string().contains("No rules were enabled"));

    // now actually use a landlock rule
    let dir = tempfile::tempdir().unwrap();

    extrasafe::SafetyContext::new()
        .enable(SystemIO::nothing().allow_create_in_dir(&dir))
        .unwrap()
        .landlock_only()
        .apply_to_current_thread()
        .unwrap();

    // test that we can run arbitrary syscalls
    let pid = unsafe { libc::getpid() };
    assert!(pid > 0, "Pid was negative: {}", pid);

    // test that we can create in the given directory
    let file_path = dir.path().join("okay.txt");
    let file_res = File::create(file_path);
    assert!(
        file_res.is_ok(),
        "Failed to create file in allowed dir: {:?}",
        file_res.unwrap_err()
    );

    // test that we can't list paths
    let list_res = read_dir(&dir);
    assert!(
        list_res.is_err(),
        "Incorrectly succeeded in listing directory"
    );
    let list_res = read_dir("/etc");
    assert!(
        list_res.is_err(),
        "Incorrectly succeeded in listing directory"
    );
}
