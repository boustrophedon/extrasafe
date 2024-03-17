#![cfg(feature = "landlock")]

use extrasafe::builtins::SystemIO;

#[test]
/// Landlock currently only supports being applied to the current thread (and child threads).
/// Make sure we error if user tries to use landlock with `SafetyContex::apply_to_all_threads`
fn test_landlock_apply_to_all_fails() {
    let dir = tempfile::tempdir().unwrap();

    let res = extrasafe::SafetyContext::new()
        .enable(SystemIO::nothing().allow_read_path(&dir))
        .unwrap()
        .landlock_only()
        .apply_to_all_threads();

    assert!(
        res.is_err(),
        "Did not error when applying to all threads with landlock rules"
    );
    assert!(res
        .unwrap_err()
        .to_string()
        .contains("Landlock does not support syncing to all threads"));
}
