//! Tests that demonstrate seccomp filters are inherited by child processes.

use extrasafe::builtins::danger_zone::{ForkAndExec, Threads};
use extrasafe::SafetyContext;

#[test]
/// Enable seccomp *only on this thread*, create a new thread, try to create a file and check that
/// it fails.
fn new_thread_inherits_restrictions() {
    SafetyContext::new()
        .enable(Threads::nothing().allow_create())
        .unwrap()
        .apply_to_current_thread()
        .unwrap();

    let handle = std::thread::spawn(|| {
        let res = std::fs::File::create("/tmp/will_not_work.txt");
        assert!(res.is_err(), "Incorrectly succeeded in creating file");

        let err = res.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    });

    let res = handle.join();
    assert!(
        res.is_ok(),
        "Error during file io test thread: {:?}",
        res.unwrap_err()
    );
}

#[test]
/// Enable seccomp *only on this thread*, fork and exec a new process, try to cat a file and
/// check that it fails.
fn new_process_inherits_restrictions() {
    SafetyContext::new()
        .enable(ForkAndExec)
        .unwrap()
        .apply_to_current_thread()
        .unwrap();

    // Note that this actually fails not because of the cat but because the new process is not even
    // allowed to open ld or glibc
    let res = std::process::Command::new("cat")
        .arg("/proc/cpuinfo")
        .status();
    assert!(
        res.is_ok(),
        "Error spawning child process: {:?}",
        res.unwrap_err()
    );

    let status = res.unwrap();
    assert!(!status.success(), "Child process suceeded incorrectly.");
}
