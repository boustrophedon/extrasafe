use std::fs::File;
use std::io::Write;

fn main() {
    // create a safety context
    // enable no systemIO
    // but allow stdout and stderr

    println!("disabling IO-related syscalls...");
    let res = extrasafe::SafetyContext::new()
        .enable(
            extrasafe::builtins::SystemIO::nothing()
                .allow_stdout()
                .allow_stderr(),
        )
        .unwrap()
        .apply_to_all_threads();
    assert!(res.is_ok(), "extrasafe failed {:?}", res.unwrap_err());

    // -- opening files should fail
    let res = File::create("should_fail.txt");
    assert!(res.is_err(), "creating file succeeded erroneously");

    let err = res.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied,
        "Error is not EPERM {:?}",
        err
    );

    // -- but we allowed writing to stdout and stderr
    let res = writeln!(std::io::stdout(), "but we can still print to stdout!");
    assert!(
        res.is_ok(),
        "error writing to stdout: {:?}",
        res.unwrap_err()
    );

    let res = writeln!(std::io::stderr(), "and stderr!");
    assert!(
        res.is_ok(),
        "error writing to stderr: {:?}",
        res.unwrap_err()
    );
}

#[test]
fn run_main() {
    main()
}
