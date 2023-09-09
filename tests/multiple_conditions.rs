use std::io::Write;

use extrasafe::*;

#[test]
/// Test that if multiple `RuleSets` have conditional rules, any of them will work i.e. they are
/// or-ed together across all `RuleSets`.
fn multiple_rulsets_conditional() {
    SafetyContext::new()
        .enable(builtins::SystemIO::nothing()
            .allow_stdout()
        ).unwrap()
        .enable(builtins::SystemIO::nothing()
            .allow_stderr()
        ).unwrap()
        .apply_to_current_thread().unwrap();

    let res = writeln!(std::io::stdout(), "we can print to stdout");
    assert!(res.is_ok(), "failed to write to stdout: {:?}", res.unwrap_err());
    let res = writeln!(std::io::stderr(), "we can print to stderr");
    assert!(res.is_ok(), "failed to write to stderr: {:?}", res.unwrap_err());
}
