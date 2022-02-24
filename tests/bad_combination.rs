use extrasafe::builtins::SystemIO;
use extrasafe::*;
use syscalls::Sysno;

use std::collections::HashMap;

struct JustWrite;
impl RuleSet for JustWrite {
    fn simple_rules(&self) -> Vec<Sysno> {
        vec![Sysno::write]
    }

    fn conditional_rules(&self) -> HashMap<Sysno, Vec<Rule>> {
        HashMap::new()
    }

    fn name(&self) -> &'static str {
        "JustWrite"
    }
}

#[test]
/// Check that adding a simple rule and a conditional rule with the same sysno fails.
/// (This is because the simple rule would override the conditional one)
fn invalid_combination_new_simple() {
    let res = extrasafe::SafetyContext::new()
        .enable(SystemIO::nothing()
            .allow_stdout()).unwrap()
        .enable(SystemIO::everything());

    assert!(
        res.is_err(),
        "Extrasafe didn't fail when adding conflicting rules"
    );

    let err = res.unwrap_err();
    assert_eq!(err.to_string(), "A conditional rule on syscall `write` from RuleSet `SystemIO` would be overridden by a simple rule from RuleSet `SystemIO`.");
}

#[test]
fn invalid_combination_new_conditional() {
    let res = extrasafe::SafetyContext::new()
        .enable(SystemIO::everything()).unwrap()
        .enable(SystemIO::nothing()
            .allow_stdout());
    assert!(res.is_err(), "Extrasafe didn't fail when adding conflicting rules");

    let err = res.unwrap_err();
    assert_eq!(err.to_string(), "A conditional rule on syscall `write` from RuleSet `SystemIO` would be overridden by a simple rule from RuleSet `SystemIO`.");
}

#[test]
/// same as above but with different rulesets to check the error message
fn invalid_combination_new_simple_different_name() {
    let res = extrasafe::SafetyContext::new()
        .enable(SystemIO::nothing()
            .allow_stdout()).unwrap()
        .enable(JustWrite);
    assert!(
        res.is_err(),
        "Extrasafe didn't fail when adding conflicting rules"
    );

    let err = res.unwrap_err();
    assert_eq!(err.to_string(), "A conditional rule on syscall `write` from RuleSet `SystemIO` would be overridden by a simple rule from RuleSet `JustWrite`.");
}

#[test]
fn invalid_combination_new_conditional_different_name() {
    let res = extrasafe::SafetyContext::new()
        .enable(JustWrite).unwrap()
        .enable(SystemIO::nothing()
            .allow_stdout());
    assert!(res.is_err(), "Extrasafe didn't fail when adding conflicting rules");

    let err = res.unwrap_err();
    assert_eq!(err.to_string(), "A conditional rule on syscall `write` from RuleSet `SystemIO` would be overridden by a simple rule from RuleSet `JustWrite`.");
}
