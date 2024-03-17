use extrasafe::syscalls::Sysno;
use extrasafe::*;

use std::collections::HashMap;

struct Seccomp;
impl RuleSet for Seccomp {
    fn simple_rules(&self) -> Vec<Sysno> {
        vec![Sysno::prctl, Sysno::seccomp]
    }
    fn conditional_rules(&self) -> HashMap<Sysno, Vec<SeccompRule>> {
        HashMap::new()
    }
    fn name(&self) -> &'static str {
        "seccomp"
    }
}

#[test]
/// You can apply multiple seccomp filters to a thread but the strictest rules win - so for
/// extrasafe, that means that only the intersection of all enabled rulesets will be enabled. So it
/// really doesn't ever make sense to enable multiple filters.
fn filter_stacking_works_but_may_give_unintended_results() {
    SafetyContext::new()
        .enable(
            builtins::SystemIO::nothing()
                .allow_stdout()
                .allow_stderr()
                .allow_open()
                .yes_really()
                .allow_metadata(),
        )
        .unwrap()
        .enable(Seccomp)
        .unwrap()
        .apply_to_current_thread()
        .unwrap();

    let res = SafetyContext::new()
        .enable(builtins::SystemIO::nothing().allow_stdout().allow_stderr())
        .unwrap()
        .enable(builtins::danger_zone::Threads::nothing().allow_create())
        .unwrap()
        .apply_to_current_thread();
    assert!(
        res.is_ok(),
        "Loading another seccomp filter after the first failed: {}",
        res.unwrap_err()
    );

    println!("test");
    let res = std::thread::Builder::new().spawn(|| println!("will not run"));
    assert!(res.is_err(), "Even though clone was enabled on the second filter, it was not in the first and so isn't allowed.");

    let res = std::fs::File::open("will_not_be_opened.txt");
    assert!(res.is_err(), "Even though opening files was enabled on the first filter, it was not in the second and so isn't allowed.");
}
