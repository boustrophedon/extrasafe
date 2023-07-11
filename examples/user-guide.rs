fn simple_example() {
    use extrasafe::builtins::{SystemIO, Networking};

    let ctx = extrasafe::SafetyContext::new();
    let ctx = ctx
        .enable(
            SystemIO::nothing()
                .allow_open_readonly()
            ).expect("Failed to add systemio ruleset to context")
        // The Networking RuleSet includes both read and write, but our files will be opened
        // readonly so we can't actually write to them.  We can still write to stdout and stderr
        // though.
        .enable(
            Networking::nothing()
                .allow_start_tcp_clients()
                .allow_running_tcp_clients()
            ).expect("Failed to add networking ruleset to context");
    ctx.apply_to_current_thread()
        .expect("Failed to apply seccomp filters");

    assert!(std::fs::File::create("/tmp/a_file").is_err());
}

fn custom_ruleset() {
    use extrasafe::{Rule, RuleSet};
    use extrasafe::syscalls::Sysno;
    use libseccomp::scmp_cmp;

    use std::collections::HashMap;

    struct MyRuleSet;

    impl RuleSet for MyRuleSet {
        fn simple_rules(&self) -> Vec<Sysno> {
            // literally reboot the computer
            vec![Sysno::reboot]
        }

        fn conditional_rules(&self) -> HashMap<Sysno, Vec<Rule>> {
            // Only allow the creation of stream (tcp) sockets
            const SOCK_STREAM: u64 = libc::SOCK_STREAM as u64;

            let rule = Rule::new(Sysno::socket)
                .and_condition(
                    scmp_cmp!($arg0 & SOCK_STREAM == SOCK_STREAM));
            HashMap::from([
                (Sysno::socket, vec![rule,])
            ])
        }

        fn name(&self) -> &'static str {
            "MyRuleSet"
        }
    }

    extrasafe::SafetyContext::new()
        .enable(MyRuleSet).unwrap()
        .apply_to_current_thread().unwrap();
}

fn main() {
    std::thread::spawn(simple_example).join().unwrap();
    std::thread::spawn(custom_ruleset).join().unwrap();
}

#[test]
fn run_main() {
    main()
}
