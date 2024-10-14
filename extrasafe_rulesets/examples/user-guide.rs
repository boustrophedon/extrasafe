use {
    extrasafe::{seccomp_arg_filter, RuleSet, SeccompRule, syscalls::Sysno, SafetyContext},
    extrasafe_rulesets::{Networking, SystemIO},
    std::{collections::HashMap, fs::File, thread::spawn},
};

#[cfg(feature = "landlock")]
use {
    std::net::UdpSocket,
    tempfile::tempdir,
};

fn simple_example() {
    let ctx = SafetyContext::new();
    let ctx = ctx
        .enable(SystemIO::nothing().allow_open_readonly())
        .expect("Failed to add systemio ruleset to context")
        // The Networking RuleSet includes both read and write, but our files will be opened
        // readonly so we can't actually write to them.  We can still write to stdout and stderr
        // though.
        .enable(
            Networking::nothing()
                .allow_start_tcp_clients()
                .allow_running_tcp_clients(),
        )
        .expect("Failed to add networking ruleset to context");
    ctx.apply_to_current_thread()
        .expect("Failed to apply seccomp filters");

    assert!(File::create("/tmp/a_file").is_err());
}

fn custom_ruleset() {
    struct MyRuleSet;

    impl RuleSet for MyRuleSet {
        fn simple_rules(&self) -> Vec<Sysno> {
            // literally reboot the computer
            vec![Sysno::reboot]
        }

        fn conditional_rules(&self) -> HashMap<Sysno, Vec<SeccompRule>> {
            // Only allow the creation of stream (tcp) sockets
            const SOCK_STREAM: u64 = libc::SOCK_STREAM as u64;

            let rule = SeccompRule::new(Sysno::socket)
                .and_condition(seccomp_arg_filter!(arg0 & SOCK_STREAM == SOCK_STREAM));
            HashMap::from([(Sysno::socket, vec![rule])])
        }

        fn name(&self) -> &'static str {
            "MyRuleSet"
        }
    }

    SafetyContext::new()
        .enable(MyRuleSet)
        .unwrap()
        .apply_to_current_thread()
        .unwrap();
}

#[cfg(feature = "landlock")]
fn with_landlock() {
    let tmp_dir_allow = tempdir().unwrap().into_path();
    let tmp_dir_deny = tempdir().unwrap().into_path();

    SafetyContext::new()
        .enable(
            SystemIO::nothing()
                .allow_create_in_dir(&tmp_dir_allow)
                .allow_write_file(&tmp_dir_allow),
        )
        .unwrap()
        .apply_to_current_thread()
        .unwrap();

    // Opening arbitrary files now fails!
    let res = File::create(tmp_dir_deny.join("evil.txt"));
    assert!(res.is_err());

    // But the directory we allowed works
    let res = File::create(tmp_dir_allow.join("my_output.txt"));
    assert!(res.is_ok());

    println!("printing to stdout is also allowed");
    eprintln!("because read/write syscalls are unrestricted");

    // And other syscalls are still disallowed
    let res = UdpSocket::bind("127.0.0.1:0");
    assert!(res.is_err());
}

fn main() {
    spawn(simple_example).join().unwrap();
    spawn(custom_ruleset).join().unwrap();
    #[cfg(feature = "landlock")]
    spawn(with_landlock).join().unwrap();
}

#[test]
fn run_main() {
    main()
}
