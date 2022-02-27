use extrasafe::{SafetyContext, builtins};
use builtins::{danger_zone::Time, SystemIO};

#[test]
fn call_main() {
    main();
}

fn main() {
    SafetyContext::new()
        .enable(
            SystemIO::nothing()
                .allow_stdout()
        ).unwrap()

        // Note that this doesn't really have an effect when using glibc, see comment on Time
        // ruleset
        .enable(
            Time::nothing()
                .allow_gettime()
        ).unwrap()
        .apply_to_current_thread().unwrap();

    let time = std::time::SystemTime::now();
    println!("time gave us: {:#?}", time);
}
