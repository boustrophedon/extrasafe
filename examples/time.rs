use extrasafe::{SafetyContext, builtins};
use builtins::{Time, SystemIO};

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

        // On most systems this won't have an effect because glibc and musl both use vDSOs that
        // compute time directly via rdtsc rather than calling the syscalls directly.
        .enable(
            Time::nothing()
                .allow_gettime()
        ).unwrap()
        .apply_to_current_thread().unwrap();

    let time = std::time::SystemTime::now();
    println!("time gave us: {:#?}", time);
}
