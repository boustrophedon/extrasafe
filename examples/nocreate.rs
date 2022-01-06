use std::fs::File;

fn main() {
    let res = extrasafe::SafetyContext::default_allow()
        .deny(extrasafe::SystemIO)
        .custom_policy(extrasafe::AllowStdout)
        .custom_policy(extrasafe::AllowStderr)
        .load();
    assert!(res.is_ok(), "extrasafe failed {:?}", res.unwrap_err());

    let res = File::create("should_fail.txt");
    assert!(res.is_err(), "creating file succeeded erroneously");
    assert!(false, "check err is eperm {:?}", res.unwrap_err());
}
