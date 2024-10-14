use {extrasafe::SafetyContext, extrasafe_rulesets::BasicRuleset};

#[test]
#[should_panic(expected = "should fail")]
#[allow(clippy::assertions_on_constants)]
/// Test that even if everything (besides default enabled syscalls) is denied with seccomp, tests can fail
/// This is also manually tested by commenting out the assert line and checking that the test
/// failure propagates to the cli
fn seccomp_active_tests_fail() {
    let res = SafetyContext::new()
        .enable(BasicRuleset)
        .unwrap()
        .apply_to_current_thread();
    assert!(res.is_ok(), "Extrasafe failed {:?}", res.unwrap_err());

    assert!(false, "should fail");
}
