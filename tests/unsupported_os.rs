#[cfg(not(target_os = "linux"))]
#[test]
fn returns_unsupported_os_error() {
    let res = extrasafe::SafetyContext::new().apply_to_all_threads();

    assert!(
        res.is_err(),
        "Succeeded in starting safety context on non-linux"
    );

    let err = res.unwrap_err();
    assert_eq!(err, extrasafe::Error::UnsupportedOs);
}
