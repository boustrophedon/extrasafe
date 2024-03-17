use extrasafe::builtins::BasicCapabilities;
use extrasafe::RuleSet;

#[test]
/// Test if `RuleSets` can be references.
fn ref_ruleset() -> Result<(), extrasafe::ExtraSafeError> {
    let ruleset: &dyn RuleSet = &BasicCapabilities;
    extrasafe::SafetyContext::new()
        .enable(ruleset)?
        .apply_to_current_thread()
}
