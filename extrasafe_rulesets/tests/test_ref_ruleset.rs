use extrasafe::RuleSet;
use extrasafe_rulesets::BasicRuleset;

#[test]
/// Test if `RuleSets` can be references.
fn ref_ruleset() -> Result<(), extrasafe::ExtraSafeError> {
    let ruleset: &dyn RuleSet = &BasicRuleset;
    extrasafe::SafetyContext::new().enable(ruleset)?.apply_to_current_thread()
}
