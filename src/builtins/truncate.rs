//! Allow `sys_truncate` and `sys_ftruncate`.

use {crate::RuleSet, syscalls::Sysno};

/// Allow the syscalls `truncate` and `ftruncate` to truncate files.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd)]
#[must_use]
pub struct Truncate;

impl RuleSet for Truncate {
    fn simple_rules(&self) -> Vec<Sysno> {
        Vec::from([Sysno::truncate, Sysno::ftruncate])
    }

    fn name(&self) -> &'static str {
        "Truncate"
    }
}

#[cfg(test)]
mod tests {
    use {super::Truncate, crate::RuleSet as _, syscalls::Sysno};

    #[test]
    fn name() {
        assert_eq!(Truncate.name(), "Truncate");
    }

    #[test]
    fn simple_rules() {
        let rules = Truncate.simple_rules();
        assert_eq!(rules.len(), 2);
        assert!(rules.contains(&Sysno::truncate));
        assert!(rules.contains(&Sysno::ftruncate));
    }

    #[test]
    fn conditional_rules() {
        assert!(Truncate.conditional_rules().is_empty());
    }
}
