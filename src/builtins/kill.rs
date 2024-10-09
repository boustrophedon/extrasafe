//! Allow `sys_kill`.

use {crate::RuleSet, syscalls::Sysno};

/// Allow the syscall `kill` to send signals to other processes.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd)]
#[must_use]
pub struct Kill;

impl RuleSet for Kill {
    fn simple_rules(&self) -> Vec<Sysno> {
        Vec::from([Sysno::kill])
    }

    fn name(&self) -> &'static str {
        "Kill"
    }
}

#[cfg(test)]
mod tests {
    use {super::Kill, crate::RuleSet as _, syscalls::Sysno};

    #[test]
    fn name() {
        assert_eq!(Kill.name(), "Kill");
    }

    #[test]
    fn simple_rules() {
        let rules = Kill.simple_rules();
        assert_eq!(rules.len(), 1);
        assert!(rules.contains(&Sysno::kill));
    }

    #[test]
    fn conditional_rules() {
        assert!(Kill.conditional_rules().is_empty());
    }
}
