//! Allow various user ID related syscalls.

use {super::YesReally, crate::RuleSet, std::collections::BTreeSet, syscalls::Sysno};

/// Allow querying and modifying user IDs.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[must_use]
pub struct UserId {
    /// A set of permitted syscalls, added by various constructors and methods.
    syscalls: BTreeSet<Sysno>,
}

impl UserId {
    /// Construct a new rule, which allows everything:
    ///   Querying and modifying user IDs without restriction.
    pub fn everything() -> YesReally<Self> {
        Self::default().allow_everything()
    }

    /// Construct a new rule, which allows querying user IDs without restriction.
    pub fn get() -> Self {
        Self::default().allow_get()
    }

    /// Construct a new rule, which allows nothing.
    pub fn nothing() -> Self {
        Self::default()
    }

    /// Construct a new rule, which allows modifying user IDs without restriction.
    pub fn set() -> YesReally<Self> {
        Self::default().allow_set()
    }

    allow! {
        /// Allow modifying and querying user IDs without restriction.
        pub unsafe fn allow_everything() {
            /// Allow modifying user IDs without restriction.
            pub unsafe fn allow_set() {
                /// Allow modifying the user ID used for filesystem checks.
                pub unsafe fn allow_setfsuid(setfsuid);

                /// Allow modifying the real, effective and saved user ID.
                pub unsafe fn allow_setresuid(setresuid);

                /// Allow modifying the real and/or effective user ID.
                pub unsafe fn allow_setreuid(setreuid);

                /// Allow modifying the real user ID.
                pub unsafe fn allow_setuid(setuid);
            }

            /// Allow querying user IDs without restriction.
            pub fn allow_get() {
                /// Allow querying the effective user ID.
                pub fn allow_geteuid(geteuid);

                /// Allow querying the real, effective and saved user ID.
                pub fn allow_getresuid(getresuid);

                /// Allow querying the real user ID.
                pub fn allow_getuid(getuid);
            }
        }
    }
}

impl RuleSet for UserId {
    fn simple_rules(&self) -> Vec<Sysno> {
        self.syscalls.iter().cloned().collect()
    }

    fn name(&self) -> &'static str {
        "UserId"
    }
}

#[cfg(test)]
mod tests {
    use {super::UserId, crate::RuleSet as _, syscalls::Sysno};

    #[test]
    fn everything() {
        let rules = UserId::everything().yes_really();
        assert_eq!(rules.name(), "UserId");
        assert!(rules.conditional_rules().is_empty());

        let simple_rules = rules.simple_rules();
        assert_eq!(simple_rules.len(), 7);
        assert!(simple_rules.contains(&Sysno::geteuid));
        assert!(simple_rules.contains(&Sysno::getresuid));
        assert!(simple_rules.contains(&Sysno::getuid));
        assert!(simple_rules.contains(&Sysno::setfsuid));
        assert!(simple_rules.contains(&Sysno::setresuid));
        assert!(simple_rules.contains(&Sysno::setreuid));
        assert!(simple_rules.contains(&Sysno::setuid));
    }

    #[test]
    fn get() {
        let rules = UserId::get();
        assert_eq!(rules.name(), "UserId");
        assert!(rules.conditional_rules().is_empty());

        let simple_rules = rules.simple_rules();
        assert_eq!(simple_rules.len(), 3);
        assert!(simple_rules.contains(&Sysno::geteuid));
        assert!(simple_rules.contains(&Sysno::getresuid));
        assert!(simple_rules.contains(&Sysno::getuid));
    }

    #[test]
    fn set() {
        let rules = UserId::set().yes_really();
        assert_eq!(rules.name(), "UserId");
        assert!(rules.conditional_rules().is_empty());

        let simple_rules = rules.simple_rules();
        assert_eq!(simple_rules.len(), 4);
        assert!(simple_rules.contains(&Sysno::setfsuid));
        assert!(simple_rules.contains(&Sysno::setresuid));
        assert!(simple_rules.contains(&Sysno::setreuid));
        assert!(simple_rules.contains(&Sysno::setuid));
    }

    #[test]
    fn nothing() {
        let rules = UserId::nothing();
        assert_eq!(rules.name(), "UserId");
        assert!(rules.conditional_rules().is_empty());

        let simple_rules = rules.simple_rules();
        assert!(simple_rules.is_empty());
    }
}
