//! Allow `sys_socketpair`.

use {crate::RuleSet, syscalls::Sysno};

/// Allow the syscall `socketpair` to create a pair of connected sockets.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd)]
#[must_use]
pub struct SocketPair;

impl RuleSet for SocketPair {
    fn simple_rules(&self) -> Vec<Sysno> {
        Vec::from([Sysno::socketpair])
    }

    fn name(&self) -> &'static str {
        "SocketPair"
    }
}

#[cfg(test)]
mod tests {
    use {super::SocketPair, crate::RuleSet as _, syscalls::Sysno};

    #[test]
    fn name() {
        assert_eq!(SocketPair.name(), "SocketPair");
    }

    #[test]
    fn simple_rules() {
        let rules = SocketPair.simple_rules();
        assert_eq!(rules.len(), 1);
        assert!(rules.contains(&Sysno::socketpair));
    }

    #[test]
    fn conditional_rules() {
        assert!(SocketPair.conditional_rules().is_empty());
    }
}
