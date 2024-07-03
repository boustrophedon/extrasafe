//! Allow netlink-sockets.

use {
    crate::{
        RuleSet, SeccompArgumentFilter as Filter, SeccompRule as Rule,
        SeccompilerComparator as Comparator,
    },
    std::collections::HashMap,
    syscalls::Sysno,
};

/// Allow the syscall `socket` to open a netlink-socket.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd)]
#[must_use]
pub struct Netlink;

impl RuleSet for Netlink {
    fn simple_rules(&self) -> Vec<Sysno> {
        Vec::default()
    }

    #[allow(clippy::as_conversions)]
    fn conditional_rules(&self) -> HashMap<Sysno, Vec<Rule>> {
        /// `AF_NETLINK` as `u64`.
        const AF_NETLINK: u64 = libc::AF_NETLINK as u64;

        /// `SOCK_RAW` as `u64`.
        const SOCK_RAW: u64 = libc::SOCK_RAW as u64;

        let rule = Rule::new(Sysno::socket)
            .and_condition(Filter::new(0, Comparator::MaskedEq(AF_NETLINK), AF_NETLINK))
            .and_condition(Filter::new(1, Comparator::MaskedEq(SOCK_RAW), SOCK_RAW));
        HashMap::from([(Sysno::socket, Vec::from([rule]))])
    }

    fn name(&self) -> &'static str {
        "Netlink"
    }
}

#[cfg(test)]
mod tests {
    use {super::Netlink, crate::RuleSet as _, syscalls::Sysno};

    #[test]
    fn name() {
        assert_eq!(Netlink.name(), "Netlink");
    }

    #[test]
    fn simple_rules() {
        let rules = Netlink.simple_rules();
        assert!(rules.is_empty());
    }

    #[test]
    fn conditional_rules() {
        let rules = Netlink.conditional_rules();
        assert_eq!(rules.len(), 1);
        assert!(rules.contains_key(&Sysno::socket));
    }
}
