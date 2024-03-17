//! Contains a [`RuleSet`] for allowing time-related syscalls, but check the comments for why you
//! probably don't actually need to enable them.

use std::collections::HashSet;

use syscalls::Sysno;

use crate::RuleSet;

#[must_use]
/// Enable syscalls related to time.
pub struct Time {
    /// Syscalls that are allowed
    allowed: HashSet<Sysno>,
}

impl Time {
    /// Create a new Time [`RuleSet`] with nothing allowed by default.
    pub fn nothing() -> Time {
        Time {
            allowed: HashSet::new(),
        }
    }

    /// On most 64 bit systems glibc and musl both use the
    /// [`vDSO`](https://man7.org/linux/man-pages/man7/vdso.7.html) to compute the time directly with
    /// rdtsc rather than calling the `clock_gettime` syscall, so in most cases you don't need to
    /// actually enable this.
    pub fn allow_gettime(mut self) -> Time {
        self.allowed
            .extend([Sysno::clock_gettime, Sysno::clock_getres]);

        self
    }
}

impl RuleSet for Time {
    fn simple_rules(&self) -> Vec<Sysno> {
        self.allowed.iter().copied().collect()
    }

    fn name(&self) -> &'static str {
        "Time"
    }
}
