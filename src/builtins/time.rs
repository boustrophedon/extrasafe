//! Allow various time related syscalls.

use {super::YesReally, crate::RuleSet, std::collections::BTreeSet, syscalls::Sysno};

/// Allow querying and modifying time as well as sleeping.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd)]
#[must_use]
pub struct Time {
    /// A set of permitted syscalls, added by various constructors and methods.
    syscalls: BTreeSet<Sysno>,
}

impl Time {
    /// Construct a new rule, which allows everything:
    ///   Querying and modifying time as well as sleeping without restriction.
    pub fn everything() -> YesReally<Self> {
        Self::default().allow_everything()
    }

    /// Construct a new rule, which allows modifying time without restriction.
    pub fn modify() -> YesReally<Self> {
        Self::default().allow_modify()
    }

    /// Construct a new rule, which allows nothing.
    pub fn nothing() -> Self {
        Self::default()
    }

    /// Construct a new rule, which allows querying time without restriction.
    pub fn query() -> Self {
        Self::default().allow_query()
    }

    /// Construct a new rule, which allows querying and modifying time without restriction.
    pub fn query_and_modify() -> YesReally<Self> {
        Self::default().allow_query().allow_modify()
    }

    /// Construct a new rule, which allows querying time as well as sleeping without restriction.
    pub fn query_and_sleep() -> Self {
        Self::default().allow_query_and_sleep()
    }

    /// Construct a new rule, which allows sleeping without restriction.
    pub fn sleep() -> Self {
        Self::default().allow_sleep()
    }

    allow! {
        /// Allow querying and modifying time as well as sleeping without restriction.
        pub unsafe fn allow_everything() {
            /// Allow modifying time without restriction.
            pub unsafe fn allow_modify() {
                /// Allow the `adjtimex` syscall to tune a kernel clock.
                pub unsafe fn allow_adjtimex(adjtimex);

                /// Allow the `clock_adjtime` syscall to tune a kernel clock.
                pub unsafe fn allow_clock_adjtime(clock_adjtime);

                /// Allow the `clock_settime` syscall to set the time of a clock.
                pub unsafe fn allow_clock_settime(clock_settime);

                /// Allow the `settimeofday` syscall to set the time.
                pub unsafe fn allow_settimeofday(settimeofday);
            }

            /// Allow querying time and sleeping without restriction.
            pub fn allow_query_and_sleep() {
                /// Allow querying time without restriction.
                pub fn allow_query() {
                    /// On most 64 bit systems glibc and musl both use the
                    /// [`vDSO`](https://man7.org/linux/man-pages/man7/vdso.7.html) to compute the time directly with
                    /// rdtsc rather than calling the `clock_gettime` syscall, so in most cases you don't need to
                    /// actually enable this.
                    pub fn allow_gettime() {
                        /// Allow the `clock_getres` syscall to get the clock resolution.
                        pub fn allow_clock_getres(clock_getres);

                        /// Allow the `clock_gettime` syscall to get the time of a clock.
                        pub fn allow_clock_gettime(clock_gettime);
                    }

                    /// Allow the `gettimeofday` syscall to get the time.
                    pub fn allow_gettimeofday(gettimeofday);

                    /// Allow the `time` syscall to get the time in seconds.
                    pub fn allow_time(time);
                }

                /// Allow sleeping without restriction.
                pub fn allow_sleep() {
                    /// Allow the `clock_nanosleep` syscall.
                    pub fn allow_clock_nanosleep(clock_nanosleep);

                    /// Allow the `nanosleep` syscall.
                    pub fn allow_nanosleep(nanosleep);
                }
            }
        }
    }
}

impl RuleSet for Time {
    fn simple_rules(&self) -> Vec<Sysno> {
        self.syscalls.iter().cloned().collect()
    }

    fn name(&self) -> &'static str {
        "Time"
    }
}

#[cfg(test)]
mod tests {
    use {super::Time, crate::RuleSet as _, syscalls::Sysno};

    #[test]
    fn everything() {
        let rules = Time::everything().yes_really();
        assert_eq!(rules.name(), "Time");
        assert!(rules.conditional_rules().is_empty());

        let simple_rules = rules.simple_rules();
        assert_eq!(simple_rules.len(), 10);
        assert!(simple_rules.contains(&Sysno::adjtimex));
        assert!(simple_rules.contains(&Sysno::clock_adjtime));
        assert!(simple_rules.contains(&Sysno::clock_getres));
        assert!(simple_rules.contains(&Sysno::clock_gettime));
        assert!(simple_rules.contains(&Sysno::clock_nanosleep));
        assert!(simple_rules.contains(&Sysno::clock_settime));
        assert!(simple_rules.contains(&Sysno::gettimeofday));
        assert!(simple_rules.contains(&Sysno::nanosleep));
        assert!(simple_rules.contains(&Sysno::settimeofday));
        assert!(simple_rules.contains(&Sysno::time));
    }

    #[test]
    fn modify() {
        let rules = Time::modify().yes_really();
        assert_eq!(rules.name(), "Time");
        assert!(rules.conditional_rules().is_empty());

        let simple_rules = rules.simple_rules();
        assert_eq!(simple_rules.len(), 4);
        assert!(simple_rules.contains(&Sysno::adjtimex));
        assert!(simple_rules.contains(&Sysno::clock_adjtime));
        assert!(simple_rules.contains(&Sysno::clock_settime));
        assert!(simple_rules.contains(&Sysno::settimeofday));
    }

    #[test]
    fn nothing() {
        let rules = Time::nothing();
        assert_eq!(rules.name(), "Time");
        assert!(rules.conditional_rules().is_empty());

        let simple_rules = rules.simple_rules();
        assert!(simple_rules.is_empty());
    }

    #[test]
    fn query() {
        let rules = Time::query();
        assert_eq!(rules.name(), "Time");
        assert!(rules.conditional_rules().is_empty());

        let simple_rules = rules.simple_rules();
        assert_eq!(simple_rules.len(), 4);
        assert!(simple_rules.contains(&Sysno::clock_getres));
        assert!(simple_rules.contains(&Sysno::clock_gettime));
        assert!(simple_rules.contains(&Sysno::gettimeofday));
        assert!(simple_rules.contains(&Sysno::time));
    }

    #[test]
    fn query_and_modify() {
        let rules = Time::query_and_modify().yes_really();
        assert_eq!(rules.name(), "Time");
        assert!(rules.conditional_rules().is_empty());

        let simple_rules = rules.simple_rules();
        assert_eq!(simple_rules.len(), 8);
        assert!(simple_rules.contains(&Sysno::adjtimex));
        assert!(simple_rules.contains(&Sysno::clock_adjtime));
        assert!(simple_rules.contains(&Sysno::clock_getres));
        assert!(simple_rules.contains(&Sysno::clock_gettime));
        assert!(simple_rules.contains(&Sysno::clock_settime));
        assert!(simple_rules.contains(&Sysno::gettimeofday));
        assert!(simple_rules.contains(&Sysno::settimeofday));
        assert!(simple_rules.contains(&Sysno::time));
    }

    #[test]
    fn query_and_sleep() {
        let rules = Time::query_and_sleep();
        assert_eq!(rules.name(), "Time");
        assert!(rules.conditional_rules().is_empty());

        let simple_rules = rules.simple_rules();
        assert_eq!(simple_rules.len(), 6);
        assert!(simple_rules.contains(&Sysno::clock_getres));
        assert!(simple_rules.contains(&Sysno::clock_gettime));
        assert!(simple_rules.contains(&Sysno::clock_nanosleep));
        assert!(simple_rules.contains(&Sysno::gettimeofday));
        assert!(simple_rules.contains(&Sysno::nanosleep));
        assert!(simple_rules.contains(&Sysno::time));
    }

    #[test]
    fn sleep() {
        let rules = Time::sleep();
        assert_eq!(rules.name(), "Time");
        assert!(rules.conditional_rules().is_empty());

        let simple_rules = rules.simple_rules();
        assert_eq!(simple_rules.len(), 2);
        assert!(simple_rules.contains(&Sysno::clock_nanosleep));
        assert!(simple_rules.contains(&Sysno::nanosleep));
    }
}
