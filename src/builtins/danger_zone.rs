//! Contains a [`RuleSet`] for allowing syscalls that may be dangerous.

use std::collections::{HashMap, HashSet};

//use libseccomp::scmp_cmp;
use syscalls::Sysno;

use crate::{SeccompRule, RuleSet};

use super::YesReally;

// const CLONE_PARENT: u64 = libc::CLONE_PARENT as u64;
// const CLONE_THREAD: u64 = libc::CLONE_THREAD as u64;

/// Allows `clone` and `sleep` syscalls, which allow creating new threads and processes, and
/// pausing them.
///
/// # Security
/// This is in the danger zone not because it's dangerous but because it can be misused: Threads
/// do not provide isolation from each other. You can still access other threads' memory and
/// potentially get them to do operations that are not allowed in the current thread's seccomp
/// context.
#[must_use]
pub struct Threads {
    allowed: HashSet<Sysno>,
}

impl Threads {
    /// Create a new [`Threads`] ruleset with nothing allowed by default.
    pub fn nothing() -> Threads {
        Threads {
            allowed: HashSet::new(),
        }
    }

    /// Allow creating new threads and processes.
    pub fn allow_create(mut self) -> Threads {
        self.allowed.extend([Sysno::clone, Sysno::clone3]);

        self
    }

    /// Allow sleeping on the current thread
    ///
    /// # Security considerations
    /// An attacker with arbitrary code execution and access to a high resolution timer can mount
    /// timing attacks (e.g. spectre).
    pub fn allow_sleep(mut self) -> YesReally<Threads> {
        self.allowed
            .extend([Sysno::clock_nanosleep, Sysno::nanosleep]);

        YesReally::new(self)
    }
}

impl RuleSet for Threads {
    fn simple_rules(&self) -> Vec<Sysno> {
        self.allowed.iter().copied().collect()
    }

    fn conditional_rules(&self) -> HashMap<Sysno, Vec<SeccompRule>> {
        // let mut rules = HashMap::new();

        // let clone = SeccompRule::new(Sysno::clone)
        //     .and_condition(scmp_cmp!($arg2 & CLONE_THREAD == CLONE_THREAD));
        // rules.entry(Sysno::clone)
        //     .or_insert_with(Vec::new)
        //     .push(clone);

        // let clone3 = SeccompRule::new(Sysno::clone3)
        //     .and_condition(scmp_cmp!($arg2 & CLONE_THREAD == CLONE_THREAD));
        // rules.entry(Sysno::clone3)
        //     .or_insert_with(Vec::new)
        //     .push(clone3);

        // rules
        HashMap::new()
    }

    fn name(&self) -> &'static str {
        "Threads"
    }
}

/// [`ForkAndExec`] is in the danger zone because it can be used to start another process,
/// including more privileged ones. That process will still be under seccomp's restrictions (see
/// `tests/inherit_filters.rs`) but depending on your filter it could still do bad things.
///
/// Note that this also allows the `clone` syscall.
#[must_use]
pub struct ForkAndExec;
impl RuleSet for ForkAndExec {
    fn simple_rules(&self) -> Vec<Sysno> {
        vec![
             Sysno::fork, Sysno::vfork,
             Sysno::execve, Sysno::execveat,
             Sysno::wait4, Sysno::waitid,
             Sysno::clone, Sysno::clone3,
        ]
    }

    fn conditional_rules(&self) -> HashMap<Sysno, Vec<SeccompRule>> {
        // TODO: figure out if there's something reasonable we can do with this. same as with
        // Threads
        // let mut custom = HashMap::new();
        //
        // let clone = SeccompRule::new(Sysno::clone)
        //     .and_condition(scmp_cmp!($arg2 & CLONE_PARENT == CLONE_PARENT));
        // custom.entry(Sysno::clone)
        //     .or_insert_with(Vec::new)
        //     .push(clone);

        // let clone3 = SeccompRule::new(Sysno::clone3)
        //     .and_condition(scmp_cmp!($arg2 & CLONE_PARENT == CLONE_PARENT));
        // custom.entry(Sysno::clone3)
        //     .or_insert_with(Vec::new)
        //     .push(clone3);
        //
        // custom
        HashMap::new()
    }

    fn name(&self) -> &'static str {
        "ForkAndExec"
    }
}
