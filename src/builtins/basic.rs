//! Contains a [`RuleSet`] for allowing base syscalls that all programs will need, and are not
//! dangerous for the most part.

use std::collections::HashMap;

use syscalls::Sysno;

use crate::{Rule, RuleSet};

/// A [`RuleSet`] allowing basic required syscalls to do things like allocate memory, and also a few that are used by
/// Rust to set up panic handling and segfault handlers.
pub struct BasicCapabilities;
impl RuleSet for BasicCapabilities {
    fn simple_rules(&self) -> Vec<Sysno> {
        vec![
            // If you want to constrain memory mapping and memory allocation, you probably want to
            // write your own seccomp filters at that point.
            Sysno::brk,
            Sysno::mmap,
            Sysno::munmap,
            Sysno::madvise,
            Sysno::mlock,
            Sysno::mlock2,
            Sysno::mlockall,
            // TODO these could maybe be in a separate capability
            Sysno::mprotect,
            Sysno::munlock,
            Sysno::munlockall,

            // Rust installs a signal handler to distinguish stack overflows from other faults
            // https://github.com/iximeow/rust/blob/master/src/libstd/sys/unix/stack_overflow.rs#L46
            // (I learned this by getting a segfault when not allowing sigaction/etc and then
            // googling rust sigaltstack and finding this issue
            // https://github.com/rust-lang/rust/issues/69533)
            Sysno::sigaltstack,
            Sysno::rt_sigaction,
            Sysno::rt_sigprocmask,
            Sysno::rt_sigreturn,

            // Futex management
            Sysno::futex,
            Sysno::get_robust_list,
            Sysno::set_robust_list,

            // Readlink isn't dangerous because you still need to be able to open the file to do
            // anything with the resolved name.
            #[cfg(target_arch = "x86_64")]
            Sysno::readlink,

            // Getpid/tid is fine.
            Sysno::getpid,
            Sysno::gettid,

            // Get kernel info
            Sysno::uname,

            // Could maybe put in a separate ruleset
            Sysno::getrandom,

            // Thread affinity and yield seems okay to put here but I could be convinced to put it
            // in the Multiprocessing ruleset. they probably should be there.
            Sysno::sched_getaffinity, Sysno::sched_setaffinity,
            Sysno::sched_yield,

            // rseq is used in newer glibc for some initialization purposes.
            // It's kind of complicated but does not appear to be dangerous.
            Sysno::rseq,

            // Exiting is probably fine.
            Sysno::exit,
            Sysno::exit_group,
        ]
    }

    fn conditional_rules(&self) -> HashMap<Sysno, Vec<Rule>> {
        HashMap::new()
    }

    fn name(&self) -> &'static str {
        "BasicCapabilities"
    }
}
