//! Contains a [`RuleSet`] for allowing pipes

use crate::RuleSet;
use syscalls::Sysno;

/// [`Pipes`] allows you to create anonymous pipes for inter-process communication via the `pipe`
/// syscalls.
pub struct Pipes;
impl RuleSet for Pipes {
    fn simple_rules(&self) -> Vec<Sysno> {
        vec![Sysno::pipe, Sysno::pipe2]
    }

    fn name(&self) -> &'static str {
        "Pipes"
    }
}
