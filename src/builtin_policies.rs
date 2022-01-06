pub struct SystemIO;

pub struct AllowStdout;
pub struct AllowStdin;
pub struct AllowStderr;

use seccomp::*;
use syscalls::Sysno;

use crate::{BasicPolicy, CustomPolicy};

impl BasicPolicy for SystemIO {
    fn syscalls(&self) -> Vec<Sysno> {
        vec![Sysno::read, Sysno::write, Sysno::readv, Sysno::writev,
        Sysno::preadv, Sysno::pwritev, Sysno::preadv2, Sysno::pwritev2,
        Sysno::open, Sysno::openat, Sysno::openat2]
    }
}

impl CustomPolicy for AllowStdin {
    fn rules(&self) -> Vec<Rule> {
        // TODO: allow other read syscalls
        let rule = Rule::new(Sysno::read.id() as usize,
            Compare::arg(0).with(0).using(Op::Ne).build(),
            Action::Errno(libc::EPERM));
       
        vec![rule]
    }
}

impl CustomPolicy for AllowStdout {
    fn rules(&self) -> Vec<Rule> {
        // TODO: allow other write syscalls
        let rule = Rule::new(Sysno::write.id() as usize,
            Compare::arg(0).with(1).using(Op::Ne).build(),
            Action::Errno(libc::EPERM));
       
        vec![rule]
    }
}

impl CustomPolicy for AllowStderr {
    fn rules(&self) -> Vec<Rule> {
        // TODO: allow other write syscalls
        let rule = Rule::new(Sysno::write.id() as usize,
            Compare::arg(0).with(2).using(Op::Ne).build(),
            Action::Errno(libc::EPERM));
       
        vec![rule]
    }
}
