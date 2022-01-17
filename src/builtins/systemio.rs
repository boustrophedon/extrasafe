//! Contains a RuleSet for allowing IO-related syscalls.

use std::collections::{HashSet, HashMap};
use std::fs::File;
use std::os::unix::io::AsRawFd;

use libseccomp::*;
use syscalls::Sysno;

use crate::{RuleSet, Rule};

const IO_READ_SYSCALLS: &[Sysno] = &[Sysno::read, Sysno::readv, Sysno::preadv, Sysno::preadv2, Sysno::pread64, Sysno::lseek];
const IO_WRITE_SYSCALLS: &[Sysno] = &[Sysno::write, Sysno::writev, Sysno::pwritev, Sysno::pwritev2, Sysno::pwrite64,
                                      Sysno::fsync, Sysno::fdatasync, Sysno::lseek];
const IO_OPEN_SYSCALLS: &[Sysno] = &[Sysno::open, Sysno::openat, Sysno::openat2];
const IO_IOCTL_SYSCALLS: &[Sysno] = &[Sysno::ioctl, Sysno::fcntl];
// TODO: may want to separate fd-based and filename-based?
const IO_METADATA_SYSCALLS: &[Sysno] = &[Sysno::stat, Sysno::fstat, Sysno::newfstatat, Sysno::lstat, Sysno::statx];
const IO_CLOSE_SYSCALLS: &[Sysno] = &[Sysno::close, Sysno::close_range];

/// A RuleSet representing syscalls that perform IO - open/close/read/write/seek/stat.
///
/// Configurable to allow subsets of IO syscalls and specific fds.
pub struct SystemIO {
    /// Syscalls that are allowed
    allowed: HashSet<Sysno>,
    /// Syscalls that are allowed with custom rules, e.g. only allow to specific fds
    custom: HashMap<Sysno, Vec<Rule>>,
}

impl SystemIO {
    /// By default, allow no IO syscalls.
    pub fn nothing() -> SystemIO {
        SystemIO {
            allowed: HashSet::new(),
            custom: HashMap::new(),
        }
    }

    /// Allow all IO syscalls.
    pub fn everything() -> SystemIO {
        SystemIO::nothing()
            .allow_read()
            .allow_write()
            .allow_open()
            .allow_metadata()
            .allow_close()
    }



    /// Allow `read` syscalls.
    pub fn allow_read(mut self) -> SystemIO {
        self.allowed.extend(IO_READ_SYSCALLS);

        self
    }

    /// Allow `write` syscalls.
    pub fn allow_write(mut self) -> SystemIO {
        self.allowed.extend(IO_WRITE_SYSCALLS);

        self
    }

    /// Allow `open` syscalls.
    pub fn allow_open(mut self) -> SystemIO {
        self.allowed.extend(IO_OPEN_SYSCALLS);

        self
    }

    /// Allow `stat` syscalls.
    pub fn allow_metadata(mut self) -> SystemIO {
        self.allowed.extend(IO_METADATA_SYSCALLS);

        self
    }

    /// Allow `ioctl` and `fcntl` syscalls.
    pub fn allow_ioctl(mut self) -> SystemIO {
        self.allowed.extend(IO_IOCTL_SYSCALLS);

        self
    }

    /// Allow `close` syscalls.
    pub fn allow_close(mut self) -> SystemIO {
        self.allowed.extend(IO_CLOSE_SYSCALLS);

        self
    }

    /// Allow reading from stdin
    pub fn allow_stdin(mut self) -> SystemIO {
        let rule = Rule::new(Sysno::read)
            .and_condition(scmp_cmp!($arg0 == 0));
        self.custom.entry(Sysno::read)
            .or_insert_with(Vec::new)
            .push(rule);

        self
    }

    /// Allow writing to stdout
    pub fn allow_stdout(mut self) -> SystemIO {
        let rule = Rule::new(Sysno::write)
            .and_condition(scmp_cmp!($arg0 == 1));
        self.custom.entry(Sysno::write)
            .or_insert_with(Vec::new)
            .push(rule);

        self
    }

    /// Allow writing to stderr
    pub fn allow_stderr(mut self) -> SystemIO {
        let rule = Rule::new(Sysno::write)
            .and_condition(scmp_cmp!($arg0 == 2));
        self.custom.entry(Sysno::write)
            .or_insert_with(Vec::new)
            .push(rule);

        self
    }

    /// Allow reading a given open File. Note that with just this, you will not be able to close
    /// the file under this context. In most cases that shouldn't really matter since presumably
    /// you've opened it in a context that has open (and therefore close) capabilities.
    pub fn allow_file_read(mut self, file: &File) -> SystemIO {
        let fd = file.as_raw_fd();
        for &syscall in IO_READ_SYSCALLS {
            let rule = Rule::new(syscall)
                .and_condition(scmp_cmp!($arg0 == fd as u64));
            self.custom.entry(syscall)
                .or_insert_with(Vec::new)
                .push(rule);
        }
        for &syscall in IO_METADATA_SYSCALLS {
            let rule = Rule::new(syscall)
                .and_condition(scmp_cmp!($arg0 == fd as u64));
            self.custom.entry(syscall)
                .or_insert_with(Vec::new)
                .push(rule);
        }

        self
    }

    /// Allow writing to a given open File. Note that with just this, you will not be able to close
    /// the file under this context. In most cases that shouldn't really matter since presumably
    /// you've opened it in a context that has open (and therefore close) capabilities.
    pub fn allow_file_write(mut self, file: &File) -> SystemIO {
        let fd = file.as_raw_fd();
        let rule = Rule::new(Sysno::write)
            .and_condition(scmp_cmp!($arg0 == fd as u64));
        self.custom.entry(Sysno::write)
            .or_insert_with(Vec::new)
            .push(rule);

        self
    }
}

impl RuleSet for SystemIO {
    fn simple_rules(&self) -> Vec<syscalls::Sysno> {
        self.allowed.iter().copied().collect()
    }

    fn conditional_rules(&self) -> HashMap<syscalls::Sysno, Vec<Rule>> {
        self.custom.clone()
    }
    fn name(&self) -> &'static str {
        "SystemIO"
    }
}
