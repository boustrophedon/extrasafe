//! Contains a [`RuleSet`] for allowing IO-related syscalls, like file opening, reading, and writing.

use std::collections::{HashSet, HashMap};
use std::fs::File;
use std::os::unix::io::AsRawFd;

use libseccomp::*;
use syscalls::Sysno;

use crate::{RuleSet, Rule};
use super::YesReally;

const IO_READ_SYSCALLS: &[Sysno] = &[Sysno::read, Sysno::readv, Sysno::preadv, Sysno::preadv2, Sysno::pread64, Sysno::lseek];
const IO_WRITE_SYSCALLS: &[Sysno] = &[Sysno::write, Sysno::writev, Sysno::pwritev, Sysno::pwritev2, Sysno::pwrite64,
                                      Sysno::fsync, Sysno::fdatasync, Sysno::lseek];
const IO_OPEN_SYSCALLS: &[Sysno] = &[Sysno::open, Sysno::openat, Sysno::openat2];
const IO_IOCTL_SYSCALLS: &[Sysno] = &[Sysno::ioctl, Sysno::fcntl];
// TODO: may want to separate fd-based and filename-based?
const IO_METADATA_SYSCALLS: &[Sysno] = &[Sysno::stat, Sysno::fstat, Sysno::newfstatat,
                                         Sysno::lstat, Sysno::statx,
                                         Sysno::getdents, Sysno::getdents64,
                                         Sysno::getcwd];
const IO_CLOSE_SYSCALLS: &[Sysno] = &[Sysno::close, Sysno::close_range];

/// A [`RuleSet`] representing syscalls that perform IO - open/close/read/write/seek/stat.
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
    #[must_use]
    pub fn nothing() -> SystemIO {
        SystemIO {
            allowed: HashSet::new(),
            custom: HashMap::new(),
        }
    }

    /// Allow all IO syscalls.
    #[must_use]
    pub fn everything() -> SystemIO {
        SystemIO::nothing()
            .allow_read()
            .allow_write()
            .allow_open().yes_really()
            .allow_metadata()
            .allow_close()
    }



    /// Allow `read` syscalls.
    #[must_use]
    pub fn allow_read(mut self) -> SystemIO {
        self.allowed.extend(IO_READ_SYSCALLS);

        self
    }

    /// Allow `write` syscalls.
    #[must_use]
    pub fn allow_write(mut self) -> SystemIO {
        self.allowed.extend(IO_WRITE_SYSCALLS);

        self
    }

    /// Allow `open` syscalls.
    ///
    /// # Security
    ///
    /// The reason this function returns a [`YesReally`] is because it's easy to accidentally combine
    /// it with another ruleset that allows `write` - for example the Network ruleset - even if you
    /// only want to read files.
    #[must_use]
    pub fn allow_open(mut self) -> YesReally<SystemIO> {
        self.allowed.extend(IO_OPEN_SYSCALLS);

        YesReally::new(self)
    }

    /// Allow `open` syscalls but not with write flags.
    ///
    /// Note that the `openat2` syscall (which is not exposed by glibc anyway according to the
    /// syscall manpage, and so probably isn't very common) is not supported here because it has a
    /// separate configuration struct instead of a flag bitset.
    #[must_use]
    pub fn allow_open_readonly(mut self) -> SystemIO {
        const O_WRONLY: u64 = libc::O_WRONLY as u64;
        const O_RDWR: u64 = libc::O_RDWR as u64;
        const O_APPEND: u64 = libc::O_APPEND as u64;
        const O_CREAT: u64 = libc::O_CREAT as u64;
        const O_EXCL: u64 = libc::O_EXCL as u64;
        // TMPFILE causes problems because it's defined as __O_TMPFILE | O_DIRECTORY
        // i.e. just the tmpfile bit or the o_directory bit. O_DIRECTORY by itself is fine because
        // it just causse the open to fail if it's a directory. however the manpage states that
        // WRONLY or RDWR is required for O_TMPFILE so we're fine to leave it out anyway.
        // const O_TMPFILE: u64 = libc::O_TMPFILE as u64;

        const WRITECREATE: u64 = O_WRONLY | O_RDWR | O_APPEND | O_CREAT | O_EXCL;// | O_TMPFILE;

        // flags are the second argument for open but the third for openat
        let rule = Rule::new(Sysno::open)
            .and_condition(scmp_cmp!($arg1 & WRITECREATE == 0));
        self.custom.entry(Sysno::open)
            .or_insert_with(Vec::new)
            .push(rule);

        let rule = Rule::new(Sysno::openat)
            .and_condition(scmp_cmp!($arg2 & WRITECREATE == 0));
        self.custom.entry(Sysno::openat)
            .or_insert_with(Vec::new)
            .push(rule);

        self
    }

    /// Allow `stat` syscalls.
    #[must_use]
    pub fn allow_metadata(mut self) -> SystemIO {
        self.allowed.extend(IO_METADATA_SYSCALLS);

        self
    }

    /// Allow `ioctl` and `fcntl` syscalls.
    #[must_use]
    pub fn allow_ioctl(mut self) -> SystemIO {
        self.allowed.extend(IO_IOCTL_SYSCALLS);

        self
    }

    /// Allow `close` syscalls.
    #[must_use]
    pub fn allow_close(mut self) -> SystemIO {
        self.allowed.extend(IO_CLOSE_SYSCALLS);

        self
    }

    /// Allow reading from stdin
    #[must_use]
    pub fn allow_stdin(mut self) -> SystemIO {
        let rule = Rule::new(Sysno::read)
            .and_condition(scmp_cmp!($arg0 == 0));
        self.custom.entry(Sysno::read)
            .or_insert_with(Vec::new)
            .push(rule);

        self
    }

    /// Allow writing to stdout
    #[must_use]
    pub fn allow_stdout(mut self) -> SystemIO {
        let rule = Rule::new(Sysno::write)
            .and_condition(scmp_cmp!($arg0 == 1));
        self.custom.entry(Sysno::write)
            .or_insert_with(Vec::new)
            .push(rule);

        self
    }

    /// Allow writing to stderr
    #[must_use]
    pub fn allow_stderr(mut self) -> SystemIO {
        let rule = Rule::new(Sysno::write)
            .and_condition(scmp_cmp!($arg0 == 2));
        self.custom.entry(Sysno::write)
            .or_insert_with(Vec::new)
            .push(rule);

        self
    }

    /// Allow reading a given open [File]. Note that with just this function, you will not be able
    /// to close the file under this context.
    ///
    /// # Security considerations
    ///
    /// If another file or socket is opened after the file provided to this function is closed,
    /// it's possible that the fd will be reused and therefore may be read from.
    #[must_use]
    pub fn allow_file_read(mut self, file: &File) -> SystemIO {
        let fd = file.as_raw_fd();
        for &syscall in IO_READ_SYSCALLS {
            let rule = Rule::new(syscall)
                .and_condition(scmp_cmp!($arg0 == fd.try_into().expect("fd provided was negative")));
            self.custom.entry(syscall)
                .or_insert_with(Vec::new)
                .push(rule);
        }
        for &syscall in IO_METADATA_SYSCALLS {
            let rule = Rule::new(syscall)
                .and_condition(scmp_cmp!($arg0 == fd.try_into().expect("fd provided was negative")));
            self.custom.entry(syscall)
                .or_insert_with(Vec::new)
                .push(rule);
        }

        self
    }

    /// Allow writing to a given open [File]. Note that with just this, you will not be able to
    /// close the file under this context.
    ///
    /// # Security considerations
    ///
    /// If another file or socket is opened after the file provided to this function is closed,
    /// it's possible that the fd will be reused and therefore may be written to.
    #[must_use]
    pub fn allow_file_write(mut self, file: &File) -> SystemIO {
        let fd = file.as_raw_fd();
        let rule = Rule::new(Sysno::write)
            .and_condition(scmp_cmp!($arg0 == fd.try_into().expect("fd provided was negative")));
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
