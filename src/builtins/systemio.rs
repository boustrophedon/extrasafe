//! Contains a [`RuleSet`] for allowing IO-related syscalls, like file opening, reading, and writing.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::unix::io::AsRawFd;

#[cfg(feature = "landlock")]
use std::path::{Path, PathBuf};

use crate::syscalls::Sysno;

#[cfg(feature = "landlock")]
use crate::landlock::{access, AccessFs, BitFlags};
#[cfg(feature = "landlock")]
use crate::LandlockRule;

use super::YesReally;
use crate::{RuleSet, SeccompRule};

pub(crate) const IO_READ_SYSCALLS: &[Sysno] = &[
    Sysno::read,
    Sysno::readv,
    Sysno::preadv,
    Sysno::preadv2,
    Sysno::pread64,
    Sysno::lseek,
];
pub(crate) const IO_WRITE_SYSCALLS: &[Sysno] = &[
    Sysno::write,
    Sysno::writev,
    Sysno::pwritev,
    Sysno::pwritev2,
    Sysno::pwrite64,
    Sysno::fsync,
    Sysno::fdatasync,
    Sysno::lseek,
];
pub(crate) const IO_OPEN_SYSCALLS: &[Sysno] = &[
    #[cfg(enabled_arch = "x86_64")]
    Sysno::open,
    Sysno::openat,
    Sysno::openat2
];
pub(crate) const IO_IOCTL_SYSCALLS: &[Sysno] = &[Sysno::ioctl, Sysno::fcntl];
// TODO: may want to separate fd-based and filename-based?
pub(crate) const IO_METADATA_SYSCALLS: &[Sysno] = &[
    #[cfg(enabled_arch = "x86_64")]
    Sysno::stat,
    Sysno::fstat,
    #[cfg(enabled_arch = "x86_64")]
    Sysno::newfstatat,
    #[cfg(any(enabled_arch = "aarch64", enabled_arch = "riscv64"))]
    Sysno::fstatat,
    #[cfg(enabled_arch = "x86_64")]
    Sysno::lstat,
    Sysno::statx,
    #[cfg(enabled_arch = "x86_64")]
    Sysno::getdents,
    Sysno::getdents64,
    Sysno::getcwd,
];
pub(crate) const IO_CLOSE_SYSCALLS: &[Sysno] = &[Sysno::close, Sysno::close_range];
pub(crate) const IO_UNLINK_SYSCALLS: &[Sysno] = &[
    #[cfg(enabled_arch = "x86_64")]
    Sysno::unlink,
    Sysno::unlinkat
];

// TODO: split into SystemIO, SystemIOLandlock, SystemIOSeccompRestricted so that you can't call a
// landlock function after using a seccomp argument filter function (or vice versa). You can still
// do it in separate .enable() calls so it doesn't make that big a difference but it would be nice
// to have.

/// A [`RuleSet`] representing syscalls that perform IO - open/close/read/write/seek/stat.
///
/// Configurable to allow subsets of IO syscalls and specific fds.
#[must_use]
pub struct SystemIO {
    /// Syscalls that are allowed
    allowed: HashSet<Sysno>,
    /// Syscalls that are allowed with custom rules, e.g. only allow to specific fds
    custom: HashMap<Sysno, Vec<SeccompRule>>,
    #[cfg(feature = "landlock")]
    /// Landlock rules
    landlock_rules: HashMap<PathBuf, LandlockRule>,
}

impl SystemIO {
    /// By default, allow no IO syscalls.
    pub fn nothing() -> SystemIO {
        SystemIO {
            allowed: HashSet::new(),
            custom: HashMap::new(),
            #[cfg(feature = "landlock")]
            landlock_rules: HashMap::new(),
        }
    }

    /// Allow all IO syscalls.
    pub fn everything() -> SystemIO {
        SystemIO::nothing()
            .allow_read()
            .allow_write()
            .allow_open()
            .yes_really()
            .allow_metadata()
            .allow_unlink()
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

    /// Allow `unlink` syscalls.
    pub fn allow_unlink(mut self) -> SystemIO {
        self.allowed.extend(IO_UNLINK_SYSCALLS);

        self
    }

    /// Allow `open` syscalls.
    ///
    /// # Security
    ///
    /// The reason this function returns a [`YesReally`] is because it's easy to accidentally combine
    /// it with another ruleset that allows `write` - for example the Network ruleset - even if you
    /// only want to read files. Consider using `allow_open_directory()` or `allow_open_file()`.
    pub fn allow_open(mut self) -> YesReally<SystemIO> {
        self.allowed.extend(IO_OPEN_SYSCALLS);

        YesReally::new(self)
    }

    /// Allow `open` syscalls but not with write flags.
    ///
    /// Note that the `openat2` syscall (which is not exposed by glibc anyway according to the
    /// syscall manpage, and so probably isn't very common) is not supported here because it has a
    /// separate configuration struct instead of a flag bitset.
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

        const WRITECREATE: u64 = O_WRONLY | O_RDWR | O_APPEND | O_CREAT | O_EXCL; // | O_TMPFILE;

        // flags are the second argument for open but the third for openat
        #[cfg(enabled_arch = "x86_64")]
        {
            let rule = SeccompRule::new(Sysno::open)
                .and_condition(seccomp_arg_filter!(arg1 & WRITECREATE == 0));
            self.custom
                .entry(Sysno::open)
                .or_insert_with(Vec::new)
                .push(rule);
        }

        let rule = SeccompRule::new(Sysno::openat)
            .and_condition(seccomp_arg_filter!(arg2 & WRITECREATE == 0));
        self.custom
            .entry(Sysno::openat)
            .or_insert_with(Vec::new)
            .push(rule);

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
        let rule = SeccompRule::new(Sysno::read).and_condition(seccomp_arg_filter!(arg0 == 0));
        self.custom
            .entry(Sysno::read)
            .or_insert_with(Vec::new)
            .push(rule);

        self
    }

    /// Allow writing to stdout
    pub fn allow_stdout(mut self) -> SystemIO {
        let rule = SeccompRule::new(Sysno::write).and_condition(seccomp_arg_filter!(arg0 == 1));
        self.custom
            .entry(Sysno::write)
            .or_insert_with(Vec::new)
            .push(rule);

        self
    }

    /// Allow writing to stderr
    pub fn allow_stderr(mut self) -> SystemIO {
        let rule = SeccompRule::new(Sysno::write).and_condition(seccomp_arg_filter!(arg0 == 2));
        self.custom
            .entry(Sysno::write)
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
    #[allow(clippy::missing_panics_doc)]
    pub fn allow_file_read(mut self, file: &File) -> SystemIO {
        let fd = file
            .as_raw_fd()
            .try_into()
            .expect("provided fd was negative");
        for &syscall in IO_READ_SYSCALLS {
            let rule = SeccompRule::new(syscall).and_condition(seccomp_arg_filter!(arg0 == fd));
            self.custom
                .entry(syscall)
                .or_insert_with(Vec::new)
                .push(rule);
        }
        for &syscall in IO_METADATA_SYSCALLS {
            let rule = SeccompRule::new(syscall).and_condition(seccomp_arg_filter!(arg0 == fd));
            self.custom
                .entry(syscall)
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
    #[allow(clippy::missing_panics_doc)]
    pub fn allow_file_write(mut self, file: &File) -> SystemIO {
        let fd = file
            .as_raw_fd()
            .try_into()
            .expect("provided fd was negative");
        let rule = SeccompRule::new(Sysno::write).and_condition(seccomp_arg_filter!(arg0 == fd));
        self.custom
            .entry(Sysno::write)
            .or_insert_with(Vec::new)
            .push(rule);

        self
    }
}

impl RuleSet for SystemIO {
    fn simple_rules(&self) -> Vec<crate::syscalls::Sysno> {
        self.allowed.iter().copied().collect()
    }

    fn conditional_rules(&self) -> HashMap<crate::syscalls::Sysno, Vec<SeccompRule>> {
        self.custom.clone()
    }

    #[cfg(feature = "landlock")]
    fn landlock_rules(&self) -> Vec<LandlockRule> {
        self.landlock_rules.values().cloned().collect()
    }

    fn name(&self) -> &'static str {
        "SystemIO"
    }
}

// landlock impls for SystemIO

#[cfg(feature = "landlock")]
impl SystemIO {
    fn insert_flags<P: AsRef<Path>>(&mut self, path: P, new_flags: BitFlags<AccessFs>) {
        let path = path.as_ref().to_path_buf();
        let _flag = self
            .landlock_rules
            .entry(path.clone())
            .and_modify(|existing_flags| existing_flags.access_rules.insert(new_flags))
            .or_insert_with(|| LandlockRule::new(&path, new_flags));
    }

    /// Use Landlock to allow only files within the specified directory, or the specific file, to
    /// be read. If this function is called multiple times, all directories and files passed will
    /// be allowed.
    ///
    /// Note that if this is used with [`allow_open_readonly`] or other syscall-argument restricting
    /// methods, applying the `SafetyContext` will fail.
    pub fn allow_read_path<P: AsRef<Path>>(mut self, path: P) -> SystemIO {
        let new_flags = access::read_path();
        self.insert_flags(path, new_flags);

        // allow relevant syscalls as well
        self.allow_close()
            .allow_read()
            .allow_metadata()
            .allow_open()
            .yes_really()
    }

    /// Use Landlock to allow only the specified file to be written to. If this function is called
    /// multiple times, all files passed will be allowed.
    ///
    /// Note that if this is used with [`allow_open_readonly`] or other syscall-argument restricting
    /// methods, applying the `SafetyContext` will fail.
    pub fn allow_write_file<P: AsRef<Path>>(mut self, path: P) -> SystemIO {
        let new_flags = access::write_file();
        self.insert_flags(path, new_flags);

        // allow relevant syscalls as well
        self.allow_close()
            .allow_write()
            .allow_metadata()
            .allow_open()
            .yes_really()
    }

    /// Use Landlock to allow files to be created in the given directory. If this function is called
    /// multiple times, all directories passed will be allowed.
    ///
    /// Note that if this is used with [`allow_open_readonly`] or other syscall-argument restricting
    /// methods, applying the `SafetyContext` will fail.
    pub fn allow_create_in_dir<P: AsRef<Path>>(mut self, path: P) -> SystemIO {
        // write file here allows us to create files, but in order to actually write to them, you'd
        // need to enable the write syscall.
        let new_flags = access::create_file() | access::write_file();
        self.insert_flags(path, new_flags);

        // allow relevant syscalls as well
        self.allowed.extend(&[Sysno::creat]);
        self.allow_open().yes_really()
    }

    /// Use Landlock to allow listing the contents of the given directory. If this function is
    /// called multiple times, all directories passed will be allowed.
    pub fn allow_list_dir<P: AsRef<Path>>(mut self, path: P) -> SystemIO {
        let new_flags = access::list_dir();
        self.insert_flags(path, new_flags);

        // allow relevant syscalls as well
        self.allow_metadata()
            .allow_close()
            .allow_ioctl()
            .allow_open()
            .yes_really()
    }

    /// Use Landlock to allow creating directories. If this function is called multiple times, all
    /// directories passed will be allowed.
    pub fn allow_create_dir<P: AsRef<Path>>(mut self, path: P) -> SystemIO {
        let new_flags = access::create_dir();
        self.insert_flags(path, new_flags);

        // allow relevant syscalls as well
        self.allowed.extend(&[Sysno::mkdir, Sysno::mkdirat]);
        self
    }

    /// Use Landlock to allow deleting files. If this function is called multiple times, all files
    /// passed will be allowed.
    pub fn allow_remove_file<P: AsRef<Path>>(mut self, path: P) -> SystemIO {
        let new_flags = access::delete_file();
        self.insert_flags(path, new_flags);

        // allow relevant syscalls as well
        self.allowed.extend(&[Sysno::unlink, Sysno::unlinkat]);
        self
    }

    /// Use Landlock to allow deleting directories. If this function is called multiple times, all
    /// directories passed will be allowed.
    ///
    /// Note that this allows you to delete the contents of the *subdirectories* of this directory,
    /// not the directory itself.
    ///
    /// Also recall that that in order to delete a directory with `unlink` or `rmdir` it must be
    /// empty.
    pub fn allow_remove_dir<P: AsRef<Path>>(mut self, path: P) -> SystemIO {
        let new_flags = access::delete_dir();
        self.insert_flags(path, new_flags);

        // allow relevant syscalls as well
        // unlinkat may be be used to remove directories as well so we include it here, since files
        // will be protected by landlock anyway.
        self.allowed.extend(&[Sysno::rmdir, Sysno::unlinkat]);
        self
    }
}

// TODO: figure out a good way to put this into the Networking Ruleset?
// the biggest issue is that stuff like allow_close, allow_read is defined here and there's not a
// great way to compose different parts from different RuleSets. It might be best to directly
// expose the internal allowed, conditional_rules, landlock_rules as &mut pointers (and then also
// keep the gather_rules) so that you can basically mix and match from different rulesets in a
// single function
#[cfg(feature = "landlock")]
impl SystemIO {
    /// Use Landlock to allow access to SSL certificates in /etc/ssl, /etc/ca-certificates, etc
    ///
    /// Note that crates using rustls and webpki-roots you actually don't need these because the
    /// certificates are embedded in the output binary.
    pub fn allow_ssl_files(mut self) -> SystemIO {
        let new_flags = access::read_path() | access::list_dir();
        for path in &["/etc/ssl/certs", "/etc/ca-certificates"] {
            self.insert_flags(path, new_flags);
        }
        // I'm not 100% sure why openssl is checking localtime but it appears to be doing so
        self.insert_flags("/etc/localtime", access::read_path());

        // allow relevant syscalls as well
        self.allow_close()
            .allow_read()
            .allow_metadata()
            .allow_open()
            .yes_really()
    }

    /// Use Landlock to allow access to DNS files, like /etc/resolv.conf
    pub fn allow_dns_files(mut self) -> SystemIO {
        let new_flags = access::read_path();
        // TODO: libnss exec perms?
        for path in &[
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/host.conf",
            "/etc/nsswitch.conf",
            "/etc/gai.conf",
        ] {
            self.insert_flags(path, new_flags);
        }
        // allow relevant syscalls as well
        self.allow_close()
            .allow_read()
            .allow_metadata()
            .allow_open()
            .yes_really()
    }
}
