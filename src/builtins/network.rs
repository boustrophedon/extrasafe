//! Contains a [`RuleSet`] for allowing networking-related syscalls.

use std::collections::{HashMap, HashSet};

use crate::syscalls::Sysno;

use super::YesReally;
use crate::{SeccompRule, RuleSet};

// TODO: make bind calls conditional on the DGRAM/UNIX/STREAM flag in each function

// TODO: add io_uring
const NET_IO_SYSCALLS: &[Sysno] = &[
    #[cfg(enabled_arch = "x86_64")]
    Sysno::epoll_create,
    Sysno::epoll_create1, Sysno::epoll_ctl,
    #[cfg(enabled_arch = "x86_64")]
    Sysno::epoll_wait,
    Sysno::epoll_pwait, Sysno::epoll_pwait2,
    #[cfg(enabled_arch = "x86_64")]
    Sysno::select,
    Sysno::pselect6,
    #[cfg(enabled_arch = "x86_64")]
    Sysno::poll,
    Sysno::ppoll, Sysno::accept, Sysno::accept4,
    // used in reqwest::blocking I guess to notify when blocking reads finish?
    #[cfg(enabled_arch = "x86_64")]
    Sysno::eventfd,
    Sysno::eventfd2,
    // Used to set tcp_nodelay
    Sysno::fcntl, Sysno::ioctl,
    Sysno::getsockopt,
    Sysno::setsockopt,

    // Misc socket info
    Sysno::getpeername,
    Sysno::getsockname,
];

// listen is technically not a "read" syscall but you'd never listen and not read.
const NET_READ_SYSCALLS: &[Sysno] = &[Sysno::listen,
                                      Sysno::recvfrom, Sysno::recvmsg, Sysno::recvmmsg,
                                      Sysno::read, Sysno::readv, Sysno::preadv, Sysno::preadv2];
const NET_WRITE_SYSCALLS: &[Sysno] = &[Sysno::sendto, Sysno::sendmsg, Sysno::sendmmsg,
                                       Sysno::sendfile,
                                       Sysno::write, Sysno::writev, Sysno::pwritev, Sysno::pwritev2];

// TODO: refactor Socket rule creation to reduce duplication in the allow_start_*_server functions

/// A [`RuleSet`] representing syscalls that perform network operations - accept/listen/bind/connect etc.
///
/// # How to use
///
/// 1. Select TCP or UDP (or both) with `enable_tcp()`, `enable_udp()`
/// 2a. If you are a server of some sort, **strongly** consider first binding to your ports and
///     then not allowing further binds by using `running_tcp_server()` or `running_udp_server()`.
///     Otherwise,
/// 2b. If you are a client, use `tcp_client()` and/or `udp_client()`, which does not allow
///     `accept` or `listen` syscalls.
/// The most common use-case: select TCP or UDP (or both) with `.enable_tcp()` or `.enable_udp()`,
/// and then decide if you're going to allow binding to new ports
///
///
/// # Security considerations
///
/// If you enable writing (on either tcp or udp), this enables the `write` syscall which will
/// therefore also enable writing to stdout/stderr and any open files. Therefore you should take
/// care to consider whether you can split up your program (e.g. across separate threads) into a
/// part that opens and writes to files and a part that speaks to the network. This is a good
/// security practice in general.
#[must_use]
pub struct Networking {
    /// Syscalls that are allowed
    allowed: HashSet<Sysno>,
    /// Syscalls that are allowed with custom rules, e.g. only allow to specific fds
    custom: HashMap<Sysno, Vec<SeccompRule>>,
}

impl Networking {
    /// By default, allow no networking syscalls.
    pub fn nothing() -> Networking {
        Networking {
            allowed: HashSet::new(),
            custom: HashMap::new(),
        }
    }

    /// Allow a running TCP server to continue running. Does not allow `socket` or `bind`,
    /// preventing new sockets from being created.
    pub fn allow_running_tcp_servers(mut self) -> Networking {
        self.allowed.extend(NET_IO_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        self
    }

    /// Allow starting new TCP servers.
    ///
    /// # Security Notes
    ///
    /// You probably don't need to use this. In most cases you can just run your server and then
    /// use [`allow_running_tcp_servers`](Self::allow_running_tcp_servers). See
    /// `examples/network_server.rs` for an example with warp.
    pub fn allow_start_tcp_servers(mut self) -> YesReally<Networking> {
        const AF_INET: u64 = libc::AF_INET as u64;
        const AF_INET6: u64 = libc::AF_INET6 as u64;
        const SOCK_STREAM: u64 = libc::SOCK_STREAM as u64;

        // IPv4
        let rule = SeccompRule::new(Sysno::socket)
            .and_condition(seccomp_arg_filter!(arg0 & AF_INET == AF_INET))
            .and_condition(seccomp_arg_filter!(arg1 & SOCK_STREAM == SOCK_STREAM));
        self.custom.entry(Sysno::socket)
            .or_insert_with(Vec::new)
            .push(rule);
        // IPv6
        let rule = SeccompRule::new(Sysno::socket)
            .and_condition(seccomp_arg_filter!(arg0 & AF_INET6 == AF_INET6))
            .and_condition(seccomp_arg_filter!(arg1 & SOCK_STREAM == SOCK_STREAM));
        self.custom.entry(Sysno::socket)
            .or_insert_with(Vec::new)
            .push(rule);

        // Bind is unconditional here because besides the socket fd, the other argument is a
        // struct we can't look into due to seccomp restrictions.
        self.allowed.extend(&[Sysno::bind]);
        self.allowed.extend(NET_IO_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        YesReally::new(self)
    }

    /// Allow a running UDP socket to continue running. Does not allow `socket` or `bind`,
    /// preventing new sockets from being created.
    pub fn allow_running_udp_sockets(mut self) -> Networking {
        self.allowed.extend(NET_IO_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        self
    }

    /// Allow starting new UDP sockets.
    ///
    /// # Security Notes
    ///
    /// You probably don't need to use this. In most cases you can just run your server and then
    /// use [`allow_running_udp_sockets`](Self::allow_running_udp_sockets).
    pub fn allow_start_udp_servers(mut self) -> YesReally<Networking> {
        const AF_INET: u64 = libc::AF_INET as u64;
        const AF_INET6: u64 = libc::AF_INET6 as u64;
        const SOCK_DGRAM: u64 = libc::SOCK_DGRAM as u64;

        // IPv4
        let rule = SeccompRule::new(Sysno::socket)
            .and_condition(seccomp_arg_filter!(arg0 & AF_INET == AF_INET))
            .and_condition(seccomp_arg_filter!(arg1 & SOCK_DGRAM == SOCK_DGRAM));
        self.custom.entry(Sysno::socket)
            .or_insert_with(Vec::new)
            .push(rule);
        // IPv6
        let rule = SeccompRule::new(Sysno::socket)
            .and_condition(seccomp_arg_filter!(arg0 & AF_INET6 == AF_INET6))
            .and_condition(seccomp_arg_filter!(arg1 & SOCK_DGRAM == SOCK_DGRAM));
        self.custom.entry(Sysno::socket)
            .or_insert_with(Vec::new)
            .push(rule);

        self.allowed.extend(&[Sysno::bind]);
        self.allowed.extend(NET_IO_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        YesReally::new(self)
    }

    /// Allow `connect` syscall
    ///
    /// # Security Considerations
    ///
    /// This allows connnecting to a potentially dangerous network resource
    pub fn allow_connect(mut self) -> YesReally<Networking> {
        self.allowed.extend(&[Sysno::connect]);
        YesReally::new(self)
    }

    /// Allow starting new TCP clients.
    ///
    /// # Security Notes
    ///
    /// In some cases you can create the socket ahead of time, but that isn't possible with e.g.
    /// reqwest, so we allow socket but not bind here.
    pub fn allow_start_tcp_clients(mut self) -> Networking {
        const AF_INET: u64 = libc::AF_INET as u64;
        const AF_INET6: u64 = libc::AF_INET6 as u64;
        const SOCK_STREAM: u64 = libc::SOCK_STREAM as u64;

        // IPv4
        let rule = SeccompRule::new(Sysno::socket)
            .and_condition(seccomp_arg_filter!(arg0 & AF_INET == AF_INET))
            .and_condition(seccomp_arg_filter!(arg1 & SOCK_STREAM == SOCK_STREAM));
        self.custom.entry(Sysno::socket)
            .or_insert_with(Vec::new)
            .push(rule);
        // IPv6
        let rule = SeccompRule::new(Sysno::socket)
            .and_condition(seccomp_arg_filter!(arg0 & AF_INET6 == AF_INET6))
            .and_condition(seccomp_arg_filter!(arg1 & SOCK_STREAM == SOCK_STREAM));
        self.custom.entry(Sysno::socket)
            .or_insert_with(Vec::new)
            .push(rule);
        
        self.allowed.extend(&[Sysno::connect]);
        self.allowed.extend(NET_IO_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        self
    }

    /// Allow a running TCP client to continue running. Does not allow `socket` or `connect`,
    /// preventing new sockets from being created.
    ///
    /// This is technically the same as
    /// [`allow_running_tcp_servers`](Self::allow_running_tcp_servers).
    pub fn allow_running_tcp_clients(mut self) -> Networking {
        self.allowed.extend(NET_IO_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        self
    }

    /// Allow starting new Unix domain servers
    ///
    /// # Security Notes
    ///
    /// You probably don't need to use this. In most cases you can just run your server and then
    /// use [`allow_running_unix_servers`](Self::allow_running_unix_servers).
    pub fn allow_start_unix_servers(mut self) -> YesReally<Networking> {
        const AF_UNIX: u64 = libc::AF_UNIX as u64;
        const SOCK_STREAM: u64 = libc::SOCK_STREAM as u64;
        const SOCK_DGRAM: u64 = libc::SOCK_DGRAM as u64;

        // We allow both stream and dgram unix sockets
        let rule = SeccompRule::new(Sysno::socket)
            .and_condition(seccomp_arg_filter!(arg0 & AF_UNIX == AF_UNIX))
            .and_condition(seccomp_arg_filter!(arg1 & SOCK_STREAM == SOCK_STREAM));
        self.custom.entry(Sysno::socket)
            .or_insert_with(Vec::new)
            .push(rule);
        // DGRAM
        let rule = SeccompRule::new(Sysno::socket)
            .and_condition(seccomp_arg_filter!(arg0 & AF_UNIX == AF_UNIX))
            .and_condition(seccomp_arg_filter!(arg1 & SOCK_DGRAM == SOCK_DGRAM));
        self.custom.entry(Sysno::socket)
            .or_insert_with(Vec::new)
            .push(rule);

        self.allowed.extend(&[Sysno::bind]);
        self.allowed.extend(NET_IO_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        YesReally::new(self)
    }

    /// Allow a running Unix server to continue running. Does not allow `socket` or `bind`,
    /// preventing new sockets from being created.
    pub fn allow_running_unix_servers(mut self) -> Networking {
        self.allowed.extend(NET_IO_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        self
    }

    /// Allow a running Unix socket client to continue running. Does not allow `socket` or `connect`,
    /// preventing new sockets from being created.
    ///
    /// This is technically the same as
    /// [`allow_running_unix_servers`](Self::allow_running_unix_servers).
    pub fn allow_running_unix_clients(mut self) -> Networking {
        self.allowed.extend(NET_IO_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        self
    }
}

impl RuleSet for Networking {
    fn simple_rules(&self) -> Vec<crate::syscalls::Sysno> {
        self.allowed.iter().copied().collect()
    }

    fn conditional_rules(&self) -> HashMap<crate::syscalls::Sysno, Vec<SeccompRule>> {
        self.custom.clone()
    }

    fn name(&self) -> &'static str {
        "Networking"
    }
}
