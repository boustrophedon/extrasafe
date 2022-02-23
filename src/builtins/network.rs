//! Contains a RuleSet for allowing networking-related syscalls.

use std::collections::{HashMap, HashSet};

use syscalls::Sysno;

use super::YesReally;
use crate::{Rule, RuleSet};

// TODO: make bind calls conditional on the DGRAM/UNIX/STREAM flag in each function

// TODO: add io_uring
const NET_IO_SYSCALLS: &[Sysno] = &[
    Sysno::epoll_create, Sysno::epoll_create1,
    Sysno::epoll_ctl, Sysno::epoll_wait, Sysno::epoll_pwait, Sysno::epoll_pwait2,
    Sysno::select, Sysno::pselect6,
    Sysno::poll, Sysno::ppoll,

    Sysno::accept, Sysno::accept4,

    // used in reqwest::blocking I guess to notify when blocking reads finish?
    Sysno::eventfd, Sysno::eventfd2,

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
const NET_CREATE_SERVER_SYSCALLS: &[Sysno] = &[Sysno::socket, Sysno::bind];
const NET_CREATE_CLIENT_SYSCALLS: &[Sysno] = &[Sysno::socket, Sysno::connect];

/// A RuleSet representing syscalls that perform network operations - accept/listen/bind/connect etc.
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
pub struct Networking {
    /// Syscalls that are allowed
    allowed: HashSet<Sysno>,
    /// Syscalls that are allowed with custom rules, e.g. only allow to specific fds
    custom: HashMap<Sysno, Vec<Rule>>,
}

impl Networking {
    /// By default, allow no networking syscalls.
    pub fn nothing() -> Networking {
        Networking {
            allowed: HashSet::new(),
            custom: HashMap::new(),
        }
    }

    /// Allow a running TCP server to continue running. Does not allow `socket` or `bind` to
    /// prevent new sockets from being created.
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
    /// use `allow_running_server`. See `examples/network_server.rs` for an example with warp.
    pub fn allow_start_tcp_servers(mut self) -> YesReally<Networking> {
        self.allowed.extend(NET_CREATE_SERVER_SYSCALLS);
        self.allowed.extend(NET_IO_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        YesReally::new(self)
    }

    /// Allow a running UDP server to continue running. Does not allow `socket` or `bind` to
    /// prevent new sockets from being created.
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
    /// use `allow_running_server`.
    pub fn allow_start_udp_servers(mut self) -> YesReally<Networking> {
        self.allowed.extend(NET_CREATE_SERVER_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        YesReally::new(self)
    }

    /// Allow starting new TCP clients.
    ///
    /// # Security Notes
    ///
    /// In some cases you can create the socket ahead of time, but that isn't possible with e.g.
    /// reqwest, so we allow socket but not bind here.
    pub fn allow_start_tcp_clients(mut self) -> Networking {
        self.allowed.extend(NET_CREATE_CLIENT_SYSCALLS);
        self.allowed.extend(NET_IO_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        self
    }

    /// Allow a running TCP client to continue running. Does not allow `socket` or `connect` to
    /// prevent new sockets from being created.
    ///
    /// This is technically the same as `allow_running_tcp_servers`.
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
    /// use `allow_running_server`.
    pub fn allow_start_unix_server(mut self) -> YesReally<Networking> {
        self.allowed.extend(NET_CREATE_SERVER_SYSCALLS);
        self.allowed.extend(NET_IO_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        YesReally::new(self)
    }

    /// Allow a running Unix server to continue running. Does not allow `socket` or `bind` to
    /// prevent new sockets from being created.
    pub fn allow_running_unix_servers(mut self) -> Networking {
        self.allowed.extend(NET_IO_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        self
    }

    /// Allow a running Unix socket client to continue running. Does not allow `socket` or `connect` to
    /// prevent new sockets from being created.
    ///
    /// This is technically the same as `allow_running_unix_servers`.
    pub fn allow_running_unix_clients(mut self) -> Networking {
        self.allowed.extend(NET_IO_SYSCALLS);
        self.allowed.extend(NET_READ_SYSCALLS);
        self.allowed.extend(NET_WRITE_SYSCALLS);

        self
    }
}

impl RuleSet for Networking {
    fn simple_rules(&self) -> Vec<syscalls::Sysno> {
        self.allowed.iter().copied().collect()
    }

    fn conditional_rules(&self) -> HashMap<syscalls::Sysno, Vec<Rule>> {
        self.custom.clone()
    }

    fn name(&self) -> &'static str {
        "Networking"
    }
}
