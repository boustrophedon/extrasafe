//! Extrasafe's `Isolate` allows you to run a subprocess in a [user
//! namespace](https://man7.org/linux/man-pages/man7/user_namespaces.7.html), which allows you to
//! isolate your program in order to e.g. run 
//!
//! Specifically, you can isolate:
//! - The filesystem. The Isolate creates a temporary directory and mounts a tmpfs onto it, and
//! then makes that tmpfs the new root. The original root filesystem becomes unaccessible.
//! Specific directories and files may be mounted into the tmpfs if desired.
//! - The network. A new network namespace may also be created. In the context of extrasafe, this
//! is mostly useful to disable the network and make it simpler to use seccomp.
//! - The program itself. In addition to running in a different memory space, so the original
//! program's data is unaffected by the subprocess, the Isolate is executed via an in-memory
//! copy of the program so that the program binary itself cannot be modified.

// options:
// - keep network
// - env vars
// - program name for ps (it's a prctl or something to set)
// - args identifier to catch we're in an isolate in main
// - bind mount directory list
// - tmpfs size?

use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::os::fd::AsRawFd;
use std::process::Output;

mod isolate_sys;
use isolate_sys as system;

/// Error type for errors related to `Isolate`
#[derive(Debug)]
pub enum IsolateError {
    /// An error that occurred during memfd operations
    MemFd(std::io::Error),
    /// An error that occurred while spawning a `std::process::Command`
    Command(std::io::Error),
    /// An error that occurred while configuring a bindmount (in the subprocess but before clone)
    BindmountConfig(std::io::Error),

}

/// Allows creation of subprocesses which then use Linux user namespaces to isolate the program
#[derive(Debug)]
#[must_use]
pub struct Isolate {
    /// Isolate name, checked for in `argv[0]` inside `main_hook`. Note that this must be a
    /// `&'static str`
    isolate_name: &'static str,
    /// The function to execute inside the isolate
    func: fn() -> (),
    /// If true, start a new network namespace. Default: true
    new_network: bool,
    /// Size in MB of the root tmpfs filesystem of the isolate. Default is 10MB.
    root_fs_size: u32,
    /// A mapping of paths in the parent filesystem to be bindmounted to paths in the child
    /// filesystem.
    bindmounts: HashMap<PathBuf, PathBuf>,
}

impl Isolate {
    /// Create a new isolate that will execute the given function when called in a subprocess with
    /// `argv[0]` equal to `isolate_name`. func must not be a closure.
    pub fn new(isolate_name: &'static str, func: fn() -> ()) -> Isolate {
        Isolate {
            isolate_name,
            func,
            new_network: true,
            root_fs_size: 10,
            bindmounts: HashMap::new(),
        }
    }

    /// Bind mount the file or path in src to the file or path in dst. If `dst` is relative, it is
    /// treated as relative to the root of the isolate's tmpfs. If `dst` is absolute, it will still
    /// be joined as if it were relative to the isolate's tmpfs root. `dst` will be created if it does not
    /// exist, including all intermediate directories.
    ///
    /// Bindmounts to files and symlinks are allowed, but if a symlink points outside the current
    /// filesystem it will not function.
    ///
    /// Bind mounts are not created until `Isolate::main_hook` executes.
    pub fn add_bind_mount(mut self, src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Isolate {
        let src = src.as_ref();
        let dst = dst.as_ref();
        
        let _old = self.bindmounts.insert(src.into(), dst.into());
        self
    }

    /// Set the maximum size of the filesystem, in MiB.
    pub fn set_rootfs_size(mut self, size: u32) -> Self {
        self.root_fs_size = size;
        self
    }

    /// If true is passed, a new network namespace is created which is detached from all existing
    /// interfaces.
    pub fn new_network(mut self, new_network: bool) -> Self {
        self.new_network = new_network;
        self
    }

    /// Start a subprocess that will activate an Isolate with the given `isolate_name` and
    /// environment variables. Only the provided environment variables will be present in the
    /// subprocess and nothing else from the current process. The subprocess's `argv` will only
    /// contain `isolate_name`.
    ///
    /// # Errors
    /// Will return an error if starting the Command fails.
    pub fn run(isolate_name: &'static str, envs: &HashMap<String, String>) -> Result<Output, IsolateError> {
        let memfd = system::create_memfd_from_self_exe()?;
        std::process::Command::new(format!("/proc/self/fd/{}", memfd.as_raw_fd()))
            .arg0(isolate_name)
            .env_clear()
            .envs(envs)
            .output()
            .map_err(IsolateError::Command)
    }

    /// At the start of the program, call this function to check whether we are in an isolate
    /// subprocess and should run `func` after setting up the user namespace.
    ///
    /// # Panics
    /// If there is an error with starting the isolate, there's no way to recover so in all cases
    /// we panic.
    pub fn main_hook<F: Fn(&'static str) -> Isolate>(isolate_name: &'static str, builder: F) {
        /// drop wrapper for the tempdir so that even if there's a panic it should get cleaned up
        struct TempDirCleanup(pub PathBuf);
        impl Drop for TempDirCleanup {
            fn drop(&mut self) {
                std::fs::remove_dir(&self.0)
                    .expect("tmpfs dir was not empty");
            }
        }

        let mut args = std::env::args();
        // Check if we're supposed to be running as the specified isolate
        if let Some(arg0) = args.next() {
            if arg0 == isolate_name {
                let isolate = builder(isolate_name);

                let tempdir = system::make_tempdir(isolate_name);
                let tempdir_clean = TempDirCleanup(tempdir.clone());

                let mut child_stack = Vec::with_capacity(system::CHILD_STACK_SIZE);

                let (_child_pid, child_pidfd) = isolate.isolate_and_run(&mut child_stack, tempdir.clone());
                let child_ret = system::wait_for_child(child_pidfd);

                drop(tempdir_clean);
                std::process::exit(child_ret);
            }
        }
        // If we're not, just continue with the rest of the program
    }

    /// `clone`s into a new namespace, creates a tmpfs at `tempdir`, bindmounts the relevant
    /// directories into it, `pivot_root`s into the tmpfs, and runs `self.func`
    fn isolate_and_run(&self, child_stack: &mut [u8], tempdir: PathBuf) -> (libc::pid_t, libc::id_t) {
        let new_network = self.new_network;
        let data = system::IsolateConfigData::new(
            self.isolate_name,
            self.bindmounts.clone(),
            self.func,
            self.root_fs_size,
            tempdir);
        system::clone_into_namespace(child_stack, data, new_network)
    }
}
