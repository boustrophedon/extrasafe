# extrasafe user guide

## Overview

extrasafe currently consists of two main components: [`SafetyContext`](https://docs.rs/extrasafe/latest/extrasafe/struct.SafetyContext.html) and [`Isolate`](https://docs.rs/extrasafe/latest/extrasafe/isolate/struct.Isolate.html)

`SafetyContext` is used to create [seccomp](https://www.kernel.org/doc/html/v4.19/userspace-api/seccomp_filter.html) and [Landlock](https://landlock.io/) filters, while `Isolate` is used to launch and configure [unprivileged user namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)

`seccomp` is a Linux kernel facility that allows you to voluntarily prohibit your code from calling specified syscalls, but is somewhat course-grained and cannot effectively filter syscalls with complicated arguments. `Landlock` allows for more fine-grained access control over filesystem (and recently network, although this is not available in extrasafe currently) operations.

Linux `namespaces` operate at a higher level of abstraction than seccomp or landlock, and change how entire Linux subsystems operate. They are the core feature that powers container runtimes, and allow your program to have root-like control over isolated filesystems, networks, process spaces, and users. extrasafe Isolates use namespaces to make your program run in an environment where it doesn't have access to the rest of your regular filesystem, network (optionally), and process tree. Isolates are suitable for running subprocesses and using libraries that may be more likely to have vulnerabilities, like image and video processing code, although that doesn't make them perfectly secure - user namespaces have had vulnerabilities in the past.

Once applied, all of these security features are enabled permanently for the lifetime of the thread, and all new threads and subprocesses created after they are enabled. Additionally, seccomp allows you to apply its filters to **all** threads at once, even ones that are already running.

Together, all of these security features allow developers to secure their programs from the inside (as opposed to externally via things like [AppArmor](https://apparmor.net/) and [selinux](https://www.redhat.com/en/topics/linux/what-is-selinux)) and hedge against undiscovered vulnerabilities lurking in your or others' code.

## Basic `SafetyContext` usage

See [the corresponding example in the source code](https://github.com/boustrophedon/extrasafe/blob/master/examples/user-guide.rs) for an executable version of this guide's code.

Create a `SafetyContext`:

```rust
let ctx = extrasafe::SafetyContext::new();
```

Enable some `RuleSet`s, which are essentially named collections of syscalls grouped by functionality:

```rust
use extrasafe::builtins::{SystemIO, Networking};

let ctx = ctx
    .enable(
        SystemIO::nothing()
            .allow_open_readonly()
        ).expect("Failed to add systemio ruleset to context")
        // The Networking RuleSet includes both read and write, but our files
        // will be opened readonly so we can't actually write to them.
        // We can still write to stdout and stderr though.
    .enable(
        Networking::nothing()
            .allow_start_tcp_clients()
            .allow_running_tcp_clients()
        ).expect("Failed to add networking ruleset to context");
```

And then finally apply the rules to the current thread, or all threads, with `apply_to_current_thread` or `apply_to_all_threads`.

```rust
ctx.apply_to_current_thread()
    .expect("Failed to apply seccomp filters");
```

now trying to create a file for writing will fail:

```rust
assert!(std::fs::File::create("/tmp/a_file").is_err());
```

See the [examples directory](https://github.com/boustrophedon/extrasafe/tree/master/examples) and the [tests](https://github.com/boustrophedon/extrasafe/tree/master/examples) for more examples of how to use extrasafe with the built-in and custom rulesets.

## More on RuleSets

The `RuleSet` trait is defined as follows:

```rust
/// A [`RuleSet`] is a collection of [`SeccompRule`] and [`LandlockRule`] s that enable a
/// functionality, such as opening files or starting threads.
pub trait RuleSet {
    /// A simple rule is a seccomp rule that just allows the syscall without restriction.
    fn simple_rules(&self) -> Vec<syscalls::Sysno>;

    /// A conditional rule is a seccomp rule that uses a condition to restrict the syscall, e.g. only
    /// specific flags as parameters.
    fn conditional_rules(&self) -> HashMap<syscalls::Sysno, Vec<SeccompRule>> {
      HashMap::new()
    }

    /// The name of the profile.
    fn name(&self) -> &'static str;

    #[cfg(feature = "landlock")]
    /// A landlock rule is a pair of an access control (e.g. read/write access, directory creation
    /// access) and a directory or path.
    fn landlock_rules(&self) -> Vec<LandlockRule> {
        Vec::new()
    }
}
```

The RuleSet is comprised of

- A list of "simple rules", which enables the syscall without restriction
- A map of syscalls to a list of "Rules", which are pairs of a syscall and conditions on its arguments.
- The name of the RuleSet, for error message reporting purposes
- Landlock rules, which will be covered in the Landlock section

There are a few restrictions to note about `RuleSet`s that originate in seccomp:

### Overlapping rules

Extrasafe starts from a default-deny state, and each time you `enable` a RuleSet, the SafetyContext gathers all the rules and adds them to its context (hence the name). Because we can only enable (i.e. the process is additive), enabling will fail if one `RuleSet` enables a syscall without restriction (via `simple_rules`), and another enables a syscall with a restriction (via `conditional_rules`). If it did not, the restriction would be silently ignored by seccomp when the filter is instantiated, which can be confusing.

One thing this impacts is where syscalls are used in multiple contexts, particularly the `read` and `write` syscalls: If you restrict the fds you can call `read` on, intending to limit access to the filesystem, you may also intentionally block yourself from `read`ing from a socket.

In order to get around this issue, you can do all your filesystem operations on one thread/process and your network operations in another, and communicate via e.g. a unix domain socket. See [examples/ipc\_server\_with\_database.rs](https://github.com/boustrophedon/extrasafe/blob/master/examples/ipc_server_with_database.rs) for an example of using communicating processes to achieve this separation.

### Syscall pointer arguments

Seccomp, the underlying functionality provided by the kernel that extrasafe uses, doesn't allow comparisons on arguments that are pointers, so for example we can't filter on file path for `open` syscalls because the path is a `char *`.

## Defining your own ruleset

If you want to use syscalls that aren't included in any of the builtin rulesets, consider [filing an issue to request a new one!](https://github.com/boustrophedon/extrasafe/issues)

`RuleSet` is implemented for the `Sysno` type directly, so if you just want to enable one or two syscalls, the simplest way to do so is:

```rust
extrasafe::SafetyContext::new()
    .enable(syscalls::Sysno::reboot).unwrap()
    .enable(syscalls::Sysno::sysinfo).unwrap()
    .apply_to_current_thread().unwrap();
```

However, this doesn't work for conditional rules yet.

In the meantime, you can create your own RuleSet:

```rust
use extrasafe::*;
use syscalls::Sysno;

use std::collections::HashMap;

struct MyRuleSet;

impl RuleSet for MyRuleSet {
    fn simple_rules(&self) -> Vec<Sysno> {
        // literally reboot the computer
        vec![Sysno::reboot]
    }

    fn conditional_rules(&self) -> HashMap<Sysno, Vec<SeccompRule>> {
        // Only allow the creation of stream (tcp) sockets
        const SOCK_STREAM: u64 = libc::SOCK_STREAM as u64;

        let rule = SeccompRule::new(Sysno::socket)
            .and_condition(
                seccomp_arg_filter!(arg0 & SOCK_STREAM == SOCK_STREAM));
        HashMap::from([
            (Sysno::socket, vec![rule,])
        ])
    }

    fn name(&self) -> &'static str {
        "MyRuleSet"
    }
}

// And it can be enabled just like the builtin ones:
extrasafe::SafetyContext::new()
    .enable(MyRuleSet).unwrap()
    .apply_to_current_thread().unwrap();
```

See the [extrasafe documentation](https://docs.rs/extrasafe/latest/macro.seccomp_arg_filter.html) for more information on how to use the comparator generator macro.

Currently [the syscalls crate's](https://crates.io/crates/syscalls) [`Sysno` enum](https://docs.rs/syscalls/latest/syscalls/enum.Sysno.html) is used in the `RuleSet` interface. It's convenient because the enum is defined separately for each target architecture such that the syscall gets mapped to the correct syscall number (which may differ on different architectures).

However, there are some syscalls that only exist on certain architectures (e.g. fstatat64 vs newfstatat). Currently the builtin RuleSets are defined assuming `x86_64`.

## Landlock

Landlock allows you to restrict access to the filesystem via a variety of [access rights](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#access-rights). These access rights are applied either to existing files, or on existing directories, in which case the right will apply to all subdirectories and subfiles.

Extrasafe currently requires V2 of the landlock ABI, which was introduced in Linux kernel 5.19.

If the crate feature "landlock" is active, and a SafetyContext enables a RuleSet that provides a non-empty Vec from its `landlock_rules` method, Landlock will be enabled. Landlock can be applied independently of seccomp by using the `SafetyContext::landlock_only()` before applying the context to the current thread.

The easiest way to use Landlock is via the SystemIO ruleset, which provides methods like `allow_create_in_dir`, `allow_read_path`, and `allow_write_file`.

If you want to implement your own LandlockRules, you can look at the `extrasafe::landlock::access` module to see what is currently exposed or you can use the [AccessFs](https://docs.rs/landlock/latest/landlock/enum.AccessFs.html) enum directly and create `extrasafe::LandlockRule`s manually.

Here's some example code using landlock to allow file creation/write access in a single directory:

```rust
fn with_landlock() {
    let tmp_dir_allow = tempfile::tempdir().unwrap().into_path();
    let tmp_dir_deny = tempfile::tempdir().unwrap().into_path();

    extrasafe::SafetyContext::new()
        .enable(
           extrasafe::builtins::SystemIO::nothing()
              .allow_create_in_dir(&tmp_dir_allow)
              .allow_write_file(&tmp_dir_allow)
        ).unwrap()
    .apply_to_current_thread().unwrap();

    // Opening arbitrary files now fails!
    let res = File::create(tmp_dir_deny.join("evil.txt"));
    assert!(res.is_err());

    // But the directory we allowed works
    let res = File::create(tmp_dir_allow.join("my_output.txt"));
    assert!(res.is_ok());

    println!("printing to stdout is also allowed");
    eprintln!("because read/write syscalls are unrestricted");

    // And other syscalls are still disallowed
    let res = std::net::UdpSocket::bind("127.0.0.1:0");
    assert!(res.is_err());
}
```

### Caveats

The existing groupings in SystemIO are a bit too orthogonal - `allow_create_in_dir` by itself will not allow you to create files because you need to also call `allow_write_file` typically unless you're very tightly controlling the flags passed to the openat/creat syscall.

It's also a bit hard to create your own RuleSets with landlock rules because the corresponding syscalls also need to be enabled. A future refactoring of the RuleSet trait may allow more easy cross-use and re-use of functions implemented on individual RuleSet implementors, so that one RuleSet can enable a grouping of syscalls defined in another. Another option is to detect which syscalls are needed by which landlock access rights, and simply enable them inside the `SafetyContext::apply*` functions.

Relatedly, we also enable possibly more syscalls than are strictly necessary (e.g. ioctl and fcntl) when enabling landlock since we're currently just using the existing pre-defined groups in SystemIO.

`SafetyContext::apply_to_all_threads` does not work with landlock. However, landlock is inherited by child threads and processes like seccomp.

## Isolates

Extrasafe `Isolates` are a easy to use wrapper around Linux [user namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html). Namespaces are most widely used in unprivileged container runtimes inside Podman and Docker, and can also be found in programs like bubblewrap and firejail. Extrasafe Isolates can be enabled with the `isolate` feature.

There are a variety of [namespace types](https://man7.org/linux/man-pages/man7/namespaces.7.html) but the most relevant for extrasafe are mount, network, PID, and user namespaces. By using an extrasafe Isolate, you can isolate your program both from the rest of the network and the rest of the filesystem.

In detail, starting an `extrasafe::Isolate` in your code will launch a subprocess by re-running the current process's executable (via the standard `std::process::Command` interface) with a different set of arguments, which then gets recognized by a piece of code the user adds to their `main()` function. The `Isolate::main_hook` function will then internally call the `clone` syscall to enter a new namespace, and then perform setup that mounts a new, private temporary filesystem and mounts user-specified directories into it, sets it as the new root filesystem with [`pivot_root`](https://man7.org/linux/man-pages/man2/pivot_root.2.html), and unmounts the old root filesystem. This all happens without affecting anything in the parent namespace, much in the same way that a container runtime does.

By default, there's no communication channel between the parent namespace and the child, but by bindmounting Unix sockets or electing not to isolate the network namespace, the parent process can communicate with an Isolate. Environment variables can be passed into the Isolate to provide initial configuration.

Here's a minimal example using most of the features except for keeping the parent network:

```rust
use extrasafe::isolate::Isolate;
use std::collections::HashMap;
use std::path::PathBuf;

const EXAMPLE_ISOLATE: &str = "user guide isolate";

/// The function that ultimately runs inside the Isolate
fn do_cool_thing() {
    println!("I'm going to read some files from /cooldir and do cool stuff with it!");
    // TODO: do cool stuff with the files in /cooldir
}

/// Isolate configuration that happens when the program is re-executed after `Isolate::run`
fn setup_isolate(name: &'static str) -> Isolate {
    let path = std::env::var("COOL_DIRECTORY").unwrap();
    let path = PathBuf::from(path);
    Isolate::new(name, do_cool_thing)
        // This will mount /a/b/c from the parent into /cooldir in the child,
        // but not until after entering the namespace.
        .add_bind_mount(path, "/cooldir")
        // Limit the amount of data that can be written to the filesystem the
        // Isolate lives in.
        .set_rootfs_size(1)
}

fn main() {
    // Once the Isolate::run call is made, this will run the setup function,
    // enter the namespace and call the the function provided. The first time the program runs,
    // this code will be ignored.
    Isolate::main_hook(EXAMPLE_ISOLATE, setup_isolate);

    // ... somewhere later in the program

    let env_vars = HashMap::from([("COOL_DIRECTORY".to_string(), "/".to_string())]);

    // `Isolate::run` returns a normal `std::process::Output`
    let output = Isolate::run(EXAMPLE_ISOLATE, &env_vars).unwrap();

    assert!(output.status.success());
    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
}
```

One thing to note is that the name passed to `Isolate::run` and `Isolate::main_hook` must be the same or your program will not enter the Isolate after re-execing.

It's also difficult to test `Isolate`s currently because they interact poorly with the builtin testing framework, but I will be prototyping new ways to test Isolates. Currently the above code isn't in `examples/user-guide.rs` for that reason, it's in a separate `examples/user_guide_isolate.rs` file.
