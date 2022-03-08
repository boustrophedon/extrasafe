# extrasafe

[![Coverage Status](https://coveralls.io/repos/github/boustrophedon/extrasafe/badge.svg?branch=master)](https://coveralls.io/github/boustrophedon/extrasafe?branch=master) [![CI Status](https://github.com/boustrophedon/extrasafe/actions/workflows/build-test.yaml/badge.svg)](https://github.com/boustrophedon/extrasafe/actions/workflows/build-test.yaml) [![crates.io](https://img.shields.io/crates/v/extrasafe)](https://crates.io/crates/extrasafe) [![docs.rs](https://img.shields.io/docsrs/extrasafe)](https://docs.rs/extrasafe/latest/extrasafe/)

*"trust noone not even urself" - internet man*

```rust
fn main() {
    println!("disabling syscalls...");

    extrasafe::SafetyContext::new()
        .enable(
           extrasafe::builtins::SystemIO::nothing()
              .allow_stdout()
              .allow_stderr()
   	    ).unwrap()
	.apply_to_all_threads().unwrap();

    // Opening files now fails!
    let res = File::create("should_fail.txt");
    assert!(res.is_err());

    println!("but printing to stdout still works!");
    eprintln!("and so does stderr!");
}
```

You've used safe and unsafe Rust: now your code can be extrasafe.

extrasafe is a wrapper around [libseccomp](https://libseccomp.readthedocs.io/en/latest/), which uses [the Linux kernel's seccomp](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html) syscall-filtering functionality to prevent your program from calling syscalls you don't need. Seccomp is used by systemd, Chrome, application sandboxes like bubblewrap and firejail, and container runtimes. Seccomp by itself is not a complete sandboxing system.

The goal of extrasafe is to make it easy to add extra security to your own programs without having to rely on external configuration by the person running the software.

seccomp is very mildly complicated, so we provide simple defaults that make it hard to misuse: Deny-by-default with pre-selected sets of syscalls to enable.

Additionally, we support slightly advanced use-cases:
  - Allow read/write on only stdin/out/err
  - Allow read/write on specific files (opened before loading the seccomp filters)
  - You can define your own set of syscalls to allow by implementing the RuleSet trait.

Check out the [**user guide here**](https://github.com/boustrophedon/extrasafe/blob/master/user-guide.md)

# Who is extrasafe for?

**Application** developers who want to tightly control what their programs can and cannot do.

If you're developing a library, there are three things you can do:

1. Provide an `extrasafe::RuleSet` that covers the functionality of your library
2. Provide some kind of `init` function that does any IO-related work ahead of time (e.g. reading config files, SSL certificates)
3. If your library has any kind of independent worker threads, you can use extrasafe inside the worker thread.

You don't want to use extrasafe directly in your library because you don't know what other functionality your dependents will be using.

**Currently extrasafe only supports `x86_64`. If you'd like to help support other archs please open an issue.**

## Other uses

You may be able to use extrasafe to help test certain edge-cases, like the network being unavailable or not being able to read files, but I think that use-case would be better served by a separate library. Email me if you're interested in this!

# Why?

So you can be extra safe. Suppose your program has a dependency with an undiscovered RCE lurking somewhere: extrasafe allows you to partially hedge against that by disabling access to functionality you don't need.

## Specific examples of vulnerabilities that could avoid exploitation with seccomp (looking for contributions!)

- https://seclists.org/oss-sec/2022/q1/55
  - When unprivileged, relies on being able to call `unshare`.
- log4j RCEs
  - Relies on being able to make network calls, so extrasafe can mitigate this by
    - If your program doesn't need network access, don't give it access (but then you aren't really exploitable anyway in most cases)
    - Logging in a separate thread that doesn't have network access
- Exploits involving executing SUID-root binaries rely on being able to fork and exec.

# Caveats

Seccomp filters are a somewhat blunt tool.

- They don't allow you to filter by path name in `open` calls, or indeed any syscall arguments that are pointers (but see below about Landlock!)
	- In particular, this can make SSL somewhat annoying because you have to open a bunch of files to check for certificates.
- Their smallest unit of scope is a thread, so if you want to protect possibly risky parsing code in a hot inner loop, you may need to figure out a way to pass data back and forth quickly to an existing thread, rather than spinning up a new thread each time.

# Why not X?

Why not both? Keep reading.

## Why not use systemd's built-in seccomp support?

systemd supports filtering child processes' syscalls with seccomp via the `SystemCallFilter` attribute. See [e.g. this blog post](https://prefetch.net/blog/2017/11/27/securing-systemd-services-with-seccomp-profiles/) and [the systemd documentation]()

Issues:

- Systemd-specific
- Precludes writing a backend for e.g. BSD that uses `pledge`
- Not as fine-grained:
	- extrasafe lets you open files and then close off further access, for example.
	- extrasafe lets you use the seccomp syscall argument filtering functionality, allowing you to only accept connections on specific, pre-allocated socket fds, for example.
- By putting the security profile inside your code, it gets to benefit from all of the work and processes put into maintaining codebases: source control, automated testing, code coverage, so you can be sure that your security profile is as specified whenever and wherever your code is deployed.

To those sysadmins or devops reading this and saying "but I don't want to trust that the developers wrote their seccomp filter correctly!" - great! Defense in depth is the goal, and you can and should continue to use AppArmor or your preferred choice of external security control system. 

## So what about AppArmor or SELinux?

As mentioned above, you should continue to use Linux Security Modules like AppArmor and SELinux! Not every program will be using extrasafe.

In the same way, from the perspective of a developer, there's no guarantee that the person running your code is using them. When there's a bug in your open-source code running on thousands of machines outside of your control, it's much nicer to know that it's not easily exploitable and can be fixed at your leisure, rather than having to coordinate a massive patch-and-upgrade effort to secure the systems. 

## Landlock

[Landlock](https://landlock.io/) is a new LSM that [exposes an ABI via new syscalls](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html) for userland developers to use, which mitigates the issues described above with regards to filtering on specific filesystem paths.

However, it's very new so older systems very likely don't have access to it, and it also only currently supports filesystem-related functionality.

It does seem to be the way forward in the future.
