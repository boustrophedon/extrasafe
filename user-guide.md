# How to use extrasafe

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
    fn conditional_rules(&self) -> HashMap<syscalls::Sysno, Vec<SeccompRule>>;

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

In the meantime, you can create your own:

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

# Landlock

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

## Caveats

The existing groupings in SystemIO are a bit too orthogonal - `allow_create_in_dir` by itself will not allow you to create files because you need to also call `allow_write_file` typically unless you're very tightly controlling the flags passed to the openat/creat syscall.

It's also a bit hard to create your own RuleSets with landlock rules because the corresponding syscalls also need to be enabled. A future refactoring of the RuleSet trait may allow more easy cross-use and re-use of functions implemented on individual RuleSet implementors, so that one RuleSet can enable a grouping of syscalls defined in another. Another option is to detect which syscalls are needed by which landlock access rights, and simply enable them inside the `SafetyContext::apply*` functions.

Relatedly, we also enable possibly more syscalls than are strictly necessary (e.g. ioctl and fcntl) when enabling landlock since we're currently just using the existing pre-defined groups in SystemIO.

`SafetyContext::apply_to_all_threads` does not work with landlock. However, landlock is inherited by child threads and processes like seccomp.
