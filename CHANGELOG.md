unreleased
----------
- Minor docs/user guide update
- Use unix datagram sockets instead of stream in ipc server example and run in CI

0.5.0
-----
- Add `Isolate` feature for using unprivileged namespaces
  - Use `Isolate::run` inside your normal code to start the isolate
  - Use `Isolate::main_hook` at the beginning of main to actually run the isolate upon re-exec
  - This feature significantly drops code coverage because llvm-cov can't write
    out coverage data from within an isolate. The code is still being covered
    by tests in `examples/isolate_test.rs`.
- Add default implementation for `RuleSet::conditional_rules`
- impl RuleSet for `syscalls::Sysno` for easier ad-hoc rulesets
- Use generics instead of impl Trait in public functions to allow turbofish usage

0.4.0
-----
- Add landlock functionality
  - Add `landlock_rules` to RuleSet trait and new `LandlockRule` type
  - Add `landlock_only` method to SafetyContext
  - In test code, use rustls only in musl to get wider environment coverage
  - Added several ExtraSafeError variants for Landlock-related errors
  - See methods in SystemIO for how to use Landlock
  - Landlock is enabled with the V2 ABI, which was added in kernel 5.19

0.3.0
-----
- Switch seccomp backend to seccompiler
  - This adds several new structs that act as wrappers around the underlying
    seccompiler structs
  - Macros are defined in extrasafe now to replace the ones provided by
    libseccomp for comparing and filtering syscall arguments
- Add `#[must_use]` attributes to several structs where it was previously only
  on methods that returned that struct
- Add Pipes builtin ruleset
- Allow `connect` syscall in dedicated method in Network builtin ruleset
- On musl, the ForkAndExec ruleset for starting new processes additionally
  allows the pipe and pipe2 syscalls, which it appears to use for
  synchronization purposes

0.2.0
-----
- reexport syscalls dependency
- Rename `Rule` to `SeccompRule` in preparation for `LandlockRule`
    - Update relevant documentation
- Disallow adding simple SeccompRules when the syscall is already restricted
  with comparators, or adding rules with comparators when the syscall is
  restricted with a simple rule. GitHub Issue #6
- Add `SystemIO::allow_unlink`

0.1.4
-----
- impl RuleSet for &RuleSet
- Remove thiserror dependency
- Update libseccomp and syscalls dependencies

0.1.3 and prior
----
Initial extrasafe release
