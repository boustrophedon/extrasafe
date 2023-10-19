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
