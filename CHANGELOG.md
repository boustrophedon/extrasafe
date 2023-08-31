unreleased
----------
- reexport syscalls dependency
- Rename `Rule` to `SeccompRule` in preparation for `LandlockRule`
    - Update relevant documentation
- Disallow adding simple SeccompRules when the syscall is already restricted
  with comparators, or adding rules with comparators when the syscall is
  restricted with a simple rule. GitHub Issue #6

0.1.4
-----
- impl RuleSet for &RuleSet
- Remove thiserror dependency
- Update libseccomp and syscalls dependencies

0.1.3 and prior
----
Initial extrasafe release
