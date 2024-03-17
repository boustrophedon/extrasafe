#![allow(unsafe_code)]
// allow unsafe to call syscalls directly

use extrasafe::*;
use builtins::SystemIO;
use extrasafe::syscalls::Sysno;

use std::collections::HashMap;

/// Ioctl with the 2nd arg restricted on all 64 bits
struct IoctlRestricted64(u64);
impl RuleSet for IoctlRestricted64 {
    fn simple_rules(&self) -> Vec<Sysno> {
        Vec::new()
    }

    fn conditional_rules(&self) -> HashMap<Sysno, Vec<SeccompRule>> {
        let cmp = SeccompArgumentFilter::new64(1, SeccompilerComparator::Eq, self.0);
        let rule = SeccompRule::new(Sysno::ioctl)
            .and_condition(cmp);

        HashMap::from([(Sysno::ioctl, vec![rule])])
    }

    fn name(&self) -> &'static str {
        "ioctl restricted 64"
    }
}

/// Ioctl but the 2nd arg restricted, but only the least-significant 32 bits
struct IoctlRestricted32(u32);
impl RuleSet for IoctlRestricted32 {
    fn simple_rules(&self) -> Vec<Sysno> {
        Vec::new()
    }

    fn conditional_rules(&self) -> HashMap<Sysno, Vec<SeccompRule>> {
        let cmp = SeccompArgumentFilter::new32(1, SeccompilerComparator::Eq, self.0);
        let rule = SeccompRule::new(Sysno::ioctl)
            .and_condition(cmp);

        HashMap::from([(Sysno::ioctl, vec![rule])])
    }

    fn name(&self) -> &'static str {
        "ioctl restricted 32"
    }
}


struct GetUidRestricted;
impl RuleSet for GetUidRestricted {
    fn simple_rules(&self) -> Vec<Sysno> {
        Vec::new()
    }

    fn conditional_rules(&self) -> HashMap<Sysno, Vec<SeccompRule>> {
        let rule = SeccompRule::new(Sysno::getuid)
            // 10 is arbitrary but it's unlikely that the value of the register ever will happen to
            // be 10
            .and_condition(seccomp_arg_filter!(arg0 == 10));

        HashMap::from([(Sysno::getuid, vec![rule])])
    }

    fn name(&self) -> &'static str {
        "getuid restricted"
    }
}

#[test]
/// Try to restrict arguments on syscall that does not receive arguments, does not error and should
/// just fail (unless value in register happens to be that value, which is highly unlikely)
fn cmp_arg_syscall_unused_parameter() {
    // SAFETY: getuid just gives the current user's uid
    let uid1 = unsafe { libc::getuid() };
    assert!(uid1 > 0);

    extrasafe::SafetyContext::new()
        .enable(SystemIO::nothing()
            .allow_stdout()
            .allow_stderr()).unwrap()
        .enable(GetUidRestricted).unwrap()
        .apply_to_current_thread().unwrap();

    // SAFETY: getuid just gives the current user's uid
    let uid2 = unsafe { libc::getuid() };
    assert!(uid1 != uid2);
}

macro_rules! assert_errno {
    ($e: expr) => {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap();
        assert_eq!(errno, $e);
    }
}

// See https://github.com/rust-vmm/seccompiler/issues/59 for more details on below two tests
#[test]
fn cmp_arg_64bit_ioctl_musl_glibc_diff() {
    let value: u64 = 0x8000_0000;
    let seccomp_errno = 999;
    extrasafe::SafetyContext::new()
        .with_errno(seccomp_errno)
        .enable(SystemIO::nothing()
            .allow_stdout()
            .allow_stderr()).unwrap()
        .enable(IoctlRestricted64(value)).unwrap()
        .apply_to_current_thread().unwrap();

    // On glibc, the second parameter is a u64, so the value seen by the kernel matches the value
    // in our seccomp filter, and the ioctl call is allowed. It then sets errno to -9 since 4321 is
    // not a valid fd.
    #[cfg(target_env = "gnu")]
    {
        let ret = unsafe { libc::ioctl(4321, value, 0) };
        assert_eq!(ret, -1);
        assert_errno!(libc::EBADF);
    }
    // On musl, the second parameter is an i32 and the value gets signed extended by musl when
    // passed to the kernel. It's therefore different than the one we pass in our seccomp filter,
    // so the ioctl call doesn't match and seccomp makes the return value of ioctl itself -999
    #[cfg(target_env = "musl")]
    {
        let ret = unsafe { libc::ioctl(4321, value as i32, 0) };
        assert_eq!(ret, -1);
        assert_errno!(seccomp_errno as i32); // apparently errno is also i32 on musl
    }
}

#[test]
fn cmp_arg_32bit_ioctl_musl_glibc_same() {
    let value: u32 = 0x8000_0000;
    let seccomp_errno = 999;
    extrasafe::SafetyContext::new()
        .with_errno(seccomp_errno)
        .enable(SystemIO::nothing()
            .allow_stdout()
            .allow_stderr()).unwrap()
        .enable(IoctlRestricted32(value)).unwrap()
        .apply_to_current_thread().unwrap();

    // here both tests are the same except for value being i32 on musl
    #[cfg(target_env = "gnu")]
    let ret = unsafe { libc::ioctl(4321, u64::from(value), 0) };

    #[cfg(target_env = "musl")]
    let ret = unsafe { libc::ioctl(4321, value as i32, 0) };

    assert_eq!(ret, -1);
    assert_errno!(libc::EBADF);
}
