#![deny(non_ascii_idents)]
#![deny(unsafe_code)]
#![deny(unused_results)]
#![allow(clippy::unwrap_or_default)] // explicit is better than implicit
#![allow(clippy::new_without_default)]
// Denied in CI
#![warn(missing_docs)]
#![warn(trivial_casts, trivial_numeric_casts)]

//! extrasafe is a library that makes it easy to improve your program's security by selectively
//! allowing the syscalls it can perform via the Linux kernel's seccomp facilities.
//!
//! See the [`SafetyContext`] struct's documentation and the tests/ and examples/ directories for
//! more information on how to use it.


// Filter is the entire, top-level seccomp filter chain. All SeccompilerRules are or-ed together.
//  Vec<(i64, Vec<SeccompilerRule>)>, Vec is empty if Rule has no filters.
// Rule is a syscall + multiple argument filters. All argument filters are and-ed together in a
// single Rule.
// ArgumentFilter is a single condition on a single argument
// Comparator is used in an ArgumentFilter to choose the comparison operation
pub use seccompiler::SeccompFilter as SeccompilerFilter;
pub use seccompiler::SeccompRule as SeccompilerRule;
pub use seccompiler::SeccompCondition as SeccompilerArgumentFilter;
pub use seccompiler::Error as SeccompilerError;
pub use seccompiler::SeccompCmpOp as SeccompilerComparator;

use seccompiler::SeccompAction;

pub use syscalls;

pub mod error;
pub use error::*;

#[macro_use]
pub mod macros;
pub use macros::*;

pub mod builtins;

#[cfg(feature = "landlock")]
mod landlock;
#[cfg(feature = "landlock")]
pub use landlock::*;

#[cfg(feature = "landlock")]
use std::path::PathBuf;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, PartialEq)]
/// A restriction on the arguments of a syscall. May be combined with other
/// [`SeccompArgumentFilter`] as part of a single [`SeccompRule`], in which case they are and-ed
/// together and must all return true for the syscall to be allowed.
///
/// Because some syscalls take 32 bit arguments which may or may not be sign-extended to 64 bits
/// when passed to the linux kernel, there is an option to indicate whether the argument is 32 or
/// 64 bits. It shouldn't need to be used frequently.
/// See <https://github.com/rust-vmm/seccompiler/issues/59> for more details
/// # Examples
///
/// ```
/// # use extrasafe::*;
/// # const SOCK_STREAM: u64 = libc::SOCK_STREAM as u64;
/// # const AF_INET: u64 = libc::AF_INET as u64;
/// // if syscall (specified elsewhere) is `read`, allow reading from stdin
/// seccomp_arg_filter!(arg0 == 1);
/// // if syscall is `socket`, allow IPV4 sockets only
/// seccomp_arg_filter!(arg0 & AF_INET == AF_INET);
/// // if syscall is `socket`, allow TCP sockets only
/// seccomp_arg_filter!(arg0 & SOCK_STREAM == SOCK_STREAM);
/// ```
///
/// You should use the [`seccomp_arg_filter!`] macros to create these.
pub struct SeccompArgumentFilter {
    /// Which syscall argument to filter. Starts at 0 for the first argument.
    pub arg_idx: u8,
    /// What operation should be used to compare to the user-provided value.
    comparator: SeccompilerComparator,
    /// The user-provided value to compare the argument against.
    pub value: u64,
    /// Whether the argument is 64 bits or 32 bits. See the docstring for why this is needed.
    pub is_64bit: bool,
}

impl SeccompArgumentFilter {
    #[must_use]
    /// Create a new [`SeccompArgumentFilter`]. You should probably use the [`seccomp_arg_filter!`]
    /// instead.
    pub fn new(arg_idx: u8, comparator: SeccompilerComparator, value: u64) -> SeccompArgumentFilter {
        // TODO: add quirks mode file and check whether syscall's parameter at index `arg_idx` is
        // 32 or 64 bit (and also I guess if it even has that many arguments)
        SeccompArgumentFilter::new64(arg_idx, comparator, value)
    }

    #[must_use]
    /// Create a new [`SeccompArgumentFilter`] that checks all 64 bits of the provided argument.
    /// You should probably use the [`seccomp_arg_filter!`] instead.
    pub fn new64(arg_idx: u8, comparator: SeccompilerComparator, value: u64) -> SeccompArgumentFilter {
        SeccompArgumentFilter {
            arg_idx,
            comparator,
            value,
            is_64bit: true,
        }
    }

    #[must_use]
    /// Create a new [`SeccompArgumentFilter`] that checks 32 bits of the provided argument.
    /// You should probably use the [`seccomp_arg_filter!`] instead. See the struct's documentation
    /// for why this is needed.
    pub fn new32(arg_idx: u8, comparator: SeccompilerComparator, value: u32) -> SeccompArgumentFilter {
        // Note that it doesn't matter if we convert with or without sign extension here since the
        // point is that we'll only compare the least significant 32 bits anyway.
        let value = u64::from(value);
        SeccompArgumentFilter {
            arg_idx,
            comparator,
            value,
            is_64bit: false,
        }
    }

    pub(crate) fn into_seccompiler(self) -> Result<SeccompilerArgumentFilter, ExtraSafeError> {
        use seccompiler::SeccompCmpArgLen;
        let arg_len = if self.is_64bit { SeccompCmpArgLen::Qword } else { SeccompCmpArgLen::Dword };
        Ok(SeccompilerArgumentFilter::new(self.arg_idx, arg_len,
                                       self.comparator, self.value)?)
    }
}

#[derive(Debug, Clone)]
#[must_use]
/// A seccomp rule.
pub struct SeccompRule {
    /// The syscall being filtered
    pub syscall: syscalls::Sysno,
    /// Filters on the syscall's arguments. The SeccompRule allows the syscall if all argument
    /// filters evaluate to true.
    pub argument_filters: Vec<SeccompArgumentFilter>,
}

impl SeccompRule {
    /// Constructs a new [`SeccompRule`] that unconditionally allows the given syscall.
    pub fn new(syscall: syscalls::Sysno) -> SeccompRule {
        SeccompRule {
            syscall,
            argument_filters: Vec::new(),
        }
    }

    /// Adds a condition to the [`SeccompRule`] which must evaluate to true in order for the syscall to be
    /// allowed.
    pub fn and_condition(mut self, argument_filter: SeccompArgumentFilter) -> SeccompRule {
        self.argument_filters.push(argument_filter);

        self
    }

    /// Convert an extrasafe `SeccompRule` to a seccompiler `SeccompilerRule`. Seccompiler's rules
    /// require that at least one `ArgumentFilter`, so if we have a "simple rule" in extrasafe
    /// terminology, we return `Option::None`.
    pub(crate) fn into_seccompiler(self) -> Result<Option<SeccompilerRule>, ExtraSafeError> {
        if self.argument_filters.is_empty() {
            return Ok(None);
        }

        let argument_filters: Vec<SeccompilerArgumentFilter> = self.argument_filters.into_iter()
            .map(SeccompArgumentFilter::into_seccompiler).collect::<Result::<_, ExtraSafeError>>()?;

        Ok(Some(SeccompilerRule::new(argument_filters)?))
    }
}

#[derive(Debug, Clone)]
/// A [`SeccompRule`] labeled with the name of the [`RuleSet`] it originated from. Internal-only.
struct LabeledSeccompRule(pub &'static str, pub SeccompRule);

/// A [`RuleSet`] is a collection of [`SeccompRule`] and `LandlockRule` s that enable a
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

impl<T: ?Sized + RuleSet> RuleSet for &T {
    #[inline]
    fn simple_rules(&self) -> Vec<syscalls::Sysno> {
        T::simple_rules(self)
    }

    #[inline]
    fn conditional_rules(&self) -> HashMap<syscalls::Sysno, Vec<SeccompRule>> {
        T::conditional_rules(self)
    }

    #[inline]
    fn name(&self) -> &'static str {
        T::name(self)
    }

    #[cfg(feature = "landlock")]
    #[inline]
    fn landlock_rules(&self) -> Vec<LandlockRule> {
        T::landlock_rules(self)
    }
}

impl RuleSet for syscalls::Sysno {
    fn simple_rules(&self) -> Vec<syscalls::Sysno> {
        Vec::from([*self])
    }

    fn conditional_rules(&self) -> HashMap<syscalls::Sysno, Vec<SeccompRule>> {
        HashMap::new()
    }

    fn name(&self) -> &'static str {
        self.name()
    }
}

#[must_use]
/// A struct representing a set of rules to be loaded into a seccomp filter and applied to the
/// current thread, or all threads in the current process.
///
/// Create with [`new()`](Self::new). Add [`RuleSet`]s with [`enable()`](Self::enable), and then use [`apply_to_current_thread()`](Self::apply_to_current_thread)
/// to apply the filters to the current thread, or [`apply_to_all_threads()`](Self::apply_to_all_threads) to apply the filter to
/// all threads in the process.
#[derive(Debug)]
pub struct SafetyContext {
    /// A mapping from a syscall to either be a single simple rule or multiple conditional rules, but not both.
    seccomp_rules: HashMap<syscalls::Sysno, Vec<LabeledSeccompRule>>,
    #[cfg(feature = "landlock")]
    /// A mapping from filesystem paths to [`LandlockRule`]s specifying files and directories with
    /// the operations that can be performed on them.
    landlock_rules: HashMap<PathBuf, LabeledLandlockRule>,
    /// The errno returned when a syscall does not match one of the seccomp rules. Defaults to 1.
    errno: u32,
    /// Flag to apply seccomp to all threads rather than just the current thread. Defaults to
    /// false (but the public apply functions always set it directly anyway)
    all_threads: bool,
    #[cfg(feature = "landlock")]
    /// Flag to only use landlock filters and not enable seccomp filters at all. Defaults to false.
    only_landlock: bool,
}

impl SafetyContext {
    /// Create a new [`SafetyContext`]. The seccomp filters will not be loaded until either
    /// [`apply_to_current_thread`](Self::apply_to_current_thread) or
    /// [`apply_to_all_threads`](Self::apply_to_all_threads) is called.
    pub fn new() -> SafetyContext {
        SafetyContext {
            seccomp_rules: HashMap::new(),
            #[cfg(feature = "landlock")]
            landlock_rules: HashMap::new(),
            errno: 1,
            all_threads: false,
            #[cfg(feature = "landlock")]
            only_landlock: false,
        }
    }

    /// Set the errno to the provided value when a syscall does not match one of the seccomp rules
    /// in this `SafetyContext`.
    pub fn with_errno(mut self, errno: u32) -> SafetyContext {
        self.errno = errno;
        self
    }

    /// Gather unconditional and conditional seccomp rules to be provided to the seccomp context.
    #[allow(clippy::needless_pass_by_value)]
    fn gather_rules<R: RuleSet>(rules: R) -> Vec<SeccompRule> {
        let base_syscalls = rules.simple_rules();
        let mut rules = rules.conditional_rules();
        for syscall in base_syscalls {
            let rule = SeccompRule::new(syscall);
            rules.entry(syscall)
                .or_insert_with(Vec::new)
                .push(rule);
        }

        rules.into_values().flatten()
            .collect()
    }

    /// Enable the simple and conditional rules provided by the [`RuleSet`].
    ///
    /// # Errors
    /// Will return [`ExtraSafeError::ConditionalNoEffectError`] if a conditional rule is enabled at
    /// the same time as a simple rule for a syscall, which would override the conditional rule.
    pub fn enable<R: RuleSet>(mut self, policy: R) -> Result<SafetyContext, ExtraSafeError> {
        #[cfg(feature = "landlock")]
        self.enable_landlock_rules(&policy)?;

        self.enable_seccomp_rules(policy)?;

        Ok(self)
    }

    #[cfg(feature = "landlock")]
    fn enable_landlock_rules<R: RuleSet>(&mut self, policy: &R) -> Result<(), ExtraSafeError> {
        let name = policy.name();
        let rules = policy.landlock_rules().into_iter()
            .map(|rule| (rule.path.clone(), LabeledLandlockRule(name, rule)));

        for (path, labeled_rule) in rules {
            if let Some(existing_rule) = self.landlock_rules.get(&path) {
                return Err(ExtraSafeError::DuplicatePath(path.clone(), existing_rule.0, labeled_rule.0));
            }
            // value here is always none because we checked above that we're not inserting a path
            // that already exists
            let _always_none = self.landlock_rules.insert(path, labeled_rule);
        }
        Ok(())
    }

    fn enable_seccomp_rules<R: RuleSet>(&mut self, policy: R) -> Result<(), ExtraSafeError> {
        let policy_name = policy.name();
        let new_rules = SafetyContext::gather_rules(policy)
            .into_iter()
            .map(|rule| LabeledSeccompRule(policy_name, rule));

        for labeled_new_rule in new_rules {
            let new_rule = &labeled_new_rule.1;
            let syscall = &new_rule.syscall;

            if let Some(existing_rules) = self.seccomp_rules.get(syscall) {
                for labeled_existing_rule in existing_rules {
                    let existing_rule = &labeled_existing_rule.1;

                    let new_is_simple = new_rule.argument_filters.is_empty();
                    let existing_is_simple = existing_rule.argument_filters.is_empty();

                    // if one rule is conditional and the other is simple, let the user know there
                    // would be a conflict and raise an error.
                    if new_is_simple && !existing_is_simple {
                        return Err(ExtraSafeError::ConditionalNoEffectError(
                            new_rule.syscall,
                            labeled_existing_rule.0,
                            labeled_new_rule.0,
                        ));
                    }
                    else if !new_is_simple && existing_is_simple {
                        return Err(ExtraSafeError::ConditionalNoEffectError(
                            new_rule.syscall,
                            labeled_new_rule.0,
                            labeled_existing_rule.0,
                        ));
                    }
                    // otherwise, they're either both conditional rules or both simple rules,
                    // in which case we continue to check the existing filters, and then add the
                    // rules to our filter as normal if all checks pass.
                    //
                    // In the end, the rules for a syscall must either be all simple (i.e.
                    // duplicates from different rulesets) or all conditional (e.g. multiple rules
                    // allowing read to be called on specific fds)
                }
            }

            self.seccomp_rules
                .entry(*syscall)
                .or_insert_with(Vec::new)
                .push(labeled_new_rule);
        }

        Ok(())
    }

    #[cfg(feature = "landlock")]
    /// Do not use seccomp at all, and only enable landlock filters.
    pub fn landlock_only(mut self) -> SafetyContext {
        self.only_landlock = true;
        self
    }

    // TODO: unused, need to figure out a good way to do this without clasing with the existing
    // seccomp argument-filtered/not-filtered checks
    // #[cfg(feature = "landlock")]
    // /// If there are both landlock and seccomp rules, and the seccomp rules are argument-filtered
    // /// such that they would conflict with the operation of the landlock rules, return the names of
    // /// the rulesets that they come from. This only gets called once in `SafetyContext::apply`
    // /// because it iterates over all seccomp rules.
    // ///
    // /// Returns (seccomp_ruleset_name, landlock_ruleset_name)
    // fn landlock_seccomp_rule_conflict(&self) -> Option<(&'static str, &'static str)> {
    //     if let Some((_path, landlock_rule)) = self.landlock_rules.iter().next() {
    //         for syscall in Self::landlock_restricted_syscalls() {
    //             if let Some(existing_rules) = self.seccomp_rules.get(&syscall) {
    //                 // the rules for a given syscall are either all argument-filtered rules or a single
    //                 // unfiltered rule so either way this will stop after 1 iteration
    //                 if let Some(labeled_rule) = existing_rules.iter().find(|rule| !rule.1.argument_filters.is_empty()) {
    //                     return Some((labeled_rule.0, landlock_rule.0)); // return the names of the originating rulesets
    //                 }
    //             }
    //         }
    //     }
    //     return None;
    // }

    // #[cfg(feature = "landlock")]
    // // TODO: there doesn't seem to be anything in the official documentation about this?
    // // this definitely isn't exhaustive
    // fn landlock_restricted_syscalls() -> Vec<syscalls::Sysno> {
    //     let mut syscalls = Vec::new();
    //     syscalls.extend(builtins::systemio::IO_OPEN_SYSCALLS);
    //     syscalls.extend(builtins::systemio::IO_METADATA_SYSCALLS);

    //     syscalls
    // }

    /// Load the [`SafetyContext`]'s rules into a seccomp filter and apply the filter to the current
    /// thread.
    ///
    /// If the landlock feature is enabled but no landlock rules are applied, landlock is not
    /// enabled, unless `landlock_only()` is called. To enable landlock but allow no file access,
    /// you can first apply a `landlock_only()` `SafetyContext`, and then apply a separate
    /// `SafetyContext` with your seccomp rules.
    ///
    /// # Errors
    /// May return an [`ExtraSafeError`].
    ///
    /// If no rulesets are enabled, returns an `ExtraSafeError::NoRulesEnabled` error. If you
    /// really want to enable "nothing", try enabling the `builtins::BasicCapabilities` default
    /// ruleset manually, or create your own with e.g. just the `exit` syscall.
    pub fn apply_to_current_thread(mut self) -> Result<(), ExtraSafeError> {
        self.all_threads = false;
        self.apply()
    }

    /// Load the [`SafetyContext`]'s rules into a seccomp filter and apply the filter to all threads in
    /// this process.
    ///
    /// If the landlock feature is enabled but no landlock rules are applied, landlock is not
    /// enabled, unless `landlock_only()` is called. To enable landlock but allow no file access,
    /// you can first apply a `landlock_only()` `SafetyContext`, and then apply a separate
    /// `SafetyContext` with your seccomp rules.
    ///
    /// # Errors
    /// May return an [`ExtraSafeError`].
    ///
    /// If no rulesets are enabled, returns an `ExtraSafeError::NoRulesEnabled` error. If you
    /// really want to enable "nothing", try enabling the `builtins::BasicCapabilities` default
    /// ruleset manually, or create your own with e.g. just the `exit` syscall.
    pub fn apply_to_all_threads(mut self) -> Result<(), ExtraSafeError> {
        #[cfg(feature = "landlock")]
        if !self.landlock_rules.is_empty() {
            return Err(ExtraSafeError::LandlockNoThreadSync);
        }
        self.all_threads = true;
        self.apply()
    }

    /// Actually do the application of the rules. If `self.all_threads` is True, applies the rules to
    /// all threads via seccomp tsync. If `self.only_landlock` is True, only applies landlock rules.
    ///
    /// If the landlock feature is enabled but no landlock rules are applied, landlock is not
    /// enabled, unless `landlock_only()` is called. To enable landlock but allow no file access,
    /// you can first apply a `landlock_only()` `SafetyContext`, and then apply a separate
    /// `SafetyContext` with your seccomp rules.
    ///
    /// If no rulesets are enabled, returns an `ExtraSafeError::NoRulesEnabled` error. If you
    /// really want to enable "nothing", try enabling the `builtins::BasicCapabilities` default
    /// ruleset manually, or create your own with e.g. just the `exit` syscall.
    fn apply(mut self) -> Result<(), ExtraSafeError> {
        #[cfg(feature = "landlock")]
        if self.seccomp_rules.is_empty() && self.landlock_rules.is_empty() {
            return Err(ExtraSafeError::NoRulesEnabled);
        }
        #[cfg(not(feature = "landlock"))]
        if self.seccomp_rules.is_empty() {
            return Err(ExtraSafeError::NoRulesEnabled);
        }

        self = self.enable(builtins::BasicCapabilities)?;

        #[cfg(feature = "landlock")]
        if self.only_landlock {
            return self.apply_landlock_rules();
        }
        // If no landlock rules, do not try to apply them since it would prevent all filesystem
        // access.
        else if self.landlock_rules.is_empty() {
            return self.apply_seccomp_rules();
        }

        #[cfg(feature = "landlock")]
        self.apply_landlock_rules()?;
        self.apply_seccomp_rules()
    }

    fn apply_seccomp_rules(self) -> Result<(), ExtraSafeError> {
        // Turn our internal HashMap into a BTreeMap for seccompiler, being careful to avoid
        // https://github.com/rust-vmm/seccompiler/issues/42 i.e. don't use BTreeMap's collect impl
        // because it will ignore duplicates.

        let mut rules_map: BTreeMap<i64, Vec<SeccompilerRule>> = BTreeMap::new();

        for (syscall, labeled_rules) in self.seccomp_rules {
            let syscall = syscall.id().into();

            let mut seccompiler_rules = Vec::new();
            for LabeledSeccompRule(_origin, rule) in labeled_rules {
                // If there are conditional rules, insert them to the vec
                if let Some(seccompiler_rule) = rule.into_seccompiler()? {
                    seccompiler_rules.push(seccompiler_rule);
                }
                // otherwise, keep the vec empty, which indicates to seccompiler that the syscall
                // should be allowed without restriction
            }
            let result = rules_map.insert(syscall, seccompiler_rules);
            assert!(result.is_none(), "extrasafe logic error: somehow inserted the same syscall's rules twice");
        }

        #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
        compile_error!("extrasafe is currently only supported on linux x86_64");

        let seccompiler_filter = SeccompilerFilter::new(
            rules_map,
            SeccompAction::Errno(self.errno),
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().expect("invalid arches are prevented above"),
        )?;

        let bpf_filter: seccompiler::BpfProgram = seccompiler_filter.try_into()?;

        if self.all_threads {
            seccompiler::apply_filter_all_threads(&bpf_filter)?;
        }
        else {
            seccompiler::apply_filter(&bpf_filter)?;
        }

        Ok(())
    }

    #[cfg(feature = "landlock")]
    fn apply_landlock_rules(&self) -> Result<(), ExtraSafeError> {
	let abi = ABI::V2;
	let mut landlock_ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
	    .handle_access(AccessFs::from_all(abi))?
	    .create()?;

        for LabeledLandlockRule(_policy_name, rule) in self.landlock_rules.values() {
            // If path does not exist or is not accessible, just ignore it
            if let Ok(fd) = PathFd::new(rule.path.clone()) {
                let path_beneath = PathBeneath::new(fd, rule.access_rules);
                landlock_ruleset = landlock_ruleset.add_rule(path_beneath)?;
            }
        }
	let _status = landlock_ruleset.restrict_self();
        Ok(())
    }
}
