#![deny(non_ascii_idents)]
#![deny(unsafe_code)]
#![deny(unused_results)]
#![allow(clippy::new_without_default)]
// Denied in CI
//#![warn(missing_docs)]
#![warn(trivial_casts, trivial_numeric_casts)]

//! extrasafe is a library that makes it easy to improve your program's security by selectively
//! allowing the syscalls it can perform via the Linux kernel's seccomp facilities.
//!
//! See the [`SafetyContext`] struct's documentation and the tests/ and examples/ directories for
//! more information on how to use it.

use libseccomp::*;
use thiserror::Error;

pub mod builtins;

use std::collections::HashMap;

#[derive(Debug, Clone)]
/// A seccomp rule.
pub struct Rule {
    /// The syscall being filtered
    pub syscall: syscalls::Sysno,
    // Yes, technically this is not the correct usage of "comparators" but it's fine.
    /// Comparisons applied to the syscall's args. The Rule allows the syscall if all comparators
    /// evaluate to true.
    pub comparators: Vec<ScmpArgCompare>,
}

impl Rule {
    /// Constructs a new Rule that unconditionally allows the given syscall.
    #[must_use]
    pub fn new(syscall: syscalls::Sysno) -> Rule {
        Rule {
            syscall,
            comparators: Vec::new(),
        }
    }

    /// Adds a condition to the Rule which must evaluate to true in order for the syscall to be
    /// allowed.
    #[must_use]
    pub fn and_condition(mut self, comparator: ScmpArgCompare) -> Rule {
        self.comparators.push(comparator);

        self
    }
}

#[derive(Debug, Clone)]
/// A [`Rule`] labeled with the profile it originated from. Internal-only.
struct LabeledRule(pub &'static str, pub Rule);

/// A [`RuleSet`] is a collection of seccomp Rules that enable a functionality.
pub trait RuleSet {
    /// A simple rule is one that just allows the syscall without restriction.
    fn simple_rules(&self) -> Vec<syscalls::Sysno>;

    /// A conditional rule is a rule that uses a condition to restrict the syscall, e.g. only
    /// specific flags as parameters.
    fn conditional_rules(&self) -> HashMap<syscalls::Sysno, Vec<Rule>>;

    /// The name of the profile.
    fn name(&self) -> &'static str;
}

#[must_use]
#[derive(Debug)]
/// A struct representing a set of rules to be loaded into a seccomp filter and applied to the
/// current thread, or all threads in the current process.
///
/// Create with [`new()`](Self::new). Add [`RuleSet`]s with [`enable()`](Self::enable), and then use [`apply_to_current_thread()`](Self::apply_to_current_thread)
/// to apply the filters to the current thread, or [`apply_to_all_threads()`](Self::apply_to_all_threads) to apply the filter to
/// all threads in the process.
pub struct SafetyContext {
    /// May either be a single simple rule or multiple conditional rules, but not both.
    rules: HashMap<syscalls::Sysno, Vec<LabeledRule>>,
}

impl SafetyContext {
    /// Create a new [`SafetyContext`]. The seccomp filters will not be loaded until either
    /// [`apply_to_current_thread`](Self::apply_to_current_thread) or
    /// [`apply_to_all_threads`](Self::apply_to_all_threads) is called.
    pub fn new() -> SafetyContext {
        #[cfg(not(target_arch = "x86_64"))]
        {
            compile_error!("Extrasafe currently only supports the x86_64 architecture. You will likely see other errors about Sysno enum variants not existing; this is why.");
        }

        SafetyContext {
            rules: HashMap::new(),
        }
    }

    /// Gather unconditional and conditional rules to be provided to the seccomp context.
    #[allow(clippy::needless_pass_by_value)]
    fn gather_rules(rules: impl RuleSet) -> Vec<Rule> {
        let base_syscalls = rules.simple_rules();
        let mut rules = rules.conditional_rules();
        for syscall in base_syscalls {
            if !rules.contains_key(&syscall) {
                let rule = Rule::new(syscall);
                rules.entry(syscall).or_insert_with(Vec::new).push(rule);
            }
        }

        rules.into_values().flatten().collect()
    }

    /// Enable the simple and conditional rules provided by the [`RuleSet`].
    ///
    /// # Errors
    /// Will return [`ExtraSafeError::ConditionalNoEffectError`] if a conditional rule is enabled at
    /// the same time as a simple rule for a syscall, which would override the conditional rule.
    pub fn enable(mut self, policy: impl RuleSet) -> Result<SafetyContext, ExtraSafeError> {
        // Note that we can't do this check in each individual gather_rules because different
        // policies may enable the same syscall.

        let policy_name = policy.name();
        let new_rules = SafetyContext::gather_rules(policy)
            .into_iter()
            .map(|rule| LabeledRule(policy_name, rule));

        for labeled_new_rule in new_rules {
            let new_rule = &labeled_new_rule.1;
            let syscall = &new_rule.syscall;

            if let Some(existing_rules) = self.rules.get(syscall) {
                for labeled_existing_rule in existing_rules {
                    let existing_rule = &labeled_existing_rule.1;

                    let new_is_simple = new_rule.comparators.is_empty();
                    let existing_is_simple = existing_rule.comparators.is_empty();
                    let same_syscall = new_rule.syscall == existing_rule.syscall;

                    if same_syscall && new_is_simple && !existing_is_simple {
                        return Err(ExtraSafeError::ConditionalNoEffectError(
                            new_rule.syscall,
                            labeled_existing_rule.0,
                            labeled_new_rule.0,
                        ));
                    }
                    if same_syscall && !new_is_simple && existing_is_simple {
                        return Err(ExtraSafeError::ConditionalNoEffectError(
                            new_rule.syscall,
                            labeled_new_rule.0,
                            labeled_existing_rule.0,
                        ));
                    }
                }
            }

            self.rules
                .entry(*syscall)
                .or_insert_with(Vec::new)
                .push(labeled_new_rule);
        }

        Ok(self)
    }

    /// Load the [`SafetyContext`]'s rules into a seccomp filter and apply the filter to the current
    /// thread.
    ///
    /// # Errors
    /// May return [`ExtraSafeError::SeccompError`].
    pub fn apply_to_current_thread(self) -> Result<(), ExtraSafeError> {
        self.apply(false)
    }

    /// Load the [`SafetyContext`]'s rules into a seccomp filter and apply the filter to all threads in
    /// this process.
    ///
    /// # Errors
    /// May return [`ExtraSafeError::SeccompError`].
    pub fn apply_to_all_threads(self) -> Result<(), ExtraSafeError> {
        self.apply(true)
    }

    fn apply(mut self, all_threads: bool) -> Result<(), ExtraSafeError> {
        // This guard will not currently ever be hit because libseccomp-rs will fail to build
        // before we get here. If we ever move off of it or if libseccomp-rs decides to do a
        // no-op build on non-linux platform, having this guard here means end users will still
        // have to explicitly acknowledge that extrasafe isn't running on that platform.
        if cfg!(not(target_os = "linux")) {
            return Err(ExtraSafeError::UnsupportedOSError);
        }

        let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Errno(libc::EPERM))?;

        if all_threads {
            ctx.set_filter_attr(ScmpFilterAttr::CtlTsync, 1)?;
        } else {
            // this is the default but we set it just to be sure.
            ctx.set_filter_attr(ScmpFilterAttr::CtlTsync, 0)?;
        }

        ctx.add_arch(ScmpArch::Native)?;

        self = self.enable(builtins::BasicCapabilities)?;
        for LabeledRule(_origin, rule) in self.rules.into_values().flatten() {
            if rule.comparators.is_empty() {
                ctx.add_rule(ScmpAction::Allow, rule.syscall.id())?;
            } else {
                ctx.add_rule_conditional(ScmpAction::Allow, rule.syscall.id(), &rule.comparators)?;
            }
        }

        ctx.load()?;

        Ok(())
    }
}

#[derive(Debug, Error)]
/// The error type produced by [`SafetyContext`]
pub enum ExtraSafeError {
    #[error("extrasafe is only usable on Linux.")]
    /// Error created when trying to apply filters on non-Linux operating systems. Should never
    /// occur.
    UnsupportedOSError,
    #[error("A conditional rule on syscall `{0}` from RuleSet `{1}` would be overridden by a simple rule from RuleSet `{2}`.")]
    /// Error created when a simple rule would override a conditional rule.
    ConditionalNoEffectError(syscalls::Sysno, &'static str, &'static str),
    #[error("A libseccomp error occured. {0:?}")]
    /// An error from the underlying seccomp library.
    SeccompError(#[from] libseccomp::error::SeccompError),
}
