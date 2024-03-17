//! Extrasafe error types

use std::fmt;

#[cfg(feature = "landlock")]
use std::path::PathBuf;

use seccompiler::Error as SeccompilerError;

#[cfg(feature = "landlock")]
use landlock::RulesetError as LandlockError;
#[cfg(feature = "landlock")]
use landlock::PathFdError;

#[derive(Debug)]
/// The error type produced by [`crate::SafetyContext`]
pub enum ExtraSafeError {
    /// Error created when a simple Seccomp rule would override a conditional rule, or when trying to add a
    /// conditional rule when there's already a simple rule with the same syscall.
    ConditionalNoEffectError(crate::syscalls::Sysno, &'static str, &'static str),
    /// An error from the underlying seccomp library.
    SeccompError(SeccompilerError),
    /// No rules were enabled in the SafetyContext.
    NoRulesEnabled,
    #[cfg(feature = "landlock")]
    /// Two landlock rules with the same path were added.
    DuplicatePath(PathBuf, &'static str, &'static str),
    #[cfg(feature = "landlock")]
    /// The path provided to extrasafe in a Landlock rule does not exist or the process does not
    /// have permission to access it.
    PathDoesNotExist(PathFdError),
    #[cfg(feature = "landlock")]
    /// Conflicting landlock and seccomp rules were added. Unused.
    LandlockSeccompConflict(&'static str, &'static str),
    #[cfg(feature = "landlock")]
    /// Landlock does not support being applied to all threads.
    LandlockNoThreadSync,
    #[cfg(feature = "landlock")]
    /// An error from the underlying landlock library.
    LandlockError(LandlockError),
}

impl fmt::Display for ExtraSafeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &Self::ConditionalNoEffectError(sysno, a, b) => write!(
                f,
                "A conditional rule on syscall `{}` from RuleSet `{}` would be overridden \
                by a simple rule from RuleSet `{}`.",
                sysno, a, b,
            ),
            Self::SeccompError(err) => write!(f, "A seccomp error occured {:?}", err),
            Self::NoRulesEnabled => write!(f, "No rules were enabled in the SafetyContext"),
            #[cfg(feature = "landlock")]
            Self::DuplicatePath(path, a, b) => write!(f, "The same path ({:?}) was used in two different landlock rules. Rulesets '{}' and '{}'", path, a, b),
            #[cfg(feature = "landlock")]
            Self::PathDoesNotExist(path_error) => write!(f, "Path provided to extrasafe in a landlock rule does not exist or the process does not have permission to access it: {:?}", path_error),
            #[cfg(feature = "landlock")]
            Self::LandlockSeccompConflict(a, b) => write!(f, "A seccomp rule and a landlock rule are in conflict. See RuleSets {} and {}", a, b),
            #[cfg(feature = "landlock")]
            Self::LandlockError(err) => write!(f, "A Landlock error occurred: {:?}", err),
            #[cfg(feature = "landlock")]
            Self::LandlockNoThreadSync => write!(f, "Landlock does not support syncing to all threads"),
        }
    }
}

impl From<SeccompilerError> for ExtraSafeError {
    fn from(value: SeccompilerError) -> Self {
        Self::SeccompError(value)
    }
}

impl From<seccompiler::BackendError> for ExtraSafeError {
    fn from(value: seccompiler::BackendError) -> Self {
        Self::SeccompError(SeccompilerError::from(value))
    }
}

impl std::error::Error for ExtraSafeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConditionalNoEffectError(..) => None,
            Self::NoRulesEnabled => None,
            Self::SeccompError(err) => Some(err),
            #[cfg(feature = "landlock")]
            Self::DuplicatePath(_, _, _) => None,
            #[cfg(feature = "landlock")]
            Self::PathDoesNotExist(pathfd_err) => Some(pathfd_err),
            #[cfg(feature = "landlock")]
            Self::LandlockSeccompConflict(_, _) => None,
            #[cfg(feature = "landlock")]
            Self::LandlockError(err) => Some(err),
            #[cfg(feature = "landlock")]
            Self::LandlockNoThreadSync => None,
        }
    }
}

#[cfg(feature = "landlock")]
impl From<LandlockError> for ExtraSafeError {
    fn from(value: LandlockError) -> Self {
        Self::LandlockError(value)
    }
}

#[cfg(feature = "landlock")]
impl From<PathFdError> for ExtraSafeError {
    fn from(value: PathFdError) -> Self {
        Self::PathDoesNotExist(value)
    }
}
