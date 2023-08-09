#![cfg(feature = "landlock")]

//! Contains landlock-specific types

use std::path::{Path, PathBuf};

pub use landlock::RulesetError as LandlockError;
pub use landlock::{ABI, Access, AccessFs, BitFlags, Compatible, CompatLevel, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr};

/// A Landlock rule. It consists of a path and a collection of access rights which determine what
/// actions can be performed on that path.
#[derive(Clone, Debug)]
pub struct LandlockRule {
    /// The path to apply the access rules to.
    pub path: PathBuf,
    /// The access rules, e.g. read, read/write, etc, to allow on the path.
    pub access_rules: BitFlags<AccessFs>,
}

impl LandlockRule {
    /// Create a new Landlock Rule.
    pub fn new(path: impl AsRef<Path>, access_rules: BitFlags<AccessFs>) -> LandlockRule {
        let path = path.as_ref().into();
        LandlockRule {
            path,
            access_rules
        }
    }
}

/// A [`LandlockRule`] labeled with the name of the [`RuleSet`] it originated from. Internal-only.
#[derive(Debug)]
pub(crate) struct LabeledLandlockRule(pub &'static str, pub LandlockRule);

/// Helper functions for Landlock access rights
pub mod access {
    use super::*;
    use landlock::AccessFs as Fs;
    /// Convenience function for landlock read file access right
    #[must_use]
    pub fn read_path() -> BitFlags<Fs> {
        Fs::ReadFile.into()
    }

    /// Convenience function for landlock write file access right
    #[must_use]
    pub fn write_file() -> BitFlags<AccessFs> {
        Fs::WriteFile.into()
    }

    /// Convenience function for landlock list dir access right
    #[must_use]
    pub fn list_dir() -> BitFlags<AccessFs> {
        Fs::ReadDir.into()
    }

    /// Convenience function for landlock create file access right
    #[must_use]
    pub fn create_file() -> BitFlags<AccessFs> {
        Fs::MakeReg.into()
    }

    /// Convenience function for landlock create dir access right
    #[must_use]
    pub fn create_dir() -> BitFlags<AccessFs> {
        Fs::MakeDir.into()
    }

    /// Convenience function for landlock delete file access right
    #[must_use]
    pub fn delete_file() -> BitFlags<AccessFs> {
        Fs::RemoveFile.into()
    }

    /// Convenience function for landlock delete dir access right
    #[must_use]
    pub fn delete_dir() -> BitFlags<AccessFs> {
        Fs::RemoveDir.into()
    }

    /// Convenience function for landlock execute access right
    #[must_use]
    pub fn execute() -> BitFlags<AccessFs> {
        Fs::Execute.into()
    }
}
