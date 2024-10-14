//! Ready to use [`RuleSet`](crate::RuleSet)s.

pub mod danger_zone;
pub mod network;
pub mod pipes;
pub mod systemio;
pub mod time;

pub use {
    self::{network::Networking, systemio::SystemIO, time::Time},
    extrasafe::basic_ruleset::BasicRuleset,
};

/// DEPRECATED: Use [`BasicRuleset`]!
pub type BasicCapabilities = BasicRuleset;
