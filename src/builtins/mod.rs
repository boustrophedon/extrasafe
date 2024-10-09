//! Built-in [`RuleSet`](crate::RuleSet)s

#[macro_use]
pub mod allow;

pub mod basic;
pub mod danger_zone;
pub mod network;
pub mod pipes;
pub mod systemio;
pub mod time;
pub mod user_id;

pub use self::{
    basic::BasicCapabilities, network::Networking, systemio::SystemIO, time::Time, user_id::UserId,
};

/// A struct whose purpose is to make you read the documentation for the function you're calling.
/// If you're reading this, go read the documentation for the function that is returning this
/// object.
#[must_use]
pub struct YesReally<T> {
    inner: T,
}

impl<T> YesReally<T> {
    /// Confirm you really wanted to call the function and return its result.
    pub fn yes_really(self) -> T {
        self.inner
    }

    /// Make a [`YesReally`].
    pub fn new(inner: T) -> YesReally<T> {
        YesReally { inner }
    }
}
