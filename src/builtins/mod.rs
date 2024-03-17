//! Built-in [`RuleSet`](crate::RuleSet)s

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
        YesReally {
            inner,
        }
    }
}

pub mod basic;
pub use basic::BasicCapabilities;

pub mod systemio;
pub use systemio::SystemIO;

pub mod network;
pub use network::Networking;

pub mod time;
pub use time::Time;

pub mod danger_zone;
pub mod pipes;
