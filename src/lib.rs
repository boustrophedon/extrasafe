use seccomp::*;
use thiserror::Error;

mod builtin_policies;
pub use builtin_policies::*;

pub trait BasicPolicy {
    /// A list of syscalls that will be allowed or denied based on usage with SafetyContext.
    fn syscalls(&self) -> Vec<syscalls::Sysno>;
}

pub trait CustomPolicy {
    /// A list of seccomp rules that will be applied to the context. Note that the policy itself
    /// decides whether the syscalls are allowed, denied, or something else.
    fn rules(&self) -> Vec<seccomp::Rule>;
}

#[derive(Debug, PartialEq)]
enum DefaultAction {
    Allow,
    Deny,
    // TODO
    //Notify,
}

#[must_use]
pub struct SafetyContext {
    default_action: DefaultAction,
    allow: Vec<Box<dyn BasicPolicy>>,
    deny: Vec<Box<dyn BasicPolicy>>,
    custom_policies: Vec<Box<dyn CustomPolicy>>,
}

impl SafetyContext {
    fn new(default_action: DefaultAction) -> SafetyContext {
        SafetyContext {
            default_action: default_action,
            allow: Vec::new(),
            deny: Vec::new(),
            custom_policies: Vec::new(),
        }
    }

    /// Create a new SafetyContext with a default-allow policy.
    pub fn default_allow() -> SafetyContext {
        SafetyContext::new(DefaultAction::Allow)
    }

    /// Create a new SafetyContext with a default-deny policy. This is safer than default-allow but
    /// more work to maintain.
    pub fn default_deny() -> SafetyContext {
        SafetyContext::new(DefaultAction::Deny)
    }

    /// Allow the operations related to this policy. If policy is default-allow, this is will error
    /// to prevent unintentional bad usage.
    pub fn allow(mut self, policy: impl BasicPolicy + 'static) -> Result<SafetyContext, ExtraSafeError> {
        if self.default_action == DefaultAction::Allow {
            return Err(ExtraSafeError::BadPolicy);
        }

        self.allow.push(Box::new(policy));

        Ok(self)
    }

    /// Deny the operations related to this policy.
    pub fn deny(mut self, policy: impl BasicPolicy + 'static) -> SafetyContext {
        // TODO: if we pass a policy that's already boxed we're double-boxing here
        self.deny.push(Box::new(policy));

        self
    }

    /// Add a custom policy that just provides a seccomp rule directly - allow, deny, etc.
    pub fn custom_policy(mut self, policy: impl CustomPolicy + 'static) -> SafetyContext {
        self.custom_policies.push(Box::new(policy));

        self
    }

    pub fn load(self) -> Result<(), ExtraSafeError> {
        let seccomp_action = match self.default_action {
            DefaultAction::Allow => seccomp::Action::Allow,
            DefaultAction::Deny => seccomp::Action::Errno(libc::EPERM),
        };
        let mut ctx = Context::default(seccomp_action)?;

        for policy in self.allow {
            for syscall in policy.syscalls() {
                ctx.add_rule(Rule::new(syscall.id() as usize, None, seccomp::Action::Allow))?;
            }
        }
        for policy in self.deny {
            for syscall in policy.syscalls() {
                ctx.add_rule(Rule::new(syscall.id() as usize, None, seccomp::Action::Errno(libc::EPERM)))?;
            }
        }

        for policy in self.custom_policies {
            for rule in policy.rules() {
                ctx.add_rule(rule)?;
            }
        }

        ctx.load()?;

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ExtraSafeError {
    #[error("Tried to add an allow policy in a default-allow context.")]
    BadPolicy,
    #[error("A libseccomp error occured. {0:?}")]
    SeccompError(#[from] SeccompError)
}
