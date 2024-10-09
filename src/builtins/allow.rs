//! The `allow!`-macro to generate `allow_`-methods.

/// Generate a method-call chain of outer methods.
///
/// Note: This macro will not check,
///   whether dangerous methods are declared inside non-dangerous methods!
macro_rules! __allow_chain {
    // Without `unsafe`: Just call `$method()`.
    (
        $self:expr =>
        $(#[$_attr:meta])*
        $_vis:vis fn $method:ident($($_syscall:ident)?)
        $($rest:tt)*
    ) => {
        __allow_chain! { $self.$method() => $($rest)* }
    };

    // With `unsafe`: An `yes_really()` is required.
    (
        $self:expr =>
        $(#[$_attr:meta])*
        $_vis:vis unsafe fn $method:ident($($_syscall:ident)?)
        $($rest:tt)*
    ) => {
        __allow_chain! { $self.$method().yes_really() => $($rest)* }
    };

    // Ignore trailing `;` and inner declaration `{ … }`:
    ( $self:expr => ; $($rest:tt)* ) => { __allow_chain! { $self => $($rest)* } };
    ( $self:expr => { $($_inner:tt)* } $($rest:tt)* ) => { __allow_chain! { $self => $($rest)* } };

    // Nothing to match, processing the body of `__allow_chain!` is done.
    ( $self:expr => ) => { $self };
}

/// This is the internal implementation detail of [`allow!`].
///
/// This macro is necessary, because the outer-most methods of `allow!` might be dangerous and
///   whether or not the declaration of dangerous methods is allowed is indicated by `@dangerous`.
macro_rules! __allow {
    // Declare a method, that allows a single syscall.
    //
    // The generated methods returns `Self`.
    (
        $(@$dangerous:ident)?
        $(#[$attr:meta])*
        $vis:vis fn $method:ident($syscall:ident);

        $($rest:tt)*
    ) => {
        // Declare the method:
        $(#[$attr])*
        $vis fn $method(mut self) -> Self {
            let _ = self.syscalls.insert(syscalls::Sysno::$syscall);
            self
        }

        // Parse the rest:
        __allow! { $(@$dangerous)? $($rest)* }
    };

    // Declare a method, that allows multiple syscalls.
    //
    // The generated methods returns `Self`.
    (
        $(@$dangerous:ident)?
        $(#[$attr:meta])*
        $vis:vis fn $method:ident() {
            $($inner:tt)*
        }

        $($rest:tt)*
    ) => {
        // Declare the outer method:
        $(#[$attr])*
        $vis fn $method(self) -> Self {
            __allow_chain! { self => $($inner)* }
        }

        // Parse the inner methods. They must not be dangerous:
        __allow! { $($inner)* }

        // Parse the rest:
        __allow! { $(@$dangerous)? $($rest)* }
    };

    // Declare a dangerous method, that allows a single syscall.
    //
    // The generated outer method returns `YesReally<Self>`.
    //
    // The label `@dangerous` ensures,
    //   that dangerous inner methods can only be declared inside dangerous outer methods.
    (
        @dangerous
        $(#[$attr:meta])*
        $vis:vis unsafe fn $method:ident($syscall:ident);

        $($rest:tt)*
    ) => {
        // Declare the method:
        $(#[$attr])*
        $vis fn $method(mut self) -> YesReally<Self> {
            let _ = self.syscalls.insert(syscalls::Sysno::$syscall);
            YesReally::new(self)
        }

        // Parse the rest:
        __allow! { @dangerous $($rest)* }
    };

    // Declare a dangerous method, that allows multiple syscalls.
    //
    // The generated outer method returns `YesReally<Self>`.
    //
    // The label `@dangerous` ensures,
    //   that dangerous inner methods can only be declared inside dangerous outer methods.
    (
        @dangerous
        $(#[$attr:meta])*
        $vis:vis unsafe fn $method:ident() {
            $($inner:tt)*
        }

        $($rest:tt)*
    ) => {
        // Declare the outer method:
        $(#[$attr])*
        $vis fn $method(self) -> YesReally<Self> {
            YesReally::new(__allow_chain! { self => $($inner)* })
        }

        // Parse the inner methods. They might or might not be dangerous:
        __allow! { @dangerous $($inner)* }

        // Parse the rest:
        __allow! { @dangerous $($rest)* }
    };

    // Nothing to match, processing the body of `__allow!` is done.
    ( $(@dangerous)? ) => {};
}

/// Implement `allow_*`-methods.
///
/// The syntax is similar to the usual syntax of function signatures,
///   including documentation, attributes and visibility.
/// However, there are some differences:
///
/// * All methods declared inside a `allow! { … }` block have one or zero arguments:
///     If a method has an argument, it is the name of the syscall,
///       which will be concatenated to `syscalls::Sysno::`.
/// * If the argument is a syscall, the declaration must end with a semicolon,
///     otherwise, the declaration must end with block (`{ … }`)
///     with inner method-declarations.
/// * Methods, that are dangerous and should be confirmed with `yes_really`,
///     can be declared by putting the keyword `unsafe` in front of the `fn`.
/// * Inner dangerous methods can be declared as the outer-most methods
///     and inside a dangerous outer method only.
///
/// See e.g. `time.rs` and `user_id.rs`.
macro_rules! allow {
    // The outer-most methods can be dangerous.
    ($($tokens:tt)*) => { __allow! { @dangerous $( $tokens )* } };
}
