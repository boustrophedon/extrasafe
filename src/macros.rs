//! Macros for extrasafe

// Heavily inspired by the libseccomp-rs macros, but written from scratch.

/// A macro to easily create [`crate::SeccompArgumentFilter`]s. Note that because internally it uses a
/// helper macro, to use this macro you should just `use extrasafe::*` if possible.
/// Usage:
/// ```
/// use extrasafe::*;
/// // usage: `seccomp_arg_filter!(<argN> <operator> <value>);`
/// // or `seccomp_arg_filter!(<argN> & <mask> == <value>);`
/// // arg0 through arg5 are supported
/// // operations <=, <, >=, >, ==, != are supported
/// let argfilter = seccomp_arg_filter!(arg0 < 5);
/// // Masked equality is also supported to check specific bits are set.
/// // The following checks the second bit of the syscall's 4th argument is set.
/// let argfilter = seccomp_arg_filter!(arg4 & 0b10 == 0b10);
/// ```
#[macro_export]
macro_rules! seccomp_arg_filter {
    ($argno:ident <= $value:expr) => {
        $crate::SeccompArgumentFilter::new(
            match_argno!($argno),
            $crate::SeccompilerComparator::Le,
            $value,
        )
    };
    ($argno:ident < $value:expr) => {
        $crate::SeccompArgumentFilter::new(
            match_argno!($argno),
            $crate::SeccompilerComparator::Lt,
            $value,
        )
    };
    ($argno:ident >= $value:expr) => {
        $crate::SeccompArgumentFilter::new(
            match_argno!($argno),
            $crate::SeccompilerComparator::Ge,
            $value,
        )
    };
    ($argno:ident > $value:expr) => {
        $crate::SeccompArgumentFilter::new(
            match_argno!($argno),
            $crate::SeccompilerComparator::Gt,
            $value,
        )
    };
    ($argno:ident == $value:expr) => {
        $crate::SeccompArgumentFilter::new(
            match_argno!($argno),
            $crate::SeccompilerComparator::Eq,
            $value,
        )
    };
    ($argno:ident != $value:expr) => {
        $crate::SeccompArgumentFilter::new(
            match_argno!($argno),
            $crate::SeccompilerComparator::Ne,
            $value,
        )
    };
    ($argno:ident & $mask:tt == $value:expr) => {
        $crate::SeccompArgumentFilter::new(
            match_argno!($argno),
            $crate::SeccompilerComparator::MaskedEq($mask),
            $value,
        )
    };
    ($_other:expr) => {
        compile_error!(
            "usage: `arg[0-5] {<=, <, >=, >, ==, !=} <value>` or `arg[0-5] & <mask> == <value>`"
        )
    };
}

#[doc(hidden)]
#[macro_export]
/// Internal macro for `seccomp_arg_filter!`
macro_rules! match_argno {
    (arg0) => {
        0
    };
    (arg1) => {
        1
    };
    (arg2) => {
        2
    };
    (arg3) => {
        3
    };
    (arg4) => {
        4
    };
    (arg5) => {
        5
    };
    ($_other:expr) => {
        compile_error!("Seccomp argument filters must start with argX where X is 0-5")
    };
}

/// These tests just test that the macro expands correctly, not that the comparators do what they
/// say they do in seccompiler.
#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_comparison_le() {
        let cmp = seccomp_arg_filter!(arg0 <= 10);
        assert_eq!(
            cmp,
            SeccompArgumentFilter::new(0, SeccompilerComparator::Le, 10)
        );
    }

    #[test]
    fn test_comparison_lt() {
        let cmp = seccomp_arg_filter!(arg1 < 10);
        assert_eq!(
            cmp,
            SeccompArgumentFilter::new(1, SeccompilerComparator::Lt, 10)
        );
    }

    #[test]
    fn test_comparison_ge() {
        let cmp = seccomp_arg_filter!(arg2 >= 5);
        assert_eq!(
            cmp,
            SeccompArgumentFilter::new(2, SeccompilerComparator::Ge, 5)
        );
    }

    #[test]
    fn test_comparison_gt() {
        let cmp = seccomp_arg_filter!(arg3 > 200);
        assert_eq!(
            cmp,
            SeccompArgumentFilter::new(3, SeccompilerComparator::Gt, 200)
        );
    }

    #[test]
    fn test_comparison_eq() {
        let cmp = seccomp_arg_filter!(arg4 == 0);
        assert_eq!(
            cmp,
            SeccompArgumentFilter::new(4, SeccompilerComparator::Eq, 0)
        );
    }

    #[test]
    fn test_comparison_ne() {
        let cmp = seccomp_arg_filter!(arg5 != 80);
        assert_eq!(
            cmp,
            SeccompArgumentFilter::new(5, SeccompilerComparator::Ne, 80)
        );
    }

    #[test]
    fn test_comparison_mask() {
        let cmp = seccomp_arg_filter!(arg2 & 0x1337 == 0x37);
        assert_eq!(
            cmp,
            SeccompArgumentFilter::new(2, SeccompilerComparator::MaskedEq(0x1337), 0x37)
        );
    }
}
