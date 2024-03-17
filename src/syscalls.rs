//! Syscalls export
//! This module re-exports syscalls for the target architecture.

#[cfg(all(feature = "x86_64", feature = "__aarch64"))]
compile_error!("feature \"x86_64\" and feature \"aarch64\" cannot be enabled at the same time!");
#[cfg(all(feature = "x86_64", feature = "__riscv64"))]
compile_error!("feature \"x86_64\" and feature \"riscv64\" cannot be enabled at the same time!");
#[cfg(all(feature = "__riscv64", feature = "__aarch64"))]
compile_error!("feature \"riscv64\" and feature \"aarch64\" cannot be enabled at the same time!");

#[cfg(all(
    any(feature = "x86_64", target_arch = "x86_64"),
    not(any(feature = "aarch64", feature = "riscv64"))
))]
pub use syscalls::x86_64::*;
#[cfg(all(
    any(feature = "aarch64", target_arch = "aarch64"),
    not(any(feature = "x86_64", feature = "riscv64"))
))]
pub use syscalls::aarch64::*;
#[cfg(all(
    any(feature = "riscv64", target_arch = "riscv64"),
    not(any(feature = "x86_64", feature = "aarch64"))
))]
pub use syscalls::riscv64::*;
