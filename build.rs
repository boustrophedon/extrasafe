fn main() {
    // prefer method A if both method A and B are selected
    if cfg!(feature = "__aarch64") || cfg!(target_arch = "aarch64") {
        println!("cargo:rustc-cfg=enabled_arch=\"aarch64\"");
    } else if cfg!(feature = "__riscv64") || cfg!(target_arch = "riscv64") {
        println!("cargo:rustc-cfg=enabled_arch=\"riscv64\"");
    } else if cfg!(feature = "__x86_64") || cfg!(target_arch = "x86_64") {
        println!("cargo:rustc-cfg=enabled_arch=\"x86_64\"");
    } else {
        panic!("No architecture feature enabled and no supported architecture detected. Please enable one of the following features: x86_64, aarch64, riscv64");
    }
}
