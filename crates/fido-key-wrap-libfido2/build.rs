//! locates the supported system libfido2 library through pkg-config.

fn main() {
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=LIBFIDO2_NO_PKG_CONFIG");

    pkg_config::Config::new()
        .range_version("1.17.0".."2.0.0")
        .probe("libfido2")
        .expect("libfido2 >= 1.17.0 and < 2.0.0 must be visible through pkg-config");
}
