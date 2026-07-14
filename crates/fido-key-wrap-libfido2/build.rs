//! locates the supported system libfido2 library through pkg-config.

mod build_policy;

fn main() {
    let target = std::env::var("CARGO_CFG_TARGET_OS").expect("cargo must provide target os");
    build_policy::validate_target(&target)
        .unwrap_or_else(|error| panic!("unsupported native fido build configuration: {error:?}"));

    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=LIBFIDO2_NO_PKG_CONFIG");

    pkg_config::Config::new()
        .range_version(build_policy::LIBFIDO2_MIN_VERSION..build_policy::LIBFIDO2_NEXT_MAJOR)
        .probe("libfido2")
        .expect("libfido2 >= 1.14.0 and < 2.0.0 must be visible through pkg-config");
}
