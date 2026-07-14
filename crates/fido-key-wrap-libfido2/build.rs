//! locates the supported system libfido2 library through pkg-config.

mod build_policy;

fn main() {
    let target = std::env::var("CARGO_CFG_TARGET_OS").expect("cargo must provide target os");
    build_policy::validate(&target, build_policy::LIBFIDO2_VERSION)
        .unwrap_or_else(|error| panic!("unsupported native fido build configuration: {error:?}"));

    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=LIBFIDO2_NO_PKG_CONFIG");

    pkg_config::Config::new()
        .exactly_version(build_policy::LIBFIDO2_VERSION)
        .probe("libfido2")
        .expect("exactly libfido2 1.17.0 must be visible through pkg-config");
}
