//! declarations for the libfido2 functions used by the backend.
//!
//! signatures follow the public libfido2 1.x `fido.h` abi from version 1.14.

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_uchar, c_void};

#[repr(C)]
pub struct fido_assert_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct fido_cbor_info_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct fido_cred_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct fido_dev_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct fido_dev_info_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct es256_pk_t {
    _private: [u8; 0],
}

pub const FIDO_DISABLE_U2F_FALLBACK: c_int = 0x02;
pub const FIDO_OK: c_int = 0x00;
pub const FIDO_ERR_TIMEOUT: c_int = 0x05;
pub const FIDO_ERR_CHANNEL_BUSY: c_int = 0x06;
pub const FIDO_ERR_UNSUPPORTED_EXTENSION: c_int = 0x16;
pub const FIDO_ERR_UNSUPPORTED_ALGORITHM: c_int = 0x26;
pub const FIDO_ERR_OPERATION_DENIED: c_int = 0x27;
pub const FIDO_ERR_UNSUPPORTED_OPTION: c_int = 0x2b;
pub const FIDO_ERR_KEEPALIVE_CANCEL: c_int = 0x2d;
pub const FIDO_ERR_NO_CREDENTIALS: c_int = 0x2e;
pub const FIDO_ERR_USER_ACTION_TIMEOUT: c_int = 0x2f;
pub const FIDO_ERR_NOT_ALLOWED: c_int = 0x30;
pub const FIDO_ERR_PIN_INVALID: c_int = 0x31;
pub const FIDO_ERR_PIN_BLOCKED: c_int = 0x32;
pub const FIDO_ERR_PIN_AUTH_BLOCKED: c_int = 0x34;
pub const FIDO_ERR_PIN_NOT_SET: c_int = 0x35;
pub const FIDO_ERR_PIN_REQUIRED: c_int = 0x36;
pub const FIDO_ERR_ACTION_TIMEOUT: c_int = 0x3a;
pub const FIDO_ERR_UV_BLOCKED: c_int = 0x3c;
pub const FIDO_ERR_UV_INVALID: c_int = 0x3f;
pub const FIDO_ERR_TX: c_int = -1;
pub const FIDO_ERR_RX: c_int = -2;
pub const FIDO_ERR_INVALID_SIG: c_int = -6;
pub const FIDO_ERR_USER_PRESENCE_REQUIRED: c_int = -8;
pub const FIDO_ERR_INTERNAL: c_int = -9;

pub const FIDO_OPT_FALSE: c_int = 1;
pub const FIDO_OPT_TRUE: c_int = 2;

pub const FIDO_EXT_HMAC_SECRET: c_int = 0x01;
pub const FIDO_EXT_CRED_PROTECT: c_int = 0x02;
pub const FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID: c_int = 0x02;
pub const FIDO_CRED_PROT_UV_REQUIRED: c_int = 0x03;
pub const COSE_ES256: c_int = -7;

pub const AUTHDATA_UP: u8 = 0x01;
pub const AUTHDATA_UV: u8 = 0x04;
// CTAP 2.2/WebAuthn backup flags. libfido2 exposes the complete signed flags
// byte but does not provide public constants for these two bits.
pub const AUTHDATA_BE: u8 = 0x08;
pub const AUTHDATA_BS: u8 = 0x10;

unsafe extern "C" {
    pub fn fido_init(flags: c_int);

    pub fn es256_pk_new() -> *mut es256_pk_t;
    pub fn es256_pk_free(public_key: *mut *mut es256_pk_t);
    pub fn es256_pk_from_ptr(
        public_key: *mut es256_pk_t,
        bytes: *const c_void,
        len: usize,
    ) -> c_int;

    pub fn fido_dev_info_new(n: usize) -> *mut fido_dev_info_t;
    pub fn fido_dev_info_free(list: *mut *mut fido_dev_info_t, n: usize);
    pub fn fido_dev_info_manifest(
        list: *mut fido_dev_info_t,
        slots: usize,
        found: *mut usize,
    ) -> c_int;
    pub fn fido_dev_info_ptr(list: *const fido_dev_info_t, index: usize) -> *const fido_dev_info_t;
    pub fn fido_dev_info_path(info: *const fido_dev_info_t) -> *const c_char;
    pub fn fido_dev_info_manufacturer_string(info: *const fido_dev_info_t) -> *const c_char;
    pub fn fido_dev_info_product_string(info: *const fido_dev_info_t) -> *const c_char;

    pub fn fido_dev_new() -> *mut fido_dev_t;
    pub fn fido_dev_free(dev: *mut *mut fido_dev_t);
    pub fn fido_dev_open(dev: *mut fido_dev_t, path: *const c_char) -> c_int;
    pub fn fido_dev_close(dev: *mut fido_dev_t) -> c_int;
    pub fn fido_dev_set_timeout(dev: *mut fido_dev_t, milliseconds: c_int) -> c_int;
    pub fn fido_dev_is_fido2(dev: *const fido_dev_t) -> bool;
    pub fn fido_dev_has_pin(dev: *const fido_dev_t) -> bool;
    pub fn fido_dev_supports_pin(dev: *const fido_dev_t) -> bool;
    pub fn fido_dev_has_uv(dev: *const fido_dev_t) -> bool;
    pub fn fido_dev_supports_uv(dev: *const fido_dev_t) -> bool;
    pub fn fido_dev_supports_cred_prot(dev: *const fido_dev_t) -> bool;
    pub fn fido_dev_get_retry_count(dev: *mut fido_dev_t, retries: *mut c_int) -> c_int;
    pub fn fido_dev_get_touch_begin(dev: *mut fido_dev_t) -> c_int;
    pub fn fido_dev_get_touch_status(
        dev: *mut fido_dev_t,
        touched: *mut c_int,
        milliseconds: c_int,
    ) -> c_int;
    pub fn fido_dev_cancel(dev: *mut fido_dev_t) -> c_int;

    pub fn fido_cbor_info_new() -> *mut fido_cbor_info_t;
    pub fn fido_cbor_info_free(info: *mut *mut fido_cbor_info_t);
    pub fn fido_dev_get_cbor_info(dev: *mut fido_dev_t, info: *mut fido_cbor_info_t) -> c_int;
    pub fn fido_cbor_info_extensions_ptr(info: *const fido_cbor_info_t) -> *mut *mut c_char;
    pub fn fido_cbor_info_extensions_len(info: *const fido_cbor_info_t) -> usize;
    pub fn fido_cbor_info_options_name_ptr(info: *const fido_cbor_info_t) -> *mut *mut c_char;
    pub fn fido_cbor_info_options_value_ptr(info: *const fido_cbor_info_t) -> *const bool;
    pub fn fido_cbor_info_options_len(info: *const fido_cbor_info_t) -> usize;
    pub fn fido_cbor_info_versions_ptr(info: *const fido_cbor_info_t) -> *mut *mut c_char;
    pub fn fido_cbor_info_versions_len(info: *const fido_cbor_info_t) -> usize;
    pub fn fido_cbor_info_algorithm_count(info: *const fido_cbor_info_t) -> usize;
    pub fn fido_cbor_info_algorithm_cose(info: *const fido_cbor_info_t, index: usize) -> c_int;

    pub fn fido_cred_new() -> *mut fido_cred_t;
    pub fn fido_cred_free(credential: *mut *mut fido_cred_t);
    pub fn fido_cred_set_clientdata_hash(
        credential: *mut fido_cred_t,
        hash: *const c_uchar,
        len: usize,
    ) -> c_int;
    pub fn fido_cred_set_rp(
        credential: *mut fido_cred_t,
        id: *const c_char,
        name: *const c_char,
    ) -> c_int;
    pub fn fido_cred_set_user(
        credential: *mut fido_cred_t,
        id: *const c_uchar,
        id_len: usize,
        name: *const c_char,
        display_name: *const c_char,
        icon: *const c_char,
    ) -> c_int;
    pub fn fido_cred_set_type(credential: *mut fido_cred_t, cose: c_int) -> c_int;
    pub fn fido_cred_set_extensions(credential: *mut fido_cred_t, extensions: c_int) -> c_int;
    pub fn fido_cred_set_prot(credential: *mut fido_cred_t, protection: c_int) -> c_int;
    pub fn fido_cred_set_rk(credential: *mut fido_cred_t, option: c_int) -> c_int;
    pub fn fido_cred_set_uv(credential: *mut fido_cred_t, option: c_int) -> c_int;
    pub fn fido_dev_make_cred(
        dev: *mut fido_dev_t,
        credential: *mut fido_cred_t,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_cred_fmt(credential: *const fido_cred_t) -> *const c_char;
    pub fn fido_cred_verify(credential: *const fido_cred_t) -> c_int;
    pub fn fido_cred_verify_self(credential: *const fido_cred_t) -> c_int;
    pub fn fido_cred_flags(credential: *const fido_cred_t) -> u8;
    pub fn fido_cred_prot(credential: *const fido_cred_t) -> c_int;
    pub fn fido_cred_type(credential: *const fido_cred_t) -> c_int;
    pub fn fido_cred_id_ptr(credential: *const fido_cred_t) -> *const c_uchar;
    pub fn fido_cred_id_len(credential: *const fido_cred_t) -> usize;
    pub fn fido_cred_pubkey_ptr(credential: *const fido_cred_t) -> *const c_uchar;
    pub fn fido_cred_pubkey_len(credential: *const fido_cred_t) -> usize;
    pub fn fido_cred_x5c_ptr(credential: *const fido_cred_t) -> *const c_uchar;
    pub fn fido_cred_x5c_len(credential: *const fido_cred_t) -> usize;

    pub fn fido_assert_new() -> *mut fido_assert_t;
    pub fn fido_assert_free(assertion: *mut *mut fido_assert_t);
    pub fn fido_assert_set_rp(assertion: *mut fido_assert_t, id: *const c_char) -> c_int;
    pub fn fido_assert_set_clientdata_hash(
        assertion: *mut fido_assert_t,
        hash: *const c_uchar,
        len: usize,
    ) -> c_int;
    #[cfg(test)]
    pub fn fido_assert_set_count(assertion: *mut fido_assert_t, count: usize) -> c_int;
    #[cfg(test)]
    pub fn fido_assert_set_authdata_raw(
        assertion: *mut fido_assert_t,
        index: usize,
        authdata: *const c_uchar,
        len: usize,
    ) -> c_int;
    #[cfg(test)]
    pub fn fido_assert_set_sig(
        assertion: *mut fido_assert_t,
        index: usize,
        signature: *const c_uchar,
        len: usize,
    ) -> c_int;
    pub fn fido_assert_allow_cred(
        assertion: *mut fido_assert_t,
        credential_id: *const c_uchar,
        len: usize,
    ) -> c_int;
    pub fn fido_assert_set_extensions(assertion: *mut fido_assert_t, extensions: c_int) -> c_int;
    pub fn fido_assert_set_hmac_salt(
        assertion: *mut fido_assert_t,
        salt: *const c_uchar,
        len: usize,
    ) -> c_int;
    pub fn fido_assert_set_up(assertion: *mut fido_assert_t, option: c_int) -> c_int;
    pub fn fido_assert_set_uv(assertion: *mut fido_assert_t, option: c_int) -> c_int;
    pub fn fido_dev_get_assert(
        dev: *mut fido_dev_t,
        assertion: *mut fido_assert_t,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_assert_count(assertion: *const fido_assert_t) -> usize;
    pub fn fido_assert_id_ptr(assertion: *const fido_assert_t, index: usize) -> *const c_uchar;
    pub fn fido_assert_id_len(assertion: *const fido_assert_t, index: usize) -> usize;
    pub fn fido_assert_verify(
        assertion: *const fido_assert_t,
        index: usize,
        cose: c_int,
        public_key: *const c_void,
    ) -> c_int;
    pub fn fido_assert_flags(assertion: *const fido_assert_t, index: usize) -> u8;
    pub fn fido_assert_hmac_secret_ptr(
        assertion: *const fido_assert_t,
        index: usize,
    ) -> *const c_uchar;
    pub fn fido_assert_hmac_secret_len(assertion: *const fido_assert_t, index: usize) -> usize;
}
