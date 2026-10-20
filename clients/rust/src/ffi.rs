//! Raw bindings for `vault_native.h`, written by hand. `bindgen` would generate the
//! same declarations; writing them out keeps the project dependency-free and makes
//! each type mapping visible. The assertions at the bottom fail the build if the
//! layouts drift from the header.

use std::ffi::{c_char, c_void};
use std::marker::{PhantomData, PhantomPinned};
use std::mem::{offset_of, size_of};

pub type VaultStatus = i32;

pub const VAULT_OK: VaultStatus = 0;
pub const VAULT_ERR_INVALID_ARGUMENT: VaultStatus = 1;
pub const VAULT_ERR_BUFFER_TOO_SMALL: VaultStatus = 2;
pub const VAULT_ERR_AUTHENTICATION_FAILED: VaultStatus = 3;

/// `vault_t`: opaque, only ever used behind a pointer. The marker makes it
/// `!Send`, `!Sync` and `!Unpin`, the recommended shape for foreign opaque types.
#[repr(C)]
pub struct Vault {
    _data: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// `vault_info_t`. Rust `bool` is 1 byte, like C `bool`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct VaultInfo {
    pub key_id: u64,
    pub key_bits: u32,
    pub hardware_accelerated: bool,
}

/// `vault_sealed_t`. `size_t` maps to `usize`.
#[repr(C)]
pub struct VaultSealed {
    pub nonce: *mut u8,
    pub nonce_len: usize,
    pub ciphertext: *mut u8,
    pub ciphertext_len: usize,
    pub tag: *mut u8,
    pub tag_len: usize,
}

/// `vault_encrypt_callback`.
pub type VaultEncryptCallback =
    unsafe extern "C" fn(status: VaultStatus, sealed: *mut VaultSealed, user_data: *mut c_void);

unsafe extern "C" {
    pub fn vault_version() -> *const c_char;
    pub fn vault_status_message(status: VaultStatus) -> *const c_char;
    pub fn vault_open(key: *const u8, key_len: usize, out_vault: *mut *mut Vault) -> VaultStatus;
    pub fn vault_close(vault: *mut Vault);
    pub fn vault_get_info(vault: *const Vault, out_info: *mut VaultInfo) -> VaultStatus;
    pub fn vault_encrypt_async(
        vault: *const Vault,
        plaintext: *const u8,
        plaintext_len: usize,
        callback: VaultEncryptCallback,
        user_data: *mut c_void,
    ) -> VaultStatus;
    pub fn vault_sealed_free(sealed: *mut VaultSealed);
    pub fn vault_decrypt(
        vault: *const Vault,
        sealed: *const VaultSealed,
        output: *mut u8,
        output_capacity: usize,
        out_written: *mut usize,
    ) -> VaultStatus;
}

// Same checks as the _Static_asserts in vault_native.h.
const _: () = assert!(size_of::<VaultInfo>() == 16);
const _: () = assert!(offset_of!(VaultInfo, hardware_accelerated) == 12);
const _: () = assert!(size_of::<VaultSealed>() == 6 * size_of::<usize>());
