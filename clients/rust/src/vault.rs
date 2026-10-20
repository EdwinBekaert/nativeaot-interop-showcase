//! Safe wrapper over the raw bindings. Every `unsafe` block lives in this file, and
//! each one states why it is sound. Callers get ordinary Rust: values that free
//! themselves, `Result` for errors, and closures for async completion.

use std::ffi::{CStr, c_void};
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{self, NonNull};

use crate::ffi;

/// A non-OK status from the library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultError(pub ffi::VaultStatus);

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (status {})", status_message(self.0), self.0)
    }
}

impl std::error::Error for VaultError {}

fn check(status: ffi::VaultStatus) -> Result<(), VaultError> {
    if status == ffi::VAULT_OK {
        Ok(())
    } else {
        Err(VaultError(status))
    }
}

/// Library version. Borrowed from static library memory, so `'static`.
pub fn version() -> &'static str {
    // SAFETY: vault_version returns a NUL-terminated string valid for the process lifetime.
    unsafe { CStr::from_ptr(ffi::vault_version()) }
        .to_str()
        .unwrap_or("?")
}

/// Readable text for a status code. Static library memory, like `version`.
pub fn status_message(status: ffi::VaultStatus) -> &'static str {
    // SAFETY: vault_status_message returns a static NUL-terminated string for any input.
    unsafe { CStr::from_ptr(ffi::vault_status_message(status)) }
        .to_str()
        .unwrap_or("?")
}

/// The completion closure, type-erased so it can travel through C as `void*`.
type Callback = Box<dyn FnOnce(Result<Sealed, VaultError>) + Send>;

/// An open vault. Owns the library handle and closes it on drop.
pub struct VaultHandle(NonNull<ffi::Vault>);

impl VaultHandle {
    pub fn open(key: &[u8]) -> Result<Self, VaultError> {
        let mut raw = ptr::null_mut();
        // SAFETY: key is valid for key.len() bytes and only read during the call;
        // raw is a valid out-pointer.
        check(unsafe { ffi::vault_open(key.as_ptr(), key.len(), &mut raw) })?;
        NonNull::new(raw)
            .map(Self)
            .ok_or(VaultError(ffi::VAULT_ERR_INVALID_ARGUMENT))
    }

    pub fn info(&self) -> Result<ffi::VaultInfo, VaultError> {
        let mut info = ffi::VaultInfo::default();
        // SAFETY: the handle is open; info is a valid out-pointer to caller-owned memory.
        check(unsafe { ffi::vault_get_info(self.0.as_ptr(), &mut info) })?;
        Ok(info)
    }

    /// Starts an encryption and returns at once. `on_done` runs exactly once, on a
    /// library worker thread, with the result.
    pub fn encrypt_async<F>(&self, plaintext: &[u8], on_done: F) -> Result<(), VaultError>
    where
        F: FnOnce(Result<Sealed, VaultError>) + Send + 'static,
    {
        // The closure travels through C as user_data: box it (a fat Box<dyn FnOnce>
        // inside a thin Box, so it fits in one void*) and leak it to a raw pointer.
        // The trampoline takes ownership back.
        let boxed: Box<Callback> = Box::new(Box::new(on_done));
        let user_data = Box::into_raw(boxed).cast::<c_void>();

        // SAFETY: the plaintext is copied before the call returns; trampoline matches
        // vault_encrypt_callback; user_data is a valid pointer from Box::into_raw.
        let status = unsafe {
            ffi::vault_encrypt_async(
                self.0.as_ptr(),
                plaintext.as_ptr(),
                plaintext.len(),
                trampoline,
                user_data,
            )
        };
        if status != ffi::VAULT_OK {
            // The callback will never run, so reclaim the closure here.
            // SAFETY: user_data came from Box::into_raw above and was not handed on.
            drop(unsafe { Box::from_raw(user_data.cast::<Callback>()) });
        }
        check(status)
    }

    /// Plaintext size for `sealed`, using the library's size query (output = NULL).
    pub fn plaintext_len(&self, sealed: &Sealed) -> Result<usize, VaultError> {
        let mut needed = 0;
        // SAFETY: a NULL output with capacity 0 is the documented size query.
        let status = unsafe {
            ffi::vault_decrypt(
                self.0.as_ptr(),
                sealed.0.as_ptr(),
                ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        match status {
            // VAULT_OK: an empty plaintext, already verified, needs no buffer.
            ffi::VAULT_ERR_BUFFER_TOO_SMALL | ffi::VAULT_OK => Ok(needed),
            other => Err(VaultError(other)),
        }
    }

    /// Decrypts into a new `Vec`: size query, allocate, decrypt.
    pub fn decrypt(&self, sealed: &Sealed) -> Result<Vec<u8>, VaultError> {
        let mut output = vec![0u8; self.plaintext_len(sealed)?];
        let mut written = 0;
        // SAFETY: output is caller-owned and valid for output.len() bytes.
        check(unsafe {
            ffi::vault_decrypt(
                self.0.as_ptr(),
                sealed.0.as_ptr(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
            )
        })?;
        output.truncate(written);
        Ok(output)
    }
}

impl Drop for VaultHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from vault_open and is closed exactly once, here.
        unsafe { ffi::vault_close(self.0.as_ptr()) }
    }
}

/// The C callback. Recovers the boxed closure from user_data and calls it.
unsafe extern "C" fn trampoline(
    status: ffi::VaultStatus,
    sealed: *mut ffi::VaultSealed,
    user_data: *mut c_void,
) {
    // SAFETY: user_data is the pointer encrypt_async made with Box::into_raw, and the
    // library calls back exactly once, so ownership is taken back exactly once.
    let on_done = unsafe { Box::from_raw(user_data.cast::<Callback>()) };
    let result = match NonNull::new(sealed) {
        Some(sealed) if status == ffi::VAULT_OK => Ok(Sealed(sealed)),
        _ => Err(VaultError(status)),
    };
    // A panic must not unwind into C# (Rust would abort the process anyway).
    if catch_unwind(AssertUnwindSafe(|| on_done(result))).is_err() {
        eprintln!("vault callback panicked");
    }
}

/// An encryption result. Owns library memory and frees it on drop.
pub struct Sealed(NonNull<ffi::VaultSealed>);

// SAFETY: the result is plain memory owned by this value alone; the library lets it
// be read and freed from any thread.
unsafe impl Send for Sealed {}

impl Sealed {
    pub fn nonce(&self) -> &[u8] {
        let s = self.raw();
        // SAFETY: the library guarantees nonce points to nonce_len bytes while we own it.
        unsafe { bytes(s.nonce, s.nonce_len) }
    }

    pub fn ciphertext(&self) -> &[u8] {
        let s = self.raw();
        // SAFETY: as above, for the ciphertext.
        unsafe { bytes(s.ciphertext, s.ciphertext_len) }
    }

    pub fn tag(&self) -> &[u8] {
        let s = self.raw();
        // SAFETY: as above, for the tag.
        unsafe { bytes(s.tag, s.tag_len) }
    }

    /// Mutable access to the tag, to demonstrate tamper detection.
    pub fn tag_mut(&mut self) -> &mut [u8] {
        let (tag, tag_len) = (self.raw().tag, self.raw().tag_len);
        if tag_len == 0 {
            return &mut [];
        }
        // SAFETY: we own the result exclusively (&mut self), and tag points to tag_len bytes.
        unsafe { std::slice::from_raw_parts_mut(tag, tag_len) }
    }

    fn raw(&self) -> &ffi::VaultSealed {
        // SAFETY: the pointer stays valid until drop.
        unsafe { self.0.as_ref() }
    }
}

impl fmt::Debug for Sealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealed")
            .field("nonce_len", &self.nonce().len())
            .field("ciphertext_len", &self.ciphertext().len())
            .field("tag_len", &self.tag().len())
            .finish()
    }
}

impl Drop for Sealed {
    fn drop(&mut self) {
        // SAFETY: library-owned memory, returned with its matching free function exactly once.
        unsafe { ffi::vault_sealed_free(self.0.as_ptr()) }
    }
}

/// Builds a slice, tolerating a null pointer when the length is zero.
unsafe fn bytes<'a>(data: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    }
}
