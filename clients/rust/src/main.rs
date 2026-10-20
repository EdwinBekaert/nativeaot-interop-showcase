//! Rust client for the Vault library. Runs the same checks as the C client through a
//! safe wrapper, so it doubles as an integration test: exit code 0 means every
//! check passed.

mod ffi;
mod vault;

use std::process::ExitCode;
use std::sync::mpsc;
use std::time::Duration;

use vault::{VaultError, VaultHandle};

struct Checks {
    failures: u32,
}

impl Checks {
    fn check(&mut self, ok: bool, what: &str) {
        println!("[{}] {what}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            self.failures += 1;
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> ExitCode {
    println!("Vault library {}\n", vault::version());
    let mut checks = Checks { failures: 0 };

    // Errors come back as Result values.
    checks.check(
        matches!(
            VaultHandle::open(&[0u8; 7]),
            Err(VaultError(ffi::VAULT_ERR_INVALID_ARGUMENT))
        ),
        "a 7-byte key is rejected with VAULT_ERR_INVALID_ARGUMENT",
    );

    // The handle closes itself when `vault` goes out of scope.
    let key: Vec<u8> = (0u8..32).collect(); // demo key; never hard-code a real one
    let vault = match VaultHandle::open(&key) {
        Ok(vault) => vault,
        Err(error) => {
            checks.check(false, &format!("vault_open with a 256-bit key: {error}"));
            return ExitCode::FAILURE;
        }
    };
    checks.check(true, "vault_open with a 256-bit key");

    match vault.info() {
        Ok(info) => {
            checks.check(info.key_bits == 256, "vault_get_info fills a stack struct");
            println!(
                "  key_id {:016x}, {}-bit key, AES hardware acceleration: {}",
                info.key_id,
                info.key_bits,
                if info.hardware_accelerated {
                    "yes"
                } else {
                    "no"
                }
            );
        }
        Err(error) => checks.check(false, &format!("vault_get_info: {error}")),
    }

    // A closure is the callback; a channel carries the result back to this thread.
    let message = b"Hello from Rust, sealed by C#!";
    let (sender, receiver) = mpsc::channel();
    let started = vault.encrypt_async(message, move |result| {
        let _ = sender.send(result);
    });
    checks.check(started.is_ok(), "vault_encrypt_async returns immediately");

    let mut sealed = match receiver.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(sealed)) => sealed,
        other => {
            checks.check(false, &format!("callback delivered a result: {other:?}"));
            return ExitCode::FAILURE;
        }
    };
    checks.check(true, "callback delivered a result on a worker thread");
    println!(
        "  nonce       ({:2} bytes) {}",
        sealed.nonce().len(),
        hex(sealed.nonce())
    );
    println!(
        "  ciphertext  ({:2} bytes) {}",
        sealed.ciphertext().len(),
        hex(sealed.ciphertext())
    );
    println!(
        "  tag         ({:2} bytes) {}",
        sealed.tag().len(),
        hex(sealed.tag())
    );

    checks.check(
        vault.plaintext_len(&sealed) == Ok(message.len()),
        "size query returns VAULT_ERR_BUFFER_TOO_SMALL with the size needed",
    );

    match vault.decrypt(&sealed) {
        Ok(plaintext) => {
            checks.check(
                plaintext == message,
                "vault_decrypt round-trips the message",
            );
            println!("  plaintext   \"{}\"", String::from_utf8_lossy(&plaintext));
        }
        Err(error) => checks.check(false, &format!("vault_decrypt: {error}")),
    }

    // Tampering is detected: flip one bit of the tag.
    sealed.tag_mut()[0] ^= 0x01;
    let tampered = vault.decrypt(&sealed);
    checks.check(
        tampered == Err(VaultError(ffi::VAULT_ERR_AUTHENTICATION_FAILED)),
        "a tampered tag fails authentication",
    );
    if let Err(error) = tampered {
        println!("  -> {error}");
    }

    // `sealed` and `vault` are freed here, in reverse order, by their Drop impls.
    if checks.failures == 0 {
        println!("\nAll checks passed.");
        ExitCode::SUCCESS
    } else {
        println!("\nSome checks FAILED.");
        ExitCode::FAILURE
    }
}
