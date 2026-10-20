"""Python client for the Vault library, using only ctypes from the standard library.

Runs the same checks as the C and Rust clients, so it doubles as an integration
test: exit code 0 means every check passed.

    python vault_client.py path/to/vault_native.dll   (or .so / .dylib)
"""

import ctypes
import itertools
import sys
import threading
from ctypes import (
    CFUNCTYPE,
    POINTER,
    Structure,
    byref,
    c_bool,
    c_char_p,
    c_int32,
    c_size_t,
    c_uint8,
    c_uint32,
    c_uint64,
    c_void_p,
)

VAULT_OK = 0
VAULT_ERR_INVALID_ARGUMENT = 1
VAULT_ERR_BUFFER_TOO_SMALL = 2
VAULT_ERR_AUTHENTICATION_FAILED = 3


# ---- Bindings: mirror vault_native.h --------------------------------------------


class VaultInfo(Structure):
    _fields_ = [
        ("key_id", c_uint64),
        ("key_bits", c_uint32),
        ("hardware_accelerated", c_bool),  # 1 byte, like C bool
    ]


class VaultSealed(Structure):
    _fields_ = [
        ("nonce", POINTER(c_uint8)),
        ("nonce_len", c_size_t),
        ("ciphertext", POINTER(c_uint8)),
        ("ciphertext_len", c_size_t),
        ("tag", POINTER(c_uint8)),
        ("tag_len", c_size_t),
    ]


# Same checks as the _Static_asserts in vault_native.h.
assert ctypes.sizeof(VaultInfo) == 16, "vault_info_t layout changed"
assert VaultInfo.hardware_accelerated.offset == 12, "vault_info_t layout changed"

ENCRYPT_CALLBACK = CFUNCTYPE(None, c_int32, POINTER(VaultSealed), c_void_p)


def load(path):
    """Loads the library and declares every function's signature.

    Without argtypes and restype, ctypes assumes int arguments and an int result,
    which silently truncates pointers to 32 bits on 64-bit platforms.
    """
    lib = ctypes.CDLL(path)
    signatures = {
        "vault_version": ([], c_char_p),
        "vault_status_message": ([c_int32], c_char_p),
        "vault_open": ([POINTER(c_uint8), c_size_t, POINTER(c_void_p)], c_int32),
        "vault_close": ([c_void_p], None),
        "vault_get_info": ([c_void_p, POINTER(VaultInfo)], c_int32),
        "vault_encrypt_async": (
            [c_void_p, POINTER(c_uint8), c_size_t, ENCRYPT_CALLBACK, c_void_p],
            c_int32,
        ),
        "vault_sealed_free": ([POINTER(VaultSealed)], None),
        "vault_decrypt": (
            [c_void_p, POINTER(VaultSealed), POINTER(c_uint8), c_size_t, POINTER(c_size_t)],
            c_int32,
        ),
    }
    for name, (argtypes, restype) in signatures.items():
        function = getattr(lib, name)
        function.argtypes = argtypes
        function.restype = restype
    return lib


def as_uint8_array(data):
    """Copies bytes into a ctypes array that can be passed as const uint8_t*."""
    return (c_uint8 * len(data)).from_buffer_copy(data)


# ---- Pythonic wrapper ----------------------------------------------------------


class VaultError(Exception):
    def __init__(self, lib, status):
        super().__init__(f"{lib.vault_status_message(status).decode()} (status {status})")
        self.status = status


class Sealed:
    """An encryption result. Owns library memory; free it with close() or `with`."""

    def __init__(self, lib, pointer):
        self._lib = lib
        self._pointer = pointer

    def _field(self, name):
        s = self._pointer.contents
        return ctypes.string_at(getattr(s, name), getattr(s, name + "_len"))

    nonce = property(lambda self: self._field("nonce"))
    ciphertext = property(lambda self: self._field("ciphertext"))
    tag = property(lambda self: self._field("tag"))

    def flip_tag_bit(self):
        """Corrupts the tag in place, to demonstrate tamper detection."""
        self._pointer.contents.tag[0] ^= 0x01

    def close(self):
        if self._pointer:
            self._lib.vault_sealed_free(self._pointer)  # never free() it
            self._pointer = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# One callback object for the whole process, routing each completion by the token in
# user_data. A ctypes callback must stay alive until the library calls it, or the
# library jumps into freed memory. A per-call callback would also have to be freed
# after it has fully returned, which Python can't observe. A permanent one avoids
# both problems; the per-call state is a plain dict entry.
_pending = {}  # token -> (lib, on_done)
_pending_lock = threading.Lock()
_tokens = itertools.count(1)  # never 0, so a token is never NULL


def _register(lib, on_done):
    token = next(_tokens)
    with _pending_lock:
        _pending[token] = (lib, on_done)
    return token


def _unregister(token):
    with _pending_lock:
        return _pending.pop(token)


@ENCRYPT_CALLBACK
def _on_encrypted(status, sealed_pointer, user_data):
    lib, on_done = _unregister(user_data)
    if status == VAULT_OK and sealed_pointer:
        on_done(Sealed(lib, sealed_pointer), None)
    else:
        on_done(None, VaultError(lib, status))


class Vault:
    """An open vault. Closes its library handle on close() or at the end of `with`."""

    def __init__(self, lib, key):
        self._lib = lib
        self._handle = c_void_p()
        self._check(lib.vault_open(as_uint8_array(key), len(key), byref(self._handle)))

    def info(self):
        info = VaultInfo()  # caller-owned; the library fills it in
        self._check(self._lib.vault_get_info(self._handle, byref(info)))
        return info

    def encrypt_async(self, plaintext, on_done):
        """Starts an encryption; on_done(sealed, error) runs once on a library thread."""
        token = _register(self._lib, on_done)
        status = self._lib.vault_encrypt_async(
            self._handle, as_uint8_array(plaintext), len(plaintext), _on_encrypted, token
        )
        if status != VAULT_OK:
            _unregister(token)  # the callback will never run
            raise VaultError(self._lib, status)

    def plaintext_len(self, sealed):
        """Size query: output = NULL makes the library report the size needed."""
        needed = c_size_t()
        status = self._lib.vault_decrypt(self._handle, sealed._pointer, None, 0, byref(needed))
        if status != VAULT_ERR_BUFFER_TOO_SMALL:
            raise VaultError(self._lib, status)
        return needed.value

    def decrypt(self, sealed):
        size = self.plaintext_len(sealed)
        output = (c_uint8 * size)()  # caller-owned buffer
        written = c_size_t()
        self._check(self._lib.vault_decrypt(self._handle, sealed._pointer, output, size, byref(written)))
        return bytes(output[: written.value])

    def close(self):
        if self._handle:
            self._lib.vault_close(self._handle)
            self._handle = c_void_p()

    def _check(self, status):
        if status != VAULT_OK:
            raise VaultError(self._lib, status)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---- Checks --------------------------------------------------------------------

failures = 0


def check(ok, what):
    global failures
    print(f"[{'PASS' if ok else 'FAIL'}] {what}")
    if not ok:
        failures += 1


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    lib = load(sys.argv[1])
    print(f"Vault library {lib.vault_version().decode()}\n")

    # Errors come back as exceptions carrying the status code.
    try:
        Vault(lib, bytes(7))
        check(False, "a 7-byte key is rejected with VAULT_ERR_INVALID_ARGUMENT")
    except VaultError as error:
        check(error.status == VAULT_ERR_INVALID_ARGUMENT, "a 7-byte key is rejected with VAULT_ERR_INVALID_ARGUMENT")

    key = bytes(range(32))  # demo key; never hard-code a real one
    with Vault(lib, key) as vault:
        check(True, "vault_open with a 256-bit key")

        info = vault.info()
        check(info.key_bits == 256, "vault_get_info fills a stack struct")
        accel = "yes" if info.hardware_accelerated else "no"
        print(f"  key_id {info.key_id:016x}, {info.key_bits}-bit key, AES hardware acceleration: {accel}")

        # The callback runs on a library thread; an Event hands the result back.
        message = b"Hello from Python, sealed by C#!"
        done = threading.Event()
        outcome = {}

        def on_done(sealed, error):
            outcome.update(sealed=sealed, error=error)
            done.set()

        vault.encrypt_async(message, on_done)
        check(True, "vault_encrypt_async returns immediately")

        finished = done.wait(timeout=10)
        sealed = outcome.get("sealed")
        check(finished and sealed is not None, "callback delivered a result on a worker thread")
        if sealed is None:
            return 1

        with sealed:
            print(f"  nonce       ({len(sealed.nonce):2} bytes) {sealed.nonce.hex()}")
            print(f"  ciphertext  ({len(sealed.ciphertext):2} bytes) {sealed.ciphertext.hex()}")
            print(f"  tag         ({len(sealed.tag):2} bytes) {sealed.tag.hex()}")

            check(
                vault.plaintext_len(sealed) == len(message),
                "size query returns VAULT_ERR_BUFFER_TOO_SMALL with the size needed",
            )

            plaintext = vault.decrypt(sealed)
            check(plaintext == message, "vault_decrypt round-trips the message")
            print(f'  plaintext   "{plaintext.decode()}"')

            # Tampering is detected: flip one bit of the tag.
            sealed.flip_tag_bit()
            try:
                vault.decrypt(sealed)
                check(False, "a tampered tag fails authentication")
            except VaultError as error:
                check(error.status == VAULT_ERR_AUTHENTICATION_FAILED, "a tampered tag fails authentication")
                print(f"  -> {error}")

    print("\nAll checks passed." if failures == 0 else "\nSome checks FAILED.")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
