# Design decisions

The choices behind the API and the code, with the alternatives that were considered.

## The API

**Status codes, not exceptions or `errno`.** Every function returns a `vault_status`.
C has no exceptions, and a global or thread-local "last error" breaks with async
callbacks, which run on a different thread. A return value is explicit and
thread-safe. `vault_status_message` adds readable text for logs.

**`int32_t` codes with `#define`s rather than a C `enum`.** The size of a C `enum` is
up to the compiler. `int32_t` has the same size in C, C#, Rust and Python's `ctypes`.

**Callback plus `user_data`, rather than polling or blocking.** A callback lets the
caller keep working and fits event loops. The `void* user_data` argument, passed back
untouched, lets the caller tie each result to its own state without globals, which C
callback APIs need in practice. The callback fires exactly once, on success or
failure, so a caller waiting on it can never hang.

**A size query for decrypt, a library allocation for encrypt.** The plaintext size is
known before decrypting, so the caller can provide the buffer and choose its own
allocator. The encryption result is created on another thread after the call has
returned, so the library has to allocate it.

**C11 and fixed-size types only.** `uint8_t`, `uint32_t`, `uint64_t`, `size_t` and
`bool` have the same meaning on every platform the project targets.

## The C# side

**`[UnmanagedCallersOnly]` with raw pointers, and no runtime marshalling.**
`[assembly: DisableRuntimeMarshalling]` turns off .NET's automatic conversions, so
every struct crossing the boundary is blittable: copied byte for byte, read in place.
Nothing happens behind the scenes, layouts are predictable, and NativeAOT needs no
generated marshalling code.

**`GCHandle` for the handle**, rather than a dictionary of IDs. It's the runtime's own
mechanism for exactly this case, it converts back to the object in constant time, and
it needs no locking. An ID table would add safety against stale handles, at the cost
of a lock on every call.

**`NativeMemory` rather than `Marshal.AllocHGlobal`.** `NativeMemory.Alloc` is the
modern API, maps to the platform's `malloc`, and has an explicit `Free` that accepts
null, which keeps the cleanup code simple.

**The input is copied before returning from `vault_encrypt_async`.** Pinning the
caller's buffer instead would avoid a copy, but would require the caller to keep it
alive until the callback, a rule that's easy to break and impossible to check. One
copy of the plaintext is cheap insurance.

**A new `AesGcm` per call.** It makes the engine safe to use from several threads at
once without relying on `AesGcm`'s own thread-safety guarantees. Creating one is
cheap compared with the encryption itself.

**`Task` in the core, callbacks only in the export layer.** The core offers a normal
`EncryptAsync`. The bridge from `Task` to C callback, via `ContinueWith`, lives in
`Exports.cs`, so the core doesn't change shape for interop.

## Known limitations

These are deliberate omissions for a demo, listed so nobody mistakes them for
oversights:

- **The async failure path is not tested.** When an encryption throws, the callback
  fires with `VAULT_ERR_INTERNAL` and a NULL result, and each client has a branch for
  that. No test reaches it, because making a correct AES-GCM encryption fail on demand
  would need a test-only failure switch in the library.
- **The key is not wiped from memory on close.** Encryptions in flight can still be
  using the engine when `vault_close` runs. Wiping safely would need reference
  counting of in-flight operations.
- **A handle used after `vault_close` is undefined behaviour,** as with any C
  library. An ID table would turn it into an error code.
- **No cancellation** for `vault_encrypt_async`.
- **The library can't be unloaded.** NativeAOT libraries stay loaded once loaded, and
  each NativeAOT library in a process has its own runtime and garbage collector.
- **The demo key in the C client is hard-coded.** Real code gets keys from a key store.
