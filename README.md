# nativeaot-interop-showcase

A C# library compiled with **.NET NativeAOT** into a plain native shared library
(`vault_native.dll` / `.so` / `.dylib`), called from C through a small C API. Callers
need no .NET runtime: to them it is just another C library.

The library itself is deliberately small (AES-GCM encryption via
`System.Security.Cryptography`), so the interesting part is the boundary between
languages: who owns which memory, how async work reports back, and how errors cross
without crashing the caller.

> **Status:** C client on Windows. Rust and Python clients, C# calling native code,
> and CI on Windows, Linux and macOS are next.

## What it demonstrates

| Pattern | Where | Why it matters |
|---|---|---|
| Opaque handle backed by a `GCHandle` | `vault_open` / `vault_close` | C holds a reference to a managed object without ever seeing a managed pointer |
| Caller-allocated struct | `vault_get_info` | C# fills a struct on the C stack: no allocation, nothing to free |
| Caller-provided buffer with size query | `vault_decrypt` | The classic "call with NULL to get the size" pattern used across Win32 and POSIX |
| Library-allocated result with a free function | `vault_sealed_free` | Memory comes from `NativeMemory` and goes back through the library, never `free()` |
| Static strings | `vault_version`, `vault_status_message` | Allocated once, valid for the process lifetime |
| Async `Task` → C callback with `user_data` | `vault_encrypt_async` | The callback fires exactly once, on success *or* failure, on a worker thread |
| Exception boundary | every export | No managed exception escapes; each becomes a status code |
| Layout checks | `vault_native.h` | `static_assert` on struct size and field offsets; `bool` is 1 byte on both sides |

## Layout

```
src/
  Vault.Core/        Managed engine (AES-GCM). Knows nothing about interop.
  Vault.Native/      NativeAOT export layer: [UnmanagedCallersOnly] functions
    include/         vault_native.h, the public C API
clients/
  c/                 C client; also the integration test
CMakeLists.txt       One build: runs dotnet publish, then compiles the clients
```

## Build and run

Requirements:

- .NET 10 SDK
- A C compiler and CMake 3.25+
- Windows: Visual Studio Build Tools (2022 or 2026) with the "Desktop development
  with C++" workload. NativeAOT uses its linker too.

```sh
cmake -B build
cmake --build build --config Release
ctest --test-dir build --build-config Release --output-on-failure
```

The NativeAOT compiler packages are downloaded from nuget.org on the first build.
There are no other third-party dependencies.

To see the C client's output, run it directly: `build/clients/c/Release/vault_c_client`
(on Windows with the Visual Studio generator).

## Memory ownership rules

Every function in [`vault_native.h`](src/Vault.Native/include/vault_native.h) labels
its pointers:

- **caller-owned**: you allocate and free it. The library reads or fills it during the
  call and keeps no pointer to it afterwards, so you may free it as soon as the call returns.
- **library-owned**: the library allocates it. Release it with the matching
  `vault_*_free` or `vault_close` function, never with `free()`: the library may use a
  different allocator from yours.
- **static**: valid for the whole process. Never free it.

## Licence

[MIT](LICENSE)
