# Memory ownership

C and C# manage memory in incompatible ways. C# moves objects around and frees them
when the garbage collector decides; C expects addresses that stay put and an explicit
`free`. Most interop bugs are a disagreement about who frees what, and when.

The rule this project follows: **every pointer in the API has exactly one owner, and
the header says which.** There are five patterns.

| Pattern | Allocated by | Freed by | Example |
|---|---|---|---|
| [Caller-allocated struct](#1-caller-allocated-struct) | caller | caller | `vault_get_info` |
| [Caller buffer with size query](#2-caller-buffer-with-size-query) | caller | caller | `vault_decrypt` |
| [Library-allocated result](#3-library-allocated-result) | library | library, via `vault_sealed_free` | `vault_encrypt_async` |
| [Opaque handle](#4-opaque-handle) | library | library, via `vault_close` | `vault_open` |
| [Static data](#5-static-data) | library, once | never | `vault_version` |

Caller-owned inputs, such as the key and the plaintext, follow one more rule: the
library reads or copies them during the call and keeps no pointer afterwards.

## 1. Caller-allocated struct

The caller provides the memory, usually a local variable. C# writes into it through
the pointer.

```c
vault_info_t info;                 /* on the C stack */
vault_get_info(vault, &info);      /* C# fills it in */
```

```csharp
outInfo->KeyId = engine.KeyId;     // writes straight into the caller's memory
outInfo->KeyBits = (uint)engine.KeyBits;
```

There is no allocation and nothing to free. It's the cheapest pattern and the hardest
to misuse, so use it whenever the size is fixed.

**Layout must match exactly.** The C struct and the C# struct describe the same bytes.
Both sides use sequential layout, `bool` is 1 byte on both (guaranteed in C# by
`[assembly: DisableRuntimeMarshalling]`), and the header checks the size and offsets:

```c
_Static_assert(sizeof(vault_info_t) == 16, "vault_info_t layout changed");
_Static_assert(offsetof(vault_info_t, hardware_accelerated) == 12, "vault_info_t layout changed");
```

```
offset  0          8          12  13      16
        | key_id   | key_bits | b | padding |
```

## 2. Caller buffer with size query

For output whose size the caller doesn't know in advance. The caller asks first,
allocates, then calls again. Win32 and many POSIX APIs work this way.

```c
size_t needed = 0;
vault_decrypt(vault, sealed, NULL, 0, &needed);          /* VAULT_ERR_BUFFER_TOO_SMALL */
uint8_t* plaintext = malloc(needed);
vault_decrypt(vault, sealed, plaintext, needed, &written); /* VAULT_OK */
free(plaintext);                                          /* caller's malloc, caller's free */
```

The caller chooses the allocator: `malloc`, the stack, an arena, a pooled buffer. The
library never allocates. Here the size is simply the ciphertext length, so a caller
who knows that can skip the query.

## 3. Library-allocated result

When the library creates the data, here asynchronously, so the caller can't provide a
buffer up front, the library allocates it and exports a matching free function.

```c
static void on_encrypted(vault_status status, vault_sealed_t* sealed, void* user_data)
{
    /* ... use sealed, or hand it to another thread ... */
    vault_sealed_free(sealed);     /* never free(sealed) */
}
```

```csharp
var result = (VaultSealed*)NativeMemory.AllocZeroed((nuint)sizeof(VaultSealed));
result->Nonce = CopyToNative(package.Nonce);
// ...
```

**Why not `free()`?** The library and the caller may use different heaps. On Windows
each C runtime can have its own heap, and `NativeMemory` may not use the same one as
your compiler's `malloc`. Freeing memory on the wrong heap corrupts it. A dedicated
free function guarantees the memory goes back where it came from.

`vault_sealed_free` frees the three inner buffers and then the struct. `ToNative`
cleans up whatever it allocated if one allocation fails partway, so a failure never
leaks.

## 4. Opaque handle

C needs to hold on to a C# object, the engine with its key, across many calls. It can't
hold a managed reference, and a raw address would break the moment the garbage
collector moves the object.

```c
vault_t* vault;
vault_open(key, sizeof key, &vault);
/* ... any number of calls ... */
vault_close(vault);
```

```csharp
*outVault = GCHandle.ToIntPtr(GCHandle.Alloc(engine));   // open
GCHandle.FromIntPtr(vault).Target as VaultEngine          // every call
GCHandle.FromIntPtr(vault).Free();                        // close
```

A `GCHandle` is an entry in the runtime's handle table. While it exists, the engine
can't be collected. The integer C receives refers to the table entry, not to the
object, so the object may move freely. C sees only `vault_t*`, a pointer to a type it
can't look inside.

`vault_close` frees the handle, not the engine. Encryptions still running hold their
own reference to the engine, so they finish normally, and the garbage collector
reclaims it afterwards.

## 5. Static data

```c
printf("Vault library %s\n", vault_version());   /* never free this */
```

The version string and the status messages are allocated once, the first time the
library is called, and live until the process exits. The caller can use them anywhere without worrying about
lifetime.

## What the C client checks

The [C client](../clients/c/main.c) runs every pattern and checks the results, and
`ctest` runs it on Windows, Linux and macOS in CI. Each pattern is labelled in the
source with its ownership tag from the header.
