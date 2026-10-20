/*
 * vault_native.h - C API of the Vault library.
 *
 * The library is written in C# and compiled with .NET NativeAOT into a plain shared
 * library (vault_native.dll / .so / .dylib). Callers need no .NET runtime.
 *
 * Every function documents who owns each piece of memory:
 *   [caller-owned]   you allocate and free it; the library only reads or fills it
 *                    during the call and keeps no pointer to it afterwards.
 *   [library-owned]  the library allocates it; release it with the matching
 *                    vault_*_free / vault_close function, never with free().
 *   [static]         lives for the whole process; never free it.
 *
 * Every `vault` argument is the [library-owned] handle from vault_open, and every
 * out_* pointer points at [caller-owned] memory that the call fills in.
 *
 * Requires C11 (or C++11).
 */
#ifndef VAULT_NATIVE_H
#define VAULT_NATIVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#  define VAULT_API __declspec(dllimport)
#else
#  define VAULT_API
#endif

/* ---- Status codes ------------------------------------------------------- */

typedef int32_t vault_status;

#define VAULT_OK                         0
#define VAULT_ERR_INVALID_ARGUMENT       1  /* null pointer, bad key length, ... */
#define VAULT_ERR_BUFFER_TOO_SMALL       2  /* *out_written holds the size needed */
#define VAULT_ERR_AUTHENTICATION_FAILED  3  /* wrong key, or the data was tampered with */
#define VAULT_ERR_INTERNAL              99  /* unexpected managed exception, caught at the boundary */

/* ---- Types -------------------------------------------------------------- */

/* Opaque handle to an open vault. */
typedef struct vault vault_t;

/* Filled in by vault_get_info. */
typedef struct vault_info {
    uint64_t key_id;               /* first 8 bytes of SHA-256(key) */
    uint32_t key_bits;             /* 128, 192 or 256 */
    bool     hardware_accelerated; /* 1 byte, like C# bool; 3 bytes of padding follow */
} vault_info_t;

/* Result of an encryption. Holds the three parts needed to decrypt. */
typedef struct vault_sealed {
    uint8_t* nonce;       size_t nonce_len;       /* 12 bytes */
    uint8_t* ciphertext;  size_t ciphertext_len;  /* same length as the plaintext */
    uint8_t* tag;         size_t tag_len;         /* 16 bytes */
} vault_sealed_t;

/*
 * Called once when vault_encrypt_async finishes.
 *   status     VAULT_OK, or an error code.
 *   sealed     [library-owned] the result, or NULL on error. Free it with
 *              vault_sealed_free once you are done with it; it may outlive the callback.
 *   user_data  the pointer you passed to vault_encrypt_async, unchanged.
 * Runs on a library worker thread, not the thread that started the operation.
 */
typedef void (*vault_encrypt_callback)(vault_status status, vault_sealed_t* sealed, void* user_data);

/* The C# side declares the same layout; these catch accidental changes on the C side. */
#ifdef __cplusplus
static_assert(sizeof(vault_info_t) == 16, "vault_info_t layout changed");
static_assert(offsetof(vault_info_t, hardware_accelerated) == 12, "vault_info_t layout changed");
#else
_Static_assert(sizeof(vault_info_t) == 16, "vault_info_t layout changed");
_Static_assert(offsetof(vault_info_t, hardware_accelerated) == 12, "vault_info_t layout changed");
#endif

/* ---- Functions ---------------------------------------------------------- */

/* Library version, e.g. "0.1.0". [static] */
VAULT_API const char* vault_version(void);

/* Human-readable text for a status code. [static] */
VAULT_API const char* vault_status_message(vault_status status);

/*
 * Opens a vault with an AES key of 16, 24 or 32 bytes.
 *   key        [caller-owned] copied; you may wipe it as soon as the call returns.
 *   out_vault  [caller-owned] variable that receives a [library-owned] handle;
 *              release the handle with vault_close.
 */
VAULT_API vault_status vault_open(const uint8_t* key, size_t key_len, vault_t** out_vault);

/*
 * Releases a handle from vault_open. NULL is ignored. Encryptions still running
 * finish normally and still call their callback. Using the handle afterwards is
 * undefined behaviour.
 */
VAULT_API void vault_close(vault_t* vault);

/* Fills *out_info. out_info is [caller-owned], typically a local variable. */
VAULT_API vault_status vault_get_info(const vault_t* vault, vault_info_t* out_info);

/*
 * Starts encrypting on a worker thread and returns at once.
 *   plaintext  [caller-owned] copied before this function returns.
 *   callback   called exactly once, but only if this function returns VAULT_OK.
 *   user_data  [caller-owned] passed through to the callback untouched, never read;
 *              may be NULL. Keep what it points to alive until the callback runs.
 */
VAULT_API vault_status vault_encrypt_async(const vault_t* vault,
                                           const uint8_t* plaintext, size_t plaintext_len,
                                           vault_encrypt_callback callback, void* user_data);

/* Releases a result passed to a vault_encrypt_callback. NULL is ignored. */
VAULT_API void vault_sealed_free(vault_sealed_t* sealed);

/*
 * Decrypts and verifies `sealed` into a buffer you provide.
 *   sealed       [caller-owned] read only; a result from the callback works as is.
 *   output       [caller-owned] receives the plaintext.
 *   out_written  [caller-owned] set to the number of bytes written.
 * To find the size needed, pass output = NULL: the call returns
 * VAULT_ERR_BUFFER_TOO_SMALL and sets *out_written to the size. An empty plaintext
 * needs no buffer: then the call verifies the tag and returns VAULT_OK (or
 * VAULT_ERR_AUTHENTICATION_FAILED) with *out_written = 0.
 * Returns VAULT_ERR_AUTHENTICATION_FAILED, with output zeroed, if verification fails.
 */
VAULT_API vault_status vault_decrypt(const vault_t* vault, const vault_sealed_t* sealed,
                                     uint8_t* output, size_t output_capacity, size_t* out_written);

#ifdef __cplusplus
}
#endif

#endif /* VAULT_NATIVE_H */
