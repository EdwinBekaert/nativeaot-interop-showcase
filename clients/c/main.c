/*
 * C client for the Vault library. Walks through each memory-ownership pattern in
 * vault_native.h and checks the results, so it doubles as the integration test:
 * exit code 0 means every check passed.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "completion.h"
#include "vault_native.h"

static int failures = 0;

static void check(bool ok, const char* what)
{
    printf("[%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok)
        failures++;
}

static void print_hex(const char* label, const uint8_t* bytes, size_t len)
{
    printf("  %-11s (%2zu bytes) ", label, len);
    for (size_t i = 0; i < len; i++)
        printf("%02x", bytes[i]);
    printf("\n");
}

/* Shared between main and the callback through user_data, so no globals are needed. */
typedef struct pending_encrypt {
    completion_t done;
    vault_status status;
    vault_sealed_t* sealed;
} pending_encrypt_t;

/* Runs on a library worker thread. Hands the result to main and returns quickly. */
static void on_encrypted(vault_status status, vault_sealed_t* sealed, void* user_data)
{
    pending_encrypt_t* pending = (pending_encrypt_t*)user_data;
    pending->status = status;
    pending->sealed = sealed; /* ownership moves to main, which frees it */
    completion_signal(&pending->done);
}

int main(void)
{
    /* [static] strings: use them, never free them. */
    printf("Vault library %s\n\n", vault_version());

    /* Invalid input is reported as a status code, not a crash. */
    uint8_t short_key[7] = {0};
    vault_t* rejected = NULL;
    check(vault_open(short_key, sizeof short_key, &rejected) == VAULT_ERR_INVALID_ARGUMENT && rejected == NULL,
          "a 7-byte key is rejected with VAULT_ERR_INVALID_ARGUMENT");

    /* [library-owned] handle: opened here, closed at the end. */
    uint8_t key[32];
    for (size_t i = 0; i < sizeof key; i++)
        key[i] = (uint8_t)i; /* demo key; never hard-code a real one */
    vault_t* vault = NULL;
    vault_status status = vault_open(key, sizeof key, &vault);
    check(status == VAULT_OK && vault != NULL, "vault_open with a 256-bit key");
    if (status != VAULT_OK)
        return 1;

    /* [caller-owned] struct on our stack, filled in by C#. */
    vault_info_t info;
    check(vault_get_info(vault, &info) == VAULT_OK && info.key_bits == 256,
          "vault_get_info fills a stack struct");
    printf("  key_id %016" PRIx64 ", %" PRIu32 "-bit key, AES hardware acceleration: %s\n",
           info.key_id, info.key_bits, info.hardware_accelerated ? "yes" : "no");

    /* Async call: the callback brings back a [library-owned] result. */
    const char* message = "Hello from C, sealed by C#!";
    size_t message_len = strlen(message);
    pending_encrypt_t pending = {0};
    completion_init(&pending.done);
    status = vault_encrypt_async(vault, (const uint8_t*)message, message_len, on_encrypted, &pending);
    check(status == VAULT_OK, "vault_encrypt_async returns immediately");
    if (status != VAULT_OK)
        return 1;

    bool finished = completion_wait(&pending.done, 10000);
    check(finished && pending.status == VAULT_OK && pending.sealed != NULL,
          "callback delivered a result on a worker thread");
    if (!finished || pending.sealed == NULL)
        return 1;

    vault_sealed_t* sealed = pending.sealed;
    print_hex("nonce", sealed->nonce, sealed->nonce_len);
    print_hex("ciphertext", sealed->ciphertext, sealed->ciphertext_len);
    print_hex("tag", sealed->tag, sealed->tag_len);

    /* [caller-owned] output buffer: ask for the size, allocate, then decrypt. */
    size_t needed = 0;
    check(vault_decrypt(vault, sealed, NULL, 0, &needed) == VAULT_ERR_BUFFER_TOO_SMALL && needed == message_len,
          "size query returns VAULT_ERR_BUFFER_TOO_SMALL with the size needed");

    uint8_t* plaintext = (uint8_t*)malloc(needed);
    if (plaintext == NULL)
        return 1;
    size_t written = 0;
    status = vault_decrypt(vault, sealed, plaintext, needed, &written);
    check(status == VAULT_OK && written == message_len && memcmp(plaintext, message, message_len) == 0,
          "vault_decrypt round-trips the message");
    printf("  plaintext   \"%.*s\"\n", (int)written, (const char*)plaintext);

    /* Tampering is detected: flip one bit of the tag. */
    sealed->tag[0] ^= 0x01;
    status = vault_decrypt(vault, sealed, plaintext, needed, &written);
    check(status == VAULT_ERR_AUTHENTICATION_FAILED, "a tampered tag fails authentication");
    printf("  -> %s\n", vault_status_message(status));

    free(plaintext);
    /* EXPERIMENT: vault_sealed_free(sealed); deliberately skipped */
    vault_close(vault);

    printf("\n%s\n", failures == 0 ? "All checks passed." : "Some checks FAILED.");
    return failures == 0 ? 0 : 1;
}
