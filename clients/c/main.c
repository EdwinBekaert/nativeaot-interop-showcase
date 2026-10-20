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
    thread_id_t callback_thread;
} pending_encrypt_t;

/* Runs on a library worker thread. Hands the result to main and returns quickly. */
static void on_encrypted(vault_status status, vault_sealed_t* sealed, void* user_data)
{
    pending_encrypt_t* pending = (pending_encrypt_t*)user_data;
    pending->status = status;
    pending->sealed = sealed; /* ownership moves to main, which frees it */
    pending->callback_thread = current_thread();
    completion_signal(&pending->done);
}

/* Encrypts and waits for the result: NULL if the call or the callback failed. */
static vault_sealed_t* encrypt_and_wait(const vault_t* vault, const uint8_t* data, size_t len)
{
    pending_encrypt_t pending = {0};
    completion_init(&pending.done);
    if (vault_encrypt_async(vault, data, len, on_encrypted, &pending) != VAULT_OK)
        return NULL;
    if (!completion_wait(&pending.done, 10000)) {
        /* The callback still holds &pending and will write to it later, so this frame
           must not return. A timeout ends the test run. */
        check(false, "an encryption finished within 10 seconds");
        exit(1);
    }
    return pending.status == VAULT_OK ? pending.sealed : NULL;
}

int main(void)
{
    /* [static] strings: use them, never free them. */
    printf("Vault library %s\n\n", vault_version());
    check(strcmp(vault_version(), "0.1.0") == 0
              && strcmp(vault_status_message(VAULT_OK), "ok") == 0
              && strcmp(vault_status_message(VAULT_ERR_INVALID_ARGUMENT), "invalid argument") == 0
              && strcmp(vault_status_message(VAULT_ERR_BUFFER_TOO_SMALL), "output buffer too small") == 0
              && strcmp(vault_status_message(VAULT_ERR_AUTHENTICATION_FAILED),
                        "authentication failed: wrong key or tampered data") == 0
              && strcmp(vault_status_message(VAULT_ERR_INTERNAL), "internal error") == 0
              && strcmp(vault_status_message(12345), "unknown status code") == 0,
          "the version and every status message are NUL-terminated static strings");

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
    check(finished && pending.status == VAULT_OK && pending.sealed != NULL
              && !same_thread(pending.callback_thread, current_thread()),
          "callback delivered a result on a worker thread");
    if (!finished || pending.sealed == NULL)
        return 1;

    vault_sealed_t* sealed = pending.sealed;
    print_hex("nonce", sealed->nonce, sealed->nonce_len);
    print_hex("ciphertext", sealed->ciphertext, sealed->ciphertext_len);
    print_hex("tag", sealed->tag, sealed->tag_len);
    check(sealed->ciphertext_len == message_len && memcmp(sealed->ciphertext, message, message_len) != 0,
          "the ciphertext differs from the plaintext");

    /* Every encryption gets a fresh nonce, even for the same message. */
    vault_sealed_t* again = encrypt_and_wait(vault, (const uint8_t*)message, message_len);
    check(again != NULL && memcmp(again->nonce, sealed->nonce, sealed->nonce_len) != 0,
          "encrypting the same message twice uses different nonces");
    vault_sealed_free(again);

    /* More invalid input: each is a status code, and no callback runs. */
    check(vault_encrypt_async(vault, (const uint8_t*)message, message_len, NULL, NULL) == VAULT_ERR_INVALID_ARGUMENT,
          "a NULL callback is rejected with VAULT_ERR_INVALID_ARGUMENT");
    check(vault_encrypt_async(vault, NULL, 1, on_encrypted, NULL) == VAULT_ERR_INVALID_ARGUMENT,
          "NULL plaintext with a non-zero length is rejected");

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

    size_t reported = 0;
    check(vault_decrypt(vault, sealed, plaintext, needed - 1, &reported) == VAULT_ERR_BUFFER_TOO_SMALL
              && reported == needed,
          "a buffer one byte short returns VAULT_ERR_BUFFER_TOO_SMALL with the size needed");
    reported = 0;
    check(vault_decrypt(vault, sealed, NULL, needed, &reported) == VAULT_ERR_BUFFER_TOO_SMALL && reported == needed,
          "a NULL output with a large capacity is still a size query");
    check(vault_decrypt(vault, sealed, plaintext, needed, NULL) == VAULT_ERR_INVALID_ARGUMENT,
          "a NULL out_written is rejected");
    vault_sealed_t short_nonce = *sealed; /* same buffers, wrong length */
    short_nonce.nonce_len = 5;
    check(vault_decrypt(vault, &short_nonce, plaintext, needed, &written) == VAULT_ERR_INVALID_ARGUMENT,
          "a 5-byte nonce is rejected with VAULT_ERR_INVALID_ARGUMENT");

    /* A different key fails authentication. */
    uint8_t other_key[32] = {0};
    vault_t* other = NULL;
    status = vault_open(other_key, sizeof other_key, &other);
    check(status == VAULT_OK && vault_decrypt(other, sealed, plaintext, needed, &written) == VAULT_ERR_AUTHENTICATION_FAILED,
          "decrypting with a different key fails authentication");
    vault_close(other);

    /* Tampering is detected: flip one bit of the tag. */
    sealed->tag[0] ^= 0x01;
    status = vault_decrypt(vault, sealed, plaintext, needed, &written);
    check(status == VAULT_ERR_AUTHENTICATION_FAILED, "a tampered tag fails authentication");
    printf("  -> %s\n", vault_status_message(status));

    free(plaintext);
    vault_sealed_free(sealed);

    /* An empty message needs no output buffer: decrypting with output = NULL still
       verifies its tag. */
    vault_sealed_t* empty = encrypt_and_wait(vault, NULL, 0);
    check(empty != NULL && empty->ciphertext_len == 0, "an empty message encrypts");
    if (empty != NULL) {
        written = 1;
        status = vault_decrypt(vault, empty, NULL, 0, &written);
        check(status == VAULT_OK && written == 0, "an empty message decrypts with output = NULL");
        empty->tag[0] ^= 0x01;
        status = vault_decrypt(vault, empty, NULL, 0, &written);
        check(status == VAULT_ERR_AUTHENTICATION_FAILED, "a tampered empty message fails authentication");
        vault_sealed_free(empty);
    }

    vault_sealed_free(NULL); /* documented as ignored */
    check(true, "vault_sealed_free(NULL) returns");
    vault_close(vault);

    printf("\n%s\n", failures == 0 ? "All checks passed." : "Some checks FAILED.");
    return failures == 0 ? 0 : 1;
}
