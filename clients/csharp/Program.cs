// C# client for the Vault library. It runs on the regular .NET runtime and reaches the
// NativeAOT library (which has its own runtime inside) only through the C API: two
// .NET runtimes in one process, talking C. Runs the same checks as the other clients,
// so it doubles as an integration test: exit code 0 means every check passed.

using System.Text;
using VaultClient;

int failures = 0;

void Check(bool ok, string what)
{
    Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {what}");
    if (!ok)
        failures++;
}

Console.WriteLine($"Vault library {Vault.Version}\n");

// Errors come back as exceptions carrying the status code.
try
{
    Vault.Open(new byte[7]).Dispose();
    Check(false, "a 7-byte key is rejected with VAULT_ERR_INVALID_ARGUMENT");
}
catch (VaultException error)
{
    Check(error.Status == Status.InvalidArgument, "a 7-byte key is rejected with VAULT_ERR_INVALID_ARGUMENT");
}

byte[] key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(); // demo key; never hard-code a real one
using (Vault vault = Vault.Open(key))
{
    Check(true, "vault_open with a 256-bit key");

    VaultInfo info = vault.GetInfo();
    Check(info.KeyBits == 256, "vault_get_info fills a stack struct");
    Console.WriteLine(
        $"  key_id {info.KeyId:x16}, {info.KeyBits}-bit key, AES hardware acceleration: {(info.HardwareAccelerated ? "yes" : "no")}");

    // The C callback completes a Task, so the async call reads like any other.
    byte[] message = Encoding.UTF8.GetBytes("Hello from C#, sealed by C#!");
    Task<SealedResult> encryption = vault.EncryptAsync(message);
    Check(true, "vault_encrypt_async returns immediately");

    bool finished = await Task.WhenAny(encryption, Task.Delay(TimeSpan.FromSeconds(10))) == encryption;
    Check(finished && encryption.IsCompletedSuccessfully, "callback delivered a result on a worker thread");
    if (!encryption.IsCompletedSuccessfully)
        return 1;

    using SealedResult sealedResult = encryption.Result;
    Console.WriteLine($"  nonce       ({sealedResult.Nonce.Length,2} bytes) {Convert.ToHexStringLower(sealedResult.Nonce)}");
    Console.WriteLine($"  ciphertext  ({sealedResult.Ciphertext.Length,2} bytes) {Convert.ToHexStringLower(sealedResult.Ciphertext)}");
    Console.WriteLine($"  tag         ({sealedResult.Tag.Length,2} bytes) {Convert.ToHexStringLower(sealedResult.Tag)}");

    Check(vault.PlaintextLength(sealedResult) == message.Length,
        "size query returns VAULT_ERR_BUFFER_TOO_SMALL with the size needed");

    byte[] plaintext = vault.Decrypt(sealedResult);
    Check(plaintext.AsSpan().SequenceEqual(message), "vault_decrypt round-trips the message");
    Console.WriteLine($"  plaintext   \"{Encoding.UTF8.GetString(plaintext)}\"");

    // Tampering is detected: flip one bit of the tag.
    sealedResult.FlipTagBit();
    try
    {
        vault.Decrypt(sealedResult);
        Check(false, "a tampered tag fails authentication");
    }
    catch (VaultException error)
    {
        Check(error.Status == Status.AuthenticationFailed, "a tampered tag fails authentication");
        Console.WriteLine($"  -> {error.Message}");
    }

    // An empty message needs no output buffer; `fixed` on an empty array passes NULL.
    try
    {
        Task<SealedResult> emptyEncryption = vault.EncryptAsync(ReadOnlySpan<byte>.Empty);
        using SealedResult empty = await emptyEncryption;
        Check(vault.Decrypt(empty).Length == 0, "an empty message round-trips");
    }
    catch (VaultException error)
    {
        Check(false, $"an empty message round-trips: {error.Message}");
    }
}

Console.WriteLine(failures == 0 ? "\nAll checks passed." : "\nSome checks FAILED.");
return failures == 0 ? 0 : 1;
