using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Vault.Core;

/// <summary>Nonce, ciphertext and authentication tag produced by one AES-GCM encryption.</summary>
public sealed record SealedPackage(byte[] Nonce, byte[] Ciphertext, byte[] Tag);

/// <summary>
/// AES-GCM encryption with one fixed key. Plain managed code: it knows nothing about
/// interop, so the same engine could sit behind a web API or a desktop app.
/// </summary>
public sealed class VaultEngine
{
    public const int NonceSize = 12;
    public const int TagSize = 16;

    private readonly byte[] _key;

    public VaultEngine(ReadOnlySpan<byte> key)
    {
        if (key.Length is not (16 or 24 or 32))
            throw new ArgumentException("Key must be 16, 24 or 32 bytes.", nameof(key));

        _key = key.ToArray();
        KeyBits = key.Length * 8;
        KeyId = BinaryPrimitives.ReadUInt64LittleEndian(SHA256.HashData(key));
    }

    /// <summary>Key size in bits: 128, 192 or 256.</summary>
    public int KeyBits { get; }

    /// <summary>First 8 bytes of SHA-256(key): identifies the key without revealing it.</summary>
    public ulong KeyId { get; }

    /// <summary>True when the CPU has AES instructions (AES-NI or the Arm crypto extension).</summary>
    public static bool IsHardwareAccelerated =>
        System.Runtime.Intrinsics.X86.Aes.IsSupported || System.Runtime.Intrinsics.Arm.Aes.IsSupported;

    public SealedPackage Encrypt(ReadOnlySpan<byte> plaintext)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];

        // A fresh AesGcm per call keeps the engine safe to use from several threads at once.
        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        return new SealedPackage(nonce, ciphertext, tag);
    }

    /// <summary>Runs <see cref="Encrypt"/> on the thread pool.</summary>
    public Task<SealedPackage> EncryptAsync(byte[] plaintext) => Task.Run(() => Encrypt(plaintext));

    /// <summary>
    /// Decrypts into <paramref name="plaintext"/>, which must be as long as the ciphertext.
    /// Throws <see cref="AuthenticationTagMismatchException"/> when the data was tampered with.
    /// </summary>
    public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext)
    {
        using var aes = new AesGcm(_key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
    }
}
