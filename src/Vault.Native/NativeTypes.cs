using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

// No runtime marshalling: every type crossing the boundary is blittable and is read or
// written in place through a pointer. C# bool is then always 1 byte, matching C bool.
[assembly: DisableRuntimeMarshalling]

namespace Vault.Native;

/// <summary>Status codes; must match the VAULT_* defines in vault_native.h.</summary>
internal static class Status
{
    public const int Ok = 0;
    public const int InvalidArgument = 1;
    public const int BufferTooSmall = 2;
    public const int AuthenticationFailed = 3;
    public const int Internal = 99;
}

/// <summary>Mirrors vault_info_t: 16 bytes, hardware_accelerated at offset 12.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct VaultInfo
{
    public ulong KeyId;
    public uint KeyBits;
    public bool HardwareAccelerated;
}

/// <summary>Mirrors vault_sealed_t. size_t maps to nuint.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct VaultSealed
{
    public byte* Nonce;
    public nuint NonceLen;
    public byte* Ciphertext;
    public nuint CiphertextLen;
    public byte* Tag;
    public nuint TagLen;
}
