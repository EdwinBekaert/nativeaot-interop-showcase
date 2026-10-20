using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

// Every type crossing the boundary is blittable, as in the library itself: bool is
// 1 byte, and structs are passed by pointer without conversion.
[assembly: DisableRuntimeMarshalling]

namespace VaultClient;

/// <summary>Status codes from vault_native.h.</summary>
internal static class Status
{
    public const int Ok = 0;
    public const int InvalidArgument = 1;
    public const int BufferTooSmall = 2;
    public const int AuthenticationFailed = 3;
}

/// <summary>vault_info_t.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct VaultInfo
{
    public ulong KeyId;
    public uint KeyBits;
    public bool HardwareAccelerated;
}

/// <summary>vault_sealed_t.</summary>
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

/// <summary>
/// The C API, declared with [LibraryImport]: the source generator writes the
/// marshalling code at compile time. Spans are pinned and passed as pointers, and
/// SafeHandles are kept alive for the duration of each call.
/// </summary>
internal static unsafe partial class NativeMethods
{
    // Resolved at run time as vault_native.dll / vault_native.so / vault_native.dylib,
    // looked up next to the application.
    private const string Library = "vault_native";

    // These return [static] memory, so they are taken as raw pointers. Declaring the
    // return type as string would make the generated code free the library's memory.
    [LibraryImport(Library, EntryPoint = "vault_version")]
    public static partial byte* Version();

    [LibraryImport(Library, EntryPoint = "vault_status_message")]
    public static partial byte* StatusMessage(int status);

    [LibraryImport(Library, EntryPoint = "vault_open")]
    public static partial int Open(ReadOnlySpan<byte> key, nuint keyLen, out VaultHandle vault);

    [LibraryImport(Library, EntryPoint = "vault_close")]
    public static partial void Close(nint vault);

    [LibraryImport(Library, EntryPoint = "vault_get_info")]
    public static partial int GetInfo(VaultHandle vault, out VaultInfo info);

    [LibraryImport(Library, EntryPoint = "vault_encrypt_async")]
    public static partial int EncryptAsync(
        VaultHandle vault,
        ReadOnlySpan<byte> plaintext,
        nuint plaintextLen,
        delegate* unmanaged<int, VaultSealed*, void*, void> callback,
        void* userData);

    [LibraryImport(Library, EntryPoint = "vault_sealed_free")]
    public static partial void SealedFree(VaultSealed* sealedResult);

    [LibraryImport(Library, EntryPoint = "vault_decrypt")]
    public static partial int Decrypt(VaultHandle vault, VaultSealed* sealedInput, byte* output, nuint outputCapacity, out nuint written);
}
