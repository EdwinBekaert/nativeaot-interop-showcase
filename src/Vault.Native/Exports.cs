using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Vault.Core;

namespace Vault.Native;

/// <summary>
/// The C API. Each method is exported under its EntryPoint name and declared in
/// include/vault_native.h. Rules followed by every export:
/// <list type="bullet">
/// <item>No exception crosses the boundary: each body catches and returns a status code.</item>
/// <item>Caller-owned memory is read or written only during the call, never kept.</item>
/// <item>Memory handed to the caller comes from NativeMemory and has a matching free export.</item>
/// </list>
/// </summary>
internal static unsafe class Exports
{
    private static readonly byte* VersionText = AllocStaticUtf8("0.1.0");

    private static readonly byte* MessageOk = AllocStaticUtf8("ok");
    private static readonly byte* MessageInvalidArgument = AllocStaticUtf8("invalid argument");
    private static readonly byte* MessageBufferTooSmall = AllocStaticUtf8("output buffer too small");
    private static readonly byte* MessageAuthenticationFailed = AllocStaticUtf8("authentication failed: wrong key or tampered data");
    private static readonly byte* MessageInternal = AllocStaticUtf8("internal error");
    private static readonly byte* MessageUnknown = AllocStaticUtf8("unknown status code");

    [UnmanagedCallersOnly(EntryPoint = "vault_version")]
    public static byte* Version() => VersionText;

    [UnmanagedCallersOnly(EntryPoint = "vault_status_message")]
    public static byte* StatusMessage(int status) => status switch
    {
        Status.Ok => MessageOk,
        Status.InvalidArgument => MessageInvalidArgument,
        Status.BufferTooSmall => MessageBufferTooSmall,
        Status.AuthenticationFailed => MessageAuthenticationFailed,
        Status.Internal => MessageInternal,
        _ => MessageUnknown,
    };

    // The handle given to C is a GCHandle: it keeps the engine alive while C holds it,
    // and turns back into the object in O(1). C never sees a raw managed pointer.
    [UnmanagedCallersOnly(EntryPoint = "vault_open")]
    public static int Open(byte* key, nuint keyLen, nint* outVault)
    {
        try
        {
            if (outVault == null)
                return Status.InvalidArgument;
            *outVault = 0;
            if (key == null || keyLen is not (16 or 24 or 32))
                return Status.InvalidArgument;

            var engine = new VaultEngine(new ReadOnlySpan<byte>(key, (int)keyLen));
            *outVault = GCHandle.ToIntPtr(GCHandle.Alloc(engine));
            return Status.Ok;
        }
        catch
        {
            return Status.Internal;
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "vault_close")]
    public static void Close(nint vault)
    {
        try
        {
            // Encryptions in flight hold their own reference to the engine, so they
            // complete normally after the handle is gone.
            if (vault != 0)
                GCHandle.FromIntPtr(vault).Free();
        }
        catch
        {
            // Nothing to report from a void export.
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "vault_get_info")]
    public static int GetInfo(nint vault, VaultInfo* outInfo)
    {
        try
        {
            if (outInfo == null || !TryGetEngine(vault, out var engine))
                return Status.InvalidArgument;

            // Written straight into the caller's struct: no allocation, nothing to free.
            outInfo->KeyId = engine.KeyId;
            outInfo->KeyBits = (uint)engine.KeyBits;
            outInfo->HardwareAccelerated = VaultEngine.IsHardwareAccelerated;
            return Status.Ok;
        }
        catch
        {
            return Status.Internal;
        }
    }

    [UnmanagedCallersOnly(EntryPoint = "vault_encrypt_async")]
    public static int EncryptAsync(
        nint vault,
        byte* plaintext,
        nuint plaintextLen,
        delegate* unmanaged<int, VaultSealed*, void*, void> callback,
        void* userData)
    {
        try
        {
            if (!TryGetEngine(vault, out var engine) || callback == null
                || (plaintext == null && plaintextLen != 0) || plaintextLen > int.MaxValue)
                return Status.InvalidArgument;

            // Copy now: the caller may free or reuse its buffer as soon as we return.
            byte[] copy = new ReadOnlySpan<byte>(plaintext, (int)plaintextLen).ToArray();

            // Pointers can't be captured by a lambda, so carry them as integers.
            nint callbackAddress = (nint)callback;
            nint userDataAddress = (nint)userData;
            engine.EncryptAsync(copy).ContinueWith(
                task => CompleteEncrypt(task, callbackAddress, userDataAddress),
                TaskScheduler.Default);
            return Status.Ok;
        }
        catch
        {
            return Status.Internal;
        }
    }

    // Turns the finished Task into exactly one call of the C callback, success or not.
    private static void CompleteEncrypt(Task<SealedPackage> task, nint callbackAddress, nint userDataAddress)
    {
        var callback = (delegate* unmanaged<int, VaultSealed*, void*, void>)callbackAddress;
        VaultSealed* sealedResult = null;
        int status;
        try
        {
            sealedResult = ToNative(task.Result);
            status = Status.Ok;
        }
        catch
        {
            status = Status.Internal;
        }
        callback(status, sealedResult, (void*)userDataAddress);
    }

    [UnmanagedCallersOnly(EntryPoint = "vault_sealed_free")]
    public static void SealedFree(VaultSealed* sealedResult) => FreeSealed(sealedResult);

    [UnmanagedCallersOnly(EntryPoint = "vault_decrypt")]
    public static int Decrypt(nint vault, VaultSealed* sealedInput, byte* output, nuint outputCapacity, nuint* outWritten)
    {
        try
        {
            if (outWritten == null || sealedInput == null || !TryGetEngine(vault, out var engine))
                return Status.InvalidArgument;
            *outWritten = 0;

            VaultSealed s = *sealedInput;
            if (s.CiphertextLen > int.MaxValue || s.NonceLen > int.MaxValue || s.TagLen > int.MaxValue
                || (s.Nonce == null && s.NonceLen != 0)
                || (s.Ciphertext == null && s.CiphertextLen != 0)
                || (s.Tag == null && s.TagLen != 0))
                return Status.InvalidArgument;

            // Size query: the caller asks first, allocates, then calls again.
            nuint needed = s.CiphertextLen;
            if (output == null || outputCapacity < needed)
            {
                *outWritten = needed;
                return Status.BufferTooSmall;
            }

            engine.Decrypt(
                new ReadOnlySpan<byte>(s.Nonce, (int)s.NonceLen),
                new ReadOnlySpan<byte>(s.Ciphertext, (int)s.CiphertextLen),
                new ReadOnlySpan<byte>(s.Tag, (int)s.TagLen),
                new Span<byte>(output, (int)needed));
            *outWritten = needed;
            return Status.Ok;
        }
        catch (AuthenticationTagMismatchException)
        {
            return Status.AuthenticationFailed;
        }
        catch (ArgumentException)
        {
            return Status.InvalidArgument; // wrong nonce or tag size
        }
        catch
        {
            return Status.Internal;
        }
    }

    private static bool TryGetEngine(nint vault, [NotNullWhen(true)] out VaultEngine? engine)
    {
        engine = vault == 0 ? null : GCHandle.FromIntPtr(vault).Target as VaultEngine;
        return engine != null;
    }

    private static VaultSealed* ToNative(SealedPackage package)
    {
        var result = (VaultSealed*)NativeMemory.AllocZeroed((nuint)sizeof(VaultSealed));
        try
        {
            result->Nonce = CopyToNative(package.Nonce);
            result->NonceLen = (nuint)package.Nonce.Length;
            result->Ciphertext = CopyToNative(package.Ciphertext);
            result->CiphertextLen = (nuint)package.Ciphertext.Length;
            result->Tag = CopyToNative(package.Tag);
            result->TagLen = (nuint)package.Tag.Length;
            return result;
        }
        catch
        {
            FreeSealed(result); // fields not yet set are null, which Free ignores
            throw;
        }
    }

    private static byte* CopyToNative(ReadOnlySpan<byte> source)
    {
        var destination = (byte*)NativeMemory.Alloc((nuint)source.Length);
        source.CopyTo(new Span<byte>(destination, source.Length));
        return destination;
    }

    private static void FreeSealed(VaultSealed* sealedResult)
    {
        if (sealedResult == null)
            return;
        NativeMemory.Free(sealedResult->Nonce);
        NativeMemory.Free(sealedResult->Ciphertext);
        NativeMemory.Free(sealedResult->Tag);
        NativeMemory.Free(sealedResult);
    }

    // Allocated once and never freed: backs the [static] strings in the header.
    private static byte* AllocStaticUtf8(string text)
    {
        int length = Encoding.UTF8.GetByteCount(text);
        var buffer = (byte*)NativeMemory.Alloc((nuint)length + 1);
        Encoding.UTF8.GetBytes(text, new Span<byte>(buffer, length));
        buffer[length] = 0;
        return buffer;
    }
}
