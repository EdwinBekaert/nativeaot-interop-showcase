using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace VaultClient;

/// <summary>A non-OK status from the library.</summary>
internal sealed class VaultException(int status) : Exception(Vault.Describe(status))
{
    public int Status { get; } = status;
}

/// <summary>
/// Owns a vault_t*. The mirror image of the GCHandle inside the library: there, native
/// code holds a C# object; here, C# holds a native one. Closed by Dispose or, as a
/// last resort, by the finalizer, and never while a call is using it.
/// </summary>
internal sealed class VaultHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public VaultHandle() : base(ownsHandle: true) { }

    protected override bool ReleaseHandle()
    {
        NativeMethods.Close(handle);
        return true;
    }
}

/// <summary>Owns a library-allocated vault_sealed_t* and frees it with vault_sealed_free.</summary>
internal sealed unsafe class SealedResult : SafeHandleZeroOrMinusOneIsInvalid
{
    public SealedResult(VaultSealed* sealedResult) : base(ownsHandle: true) => SetHandle((nint)sealedResult);

    internal VaultSealed* Raw
    {
        get
        {
            ObjectDisposedException.ThrowIf(IsClosed, this);
            return (VaultSealed*)handle;
        }
    }

    public byte[] Nonce => Copy(Raw->Nonce, Raw->NonceLen);
    public byte[] Ciphertext => Copy(Raw->Ciphertext, Raw->CiphertextLen);
    public byte[] Tag => Copy(Raw->Tag, Raw->TagLen);

    /// <summary>Corrupts the tag in place, to demonstrate tamper detection.</summary>
    public void FlipTagBit() => Raw->Tag[0] ^= 0x01;

    protected override bool ReleaseHandle()
    {
        NativeMethods.SealedFree((VaultSealed*)handle);
        return true;
    }

    private static byte[] Copy(byte* data, nuint length) => new ReadOnlySpan<byte>(data, checked((int)length)).ToArray();
}

/// <summary>Idiomatic C# over the C API: exceptions, IDisposable, and Task for async.</summary>
internal sealed unsafe class Vault : IDisposable
{
    private readonly VaultHandle _handle;

    private Vault(VaultHandle handle) => _handle = handle;

    public static string Version => Marshal.PtrToStringUTF8((nint)NativeMethods.Version()) ?? "?";

    public static string Describe(int status) =>
        $"{Marshal.PtrToStringUTF8((nint)NativeMethods.StatusMessage(status))} (status {status})";

    public static Vault Open(ReadOnlySpan<byte> key)
    {
        int status = NativeMethods.Open(key, (nuint)key.Length, out VaultHandle handle);
        if (status != Status.Ok)
        {
            handle.Dispose();
            throw new VaultException(status);
        }
        return new Vault(handle);
    }

    public VaultInfo GetInfo()
    {
        Check(NativeMethods.GetInfo(_handle, out VaultInfo info));
        return info;
    }

    /// <summary>Wraps vault_encrypt_async in a Task: Task → C callback → Task.</summary>
    public Task<SealedResult> EncryptAsync(ReadOnlySpan<byte> plaintext)
    {
        // Continuations run on the thread pool, not inside the library's callback thread.
        var completion = new TaskCompletionSource<SealedResult>(TaskCreationOptions.RunContinuationsAsynchronously);

        // The library hands user_data back untouched; a GCHandle turns it back into
        // the TaskCompletionSource, and keeps it alive until then.
        GCHandle state = GCHandle.Alloc(completion);
        int status = NativeMethods.EncryptAsync(
            _handle, plaintext, (nuint)plaintext.Length, &OnEncrypted, (void*)GCHandle.ToIntPtr(state));
        if (status != Status.Ok)
        {
            state.Free(); // the callback will never run
            throw new VaultException(status);
        }
        return completion.Task;
    }

    // A plain static method with a C calling convention: its address is a C function
    // pointer, so no delegate has to be kept alive. Runs on a library thread.
    [UnmanagedCallersOnly]
    private static void OnEncrypted(int status, VaultSealed* sealedResult, void* userData)
    {
        // An exception escaping here would end the process, so nothing may throw out.
        try
        {
            GCHandle state = GCHandle.FromIntPtr((nint)userData);
            var completion = (TaskCompletionSource<SealedResult>)state.Target!;
            state.Free();

            if (status == Status.Ok && sealedResult != null)
                completion.SetResult(new SealedResult(sealedResult));
            else
                completion.SetException(new VaultException(status));
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"vault callback failed: {exception}");
        }
    }

    /// <summary>Plaintext size, from the library's size query (output = NULL).</summary>
    public int PlaintextLength(SealedResult sealedResult)
    {
        int status = NativeMethods.Decrypt(_handle, sealedResult.Raw, null, 0, out nuint needed);
        GC.KeepAlive(sealedResult);
        if (status != Status.BufferTooSmall)
            throw new VaultException(status);
        return checked((int)needed);
    }

    public byte[] Decrypt(SealedResult sealedResult)
    {
        byte[] output = new byte[PlaintextLength(sealedResult)];
        nuint written;
        fixed (byte* destination = output)
        {
            Check(NativeMethods.Decrypt(_handle, sealedResult.Raw, destination, (nuint)output.Length, out written));
        }
        GC.KeepAlive(sealedResult);
        return output[..checked((int)written)];
    }

    public void Dispose() => _handle.Dispose();

    private static void Check(int status)
    {
        if (status != Status.Ok)
            throw new VaultException(status);
    }
}
