# Build notes

Problems hit while getting NativeAOT shared libraries to build on all three platforms,
and how the build handles them. You shouldn't need any of this to build the project,
since the fixes are already in place. It's here for anyone building NativeAOT libraries
of their own.

## Windows: NativeAOT can't find the linker with Visual Studio 2026

**Symptom:** `dotnet publish` fails at the link step:

```
error MSB3073: The command ""'vswhere.exe' is not recognized as an internal or
external command, ... link.exe" @"...\link.rsp"" exited with code 3.
```

**Cause:** NativeAOT links with MSVC on Windows. To find it, the ILCompiler package
runs `findvcvarsall.bat`, which calls Visual Studio's `vcvarsall.bat` and reads the
linker location from its output. The Visual Studio 2026 version of `vcvarsall.bat`
runs `vswhere.exe` by name, expecting it on `PATH`, but the installer doesn't put it
there. The resulting "not recognized" error text ends up in the output ILCompiler
parses, so it builds a nonsense linker command.

**Fix:** [`CMakeLists.txt`](../CMakeLists.txt) finds `vswhere.exe` in the Visual
Studio Installer folder and adds that folder to `PATH` for the publish step only. If
you run `dotnet publish` by hand, add
`C:\Program Files (x86)\Microsoft Visual Studio\Installer` to `PATH` first.

## Windows: no import library in the publish folder

**Symptom:** the C client fails to link, because `vault_native.lib` doesn't exist.

**Cause:** on Windows, a C program links against a DLL through its import library
(`.lib`). NativeAOT creates it, but leaves it in the intermediate `native/` folder and
copies only the `.dll` to the publish folder.

**Fix:** a small MSBuild target in
[`Vault.Native.csproj`](../src/Vault.Native/Vault.Native.csproj) copies the `.lib` to
the publish folder after publishing.

## Windows: warnings about `LIB` from the C# compiler

**Symptom:** many `CS1668: Invalid search path ... specified in 'LIB environment
variable'` warnings when building through CMake's Visual Studio generator.

**Cause:** the C++ project that runs the publish step passes its own partial `LIB`
variable to child processes. The C# compiler checks every folder in it.

**Fix:** CMake clears `LIB` for the publish step. NativeAOT's `vcvarsall.bat` call sets
the correct value itself.

## Windows: building from Git Bash

Git Bash drops environment variables whose names contain parentheses, such as
`ProgramFiles(x86)`, which the Visual Studio scripts rely on. Build from PowerShell or
a Developer Command Prompt.

## Linux: no soname on the shared library

**Symptom:** none at first. But when a program links a library by its full path, as
CMake does here, and the library has no soname, the program records that full build
path. It then breaks when moved to another machine.

**Cause:** NativeAOT gives macOS libraries an `@rpath/` install name, but sets no
`soname` on Linux. Without a soname, the linker records whatever path it was given.

**Fix:** the project passes `-Wl,-soname,vault_native.so` to the linker on Linux, and
the C client's rpath is set to its own folder (`$ORIGIN`, or `@loader_path` on macOS),
where the build copies the library.

## Library file names

NativeAOT names the library after the assembly, without a `lib` prefix:
`vault_native.dll`, `vault_native.so`, `vault_native.dylib`. The project sets
`<AssemblyName>vault_native</AssemblyName>` so the name looks like a C library's.
Linkers that expect `libvault_native.so` (`-lvault_native`) need the full path
instead, which is what the CMake `IMPORTED` target provides.
