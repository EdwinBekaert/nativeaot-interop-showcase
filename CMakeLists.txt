cmake_minimum_required(VERSION 3.25)
project(nativeaot_interop_showcase LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
enable_testing()

# ---- Build the C# library with NativeAOT -------------------------------------
# `cmake --build` runs `dotnet publish`, so one build command produces the native
# library and every client.

find_program(DOTNET dotnet REQUIRED)

# Map the platform CMake is building for to a .NET runtime identifier.
if(WIN32)
    set(vault_os win)
elseif(APPLE)
    set(vault_os osx)
else()
    set(vault_os linux)
endif()
string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" vault_arch)
if(vault_arch MATCHES "^(amd64|x86_64|x64)$")
    set(vault_arch x64)
elseif(vault_arch MATCHES "^(arm64|aarch64)$")
    set(vault_arch arm64)
else()
    message(FATAL_ERROR "Unsupported processor: ${CMAKE_SYSTEM_PROCESSOR}")
endif()
set(VAULT_RID "${vault_os}-${vault_arch}")

set(vault_publish_dir "${CMAKE_BINARY_DIR}/native")
if(WIN32)
    set(vault_library "${vault_publish_dir}/vault_native.dll")
    set(vault_import_library "${vault_publish_dir}/vault_native.lib")
elseif(APPLE)
    set(vault_library "${vault_publish_dir}/vault_native.dylib")
else()
    set(vault_library "${vault_publish_dir}/vault_native.so")
endif()

# On Windows, NativeAOT links with MSVC and locates it through vcvarsall.bat. The
# Visual Studio 2026 version of that script runs vswhere.exe from PATH, and the
# installer does not put it there, so add it for the publish step only. LIB is
# cleared because the Visual Studio generator passes a partial one down, which
# makes the C# compiler warn; vcvarsall.bat sets the right value itself.
set(vault_publish_env "")
if(WIN32)
    set(program_files_x86 "ProgramFiles(x86)")
    find_program(VSWHERE vswhere
        HINTS "$ENV{${program_files_x86}}/Microsoft Visual Studio/Installer"
        REQUIRED)
    cmake_path(GET VSWHERE PARENT_PATH vswhere_dir)
    set(vault_publish_env "${CMAKE_COMMAND}" -E env
        --modify "PATH=path_list_prepend:${vswhere_dir}"
        --modify "LIB=unset:")
endif()

file(GLOB_RECURSE vault_sources CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/*.cs"
    "${CMAKE_SOURCE_DIR}/src/*.csproj")

add_custom_command(
    OUTPUT "${vault_library}" ${vault_import_library}
    COMMAND ${vault_publish_env} "${DOTNET}" publish "${CMAKE_SOURCE_DIR}/src/Vault.Native/Vault.Native.csproj"
            --configuration Release
            --runtime ${VAULT_RID}
            --output "${vault_publish_dir}"
            --artifacts-path "${CMAKE_BINARY_DIR}/dotnet"
            --nologo
    DEPENDS ${vault_sources}
            "${CMAKE_SOURCE_DIR}/Directory.Build.props"
            "${CMAKE_SOURCE_DIR}/global.json"
    COMMENT "Publishing Vault.Native with NativeAOT for ${VAULT_RID}"
    VERBATIM)
add_custom_target(vault_native_publish DEPENDS "${vault_library}")

# Expose the published library to CMake like any other shared library.
add_library(vault_native SHARED IMPORTED GLOBAL)
set_target_properties(vault_native PROPERTIES
    IMPORTED_LOCATION "${vault_library}"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/src/Vault.Native/include")
if(WIN32)
    set_target_properties(vault_native PROPERTIES IMPORTED_IMPLIB "${vault_import_library}")
endif()
add_dependencies(vault_native vault_native_publish)

# ---- Clients -----------------------------------------------------------------

add_subdirectory(clients/c)

# Clients in other languages are built when their toolchain is installed. CI sets
# VAULT_REQUIRE_ALL_CLIENTS so a missing toolchain fails instead of skipping.
option(VAULT_REQUIRE_ALL_CLIENTS "Fail when a client's toolchain is missing" OFF)

find_program(CARGO cargo HINTS "$ENV{HOME}/.cargo/bin" "$ENV{USERPROFILE}/.cargo/bin")
if(CARGO)
    add_subdirectory(clients/rust)
elseif(VAULT_REQUIRE_ALL_CLIENTS)
    message(FATAL_ERROR "cargo not found, and VAULT_REQUIRE_ALL_CLIENTS is ON")
else()
    message(STATUS "cargo not found: skipping the Rust client")
endif()
