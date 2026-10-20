# A regular .NET app: built with dotnet build and run with dotnet. [LibraryImport]
# looks for vault_native next to the app, so the library is copied there.
set(csharp_output_dir "${CMAKE_BINARY_DIR}/csharp")

add_custom_target(vault_csharp_client ALL
    COMMAND ${vault_dotnet_env} "${DOTNET}" build "${CMAKE_CURRENT_SOURCE_DIR}/VaultClient.csproj"
            --configuration Release
            --output "${csharp_output_dir}"
            --artifacts-path "${CMAKE_BINARY_DIR}/dotnet"
            --nologo
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${vault_library}" "${csharp_output_dir}"
    COMMENT "Building the C# client"
    VERBATIM)
add_dependencies(vault_csharp_client vault_native_publish)

add_test(NAME csharp_client COMMAND "${DOTNET}" "${csharp_output_dir}/vault_csharp_client.dll")
