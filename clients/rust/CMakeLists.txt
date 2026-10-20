# Cargo builds the Rust client; CMake only runs it, so `cmake --build` and `ctest`
# cover every client. build.rs finds the library through VAULT_NATIVE_DIR.
set(rust_target_dir "${CMAKE_BINARY_DIR}/cargo")
set(rust_output_dir "${rust_target_dir}/release")
set(rust_executable "${rust_output_dir}/vault_rust_client${CMAKE_EXECUTABLE_SUFFIX}")

add_custom_target(vault_rust_client ALL
    COMMAND "${CMAKE_COMMAND}" -E env "VAULT_NATIVE_DIR=${vault_publish_dir}"
            "${CARGO}" build --release --quiet
            --manifest-path "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml"
            --target-dir "${rust_target_dir}"
    # Put the library next to the executable, as for the C client.
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${vault_library}" "${rust_output_dir}"
    COMMENT "Building the Rust client with cargo"
    VERBATIM)
add_dependencies(vault_rust_client vault_native_publish)

add_test(NAME rust_client COMMAND "${rust_executable}")
