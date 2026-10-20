add_executable(vault_c_client main.c)
target_link_libraries(vault_c_client PRIVATE vault_native)

if(MSVC)
    target_compile_options(vault_c_client PRIVATE /W4 /WX)
else()
    target_compile_options(vault_c_client PRIVATE -Wall -Wextra -Wpedantic -Werror)
    find_package(Threads REQUIRED)
    target_link_libraries(vault_c_client PRIVATE Threads::Threads)
endif()

# AddressSanitizer replaces malloc and free for the whole process. The library
# allocates its results with NativeMemory, which uses the same malloc, so a result
# the client forgets to pass to vault_sealed_free is reported as a leak, and a
# double free or use after free stops the program.
if(VAULT_SANITIZE)
    if(MSVC)
        message(FATAL_ERROR "VAULT_SANITIZE needs GCC or Clang: MSVC has no leak detection")
    endif()
    set(sanitize_flags -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
    target_compile_options(vault_c_client PRIVATE ${sanitize_flags})
    target_link_options(vault_c_client PRIVATE ${sanitize_flags})
endif()

# Put the library next to the executable so it is found at run time: Windows looks
# there first, and on Linux and macOS the rpath points there.
if(APPLE)
    set_target_properties(vault_c_client PROPERTIES BUILD_RPATH "@loader_path")
elseif(UNIX)
    set_target_properties(vault_c_client PROPERTIES BUILD_RPATH "$ORIGIN")
endif()

add_custom_command(TARGET vault_c_client POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "$<TARGET_FILE:vault_native>" "$<TARGET_FILE_DIR:vault_c_client>"
    VERBATIM)

add_test(NAME c_client COMMAND vault_c_client)
if(VAULT_SANITIZE)
    set_tests_properties(c_client PROPERTIES ENVIRONMENT
        "LSAN_OPTIONS=suppressions=${CMAKE_CURRENT_SOURCE_DIR}/lsan.supp:print_suppressions=1")
endif()
