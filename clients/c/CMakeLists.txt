add_executable(vault_c_client main.c)
target_link_libraries(vault_c_client PRIVATE vault_native)

if(MSVC)
    target_compile_options(vault_c_client PRIVATE /W4 /WX)
else()
    target_compile_options(vault_c_client PRIVATE -Wall -Wextra -Wpedantic -Werror)
    find_package(Threads REQUIRED)
    target_link_libraries(vault_c_client PRIVATE Threads::Threads)
endif()

# Put the library next to the executable so it is found at run time.
add_custom_command(TARGET vault_c_client POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "$<TARGET_FILE:vault_native>" "$<TARGET_FILE_DIR:vault_c_client>"
    VERBATIM)

add_test(NAME c_client COMMAND vault_c_client)
