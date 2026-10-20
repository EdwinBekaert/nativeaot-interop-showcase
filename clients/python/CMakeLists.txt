# Nothing to build: the test runs the script against the published library.
# -I (isolated mode) ignores PYTHON* environment variables and user site-packages.
add_test(NAME python_client
    COMMAND "${Python3_EXECUTABLE}" -I "${CMAKE_CURRENT_SOURCE_DIR}/vault_client.py"
            "$<TARGET_FILE:vault_native>")
