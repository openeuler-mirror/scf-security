# --------------------------
# Define usefull test macros
# --------------------------

macro(add_scf_fuzz NAME)
    add_executable(${NAME}_fuzz ${NAME}.cpp)
    target_link_libraries(
            ${NAME}_fuzz
            PRIVATE SCF::scf
            Dependency::gtest
            Dependency::secodefuzz
            Dependency::secure_c
            gcov
            -lasan)
    add_test(
            NAME ${NAME}_fuzz
            COMMAND
            python3 ${PROJECT_SOURCE_DIR}/cmake/scripts/SecTracy.py -m
            ${PROJECT_BINARY_DIR}/src/scf/ -s
            ${PROJECT_BINARY_DIR}/src/scf/ -n SCFFuzz -T ./scf.txt
            ${NAME}_fuzz)
    set_tests_properties(
            ${NAME}_fuzz
            PROPERTIES
            ENVIRONMENT
            "LD_LIBRARY_PATH=${CMAKE_DEPENDENCY_LIBDIR}:$LD_LIBRARY_PATH"
    )
endmacro()
#add_compiler_flags("-ftest-coverage")

file(GLOB FUZZ_SOURCE
        ${PROJECT_SOURCE_DIR}/test/test_utils/test_tcp_client.cpp
        ${PROJECT_SOURCE_DIR}/test/test_utils/test_tcp_server.cpp
        ${PROJECT_SOURCE_DIR}/test/test_utils/test_tcp_common.cpp
        ${PROJECT_SOURCE_DIR}/test/test_utils/test_tcp_connection.cpp
)
macro(add_fuzz NAME)
    add_executable(${NAME}_fuzz ${NAME}.cpp ${FUZZ_SOURCE})
    target_link_libraries(
            ${NAME}_fuzz
            PRIVATE SCF::scf
            Dependency::gtest
            Dependency::secodefuzz
            Dependency::secure_c
            gcov
            -lasan)
    include_directories(
#            ${PROJECT_SOURCE_DIR}/test/scfdemo/test_include
            ${PROJECT_SOURCE_DIR}/test/test_include
            ${PROJECT_SOURCE_DIR}/build/deps/include/securec
    )
    add_test(NAME ${NAME}_fuzz COMMAND ${NAME}_fuzz)
    set_tests_properties(
            ${NAME}_fuzz
            PROPERTIES
            ENVIRONMENT
            "LD_LIBRARY_PATH=${CMAKE_DEPENDENCY_LIBDIR}:$LD_LIBRARY_PATH"
    )
endmacro()

# --------------------------
# Declare HSE tests
# --------------------------

# --------------------------
# Declare XWCRYPTO tests
# --------------------------

add_fuzz(test_scf_policy)
