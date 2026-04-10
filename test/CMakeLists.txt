# --------------------------
# Define usefull test macros
# --------------------------
file(GLOB_RECURSE ALL_SOURCES
        "test_utils/*.cpp"
        "test_cpp/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/test_log.cpp"
)

message(STATUS "Current CMake source directory===: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "Current CMake binary directory====: ${CMAKE_CURRENT_BINARY_DIR}")
add_executable(scf_tls_test_all ${ALL_SOURCES})
target_link_libraries(
        scf_tls_test_all PRIVATE SCF::scf Dependency::gtest Dependency::secure_c -L/usr/lib/gcc/aarch64-openEuler-linux/12/libasan.so -lasan
        -fsanitize=address -lasan
)

target_include_directories(scf_tls_test_all
        PRIVATE
        ${CMAKE_DEPENDENCY_INCLUDEDIR}
        ${PROJECT_SOURCE_DIR}/test/test_include
        ${PROJECT_SOURCE_DIR}/src/include
        ${PROJECT_SOURCE_DIR}/src/callback
        ${PROJECT_SOURCE_DIR}/src/adaptor/base
        ${PROJECT_SOURCE_DIR}/src/adaptor/include
        ${PROJECT_SOURCE_DIR}/src/common/constant
        ${PROJECT_SOURCE_DIR}/src/common/util
)
add_dependencies(scf_tls_test_all SCF::scf)
add_test(NAME scf_tls_test_all COMMAND scf_tls_test_all)
target_link_directories(scf_tls_test_all PRIVATE
        ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
        ${PROJECT_SOURCE_DIR}/output/scf/lib64
        ${CMAKE_DEPENDENCY_LIBDIR})
target_compile_definitions(scf_tls_test_all PRIVATE PROJECT_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

add_custom_target(build_test
        COMMAND env
        LD_PRELOAD=/usr/lib/gcc/aarch64-openEuler-linux/12/libasan.so
        LD_LIBRARY_PATH=${PROJECT_SOURCE_DIR}/output/scf/lib64:${CMAKE_DEPENDENCY_LIBDIR}:$LD_LIBRARY_PATH
        ${PROJECT_SOURCE_DIR}/build/test/scf_tls_test_all --gtest_output=xml:${PROJECT_SOURCE_DIR}/build/test_results.xml
        DEPENDS
)