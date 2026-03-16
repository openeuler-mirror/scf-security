# --------------------------
# Define usefull test macros
# --------------------------
file(GLOB_RECURSE ALL_SOURCES
        "test_utils/*.cpp"
        "test_cpp/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/test_log.cpp"
)

macro(add_scf_test NAME)
    message(STATUS "Current CMake source directory===: ${CMAKE_CURRENT_SOURCE_DIR}")
    message(STATUS "Current CMake binary directory====: ${CMAKE_CURRENT_BINARY_DIR}")
    add_executable(${NAME} ${ALL_SOURCES})
    target_link_libraries(
            ${NAME} PRIVATE SCF::scf Dependency::gtest Dependency::secure_c -L/usr/lib/gcc/aarch64-openEuler-linux/12/libasan.so -lasan
            -fsanitize=address -lasan
            )
    target_include_directories(${NAME}
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
    add_dependencies(${NAME} SCF::scf)
    add_test(NAME ${NAME} COMMAND ${NAME})
    set_tests_properties(
            ${NAME}
            PROPERTIES
            ENVIRONMENT
            "LD_LIBRARY_PATH=${PROJECT_SOURCE_DIR}/output/scf/lib64:${CMAKE_DEPENDENCY_LIBDIR}:$LD_LIBRARY_PATH"
    )
    target_link_directories(${NAME} PRIVATE ${PROJECT_SOURCE_DIR}/output/scf/lib64)
    target_link_directories(${NAME} PRIVATE ${CMAKE_DEPENDENCY_LIBDIR})
    target_compile_definitions(${NAME} PRIVATE PROJECT_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
endmacro()

add_scf_test(scf_tls_test_all)