# Copyright (C) 2025 by huawei.com

add_library(scf SHARED)

## use PUBLIC the cur dir and sub dir will be configured , use PRIVATE only cur dir will be configured
target_include_directories(
        scf
        PUBLIC ${CMAKE_DEPENDENCY_INCLUDEDIR}
                ${PROJECT_SOURCE_DIR}/src/include
                ${PROJECT_SOURCE_DIR}/src/callback
                ${PROJECT_SOURCE_DIR}/src/adaptor/base
                ${PROJECT_SOURCE_DIR}/src/common/utils
                ${PROJECT_SOURCE_DIR}/src/common/constant
                ${PROJECT_SOURCE_DIR}/src/adaptor/hitls
                ${PROJECT_SOURCE_DIR}/src/adaptor/openssl
)

# note project
get_target_property(PROJECT_INCLUDE_DIRS scf INCLUDE_DIRECTORIES)
message(STATUS "Include directories for scf: ${PROJECT_INCLUDE_DIRS}")

set(SCF_SOURCE_FILES "")

################### only used in src ###################
if(NOT BUILD_TEST)
    message("Release add compiler flags")
    add_compiler_flags("-Wfloat-equal")
    add_compiler_flags("-Wstrict-prototypes")
    add_compiler_flags("-Wconversion")
    add_compiler_flags("-Wstack-usage=8192")
    add_compiler_flags("-Wframe-larger-than=8192")
    add_compiler_flags("-Wnon-virtual-dtor")
    add_compiler_flags("-Wshadow")
    add_compiler_flags("-Wswitch-default")
    add_compiler_flags("-Wcast-qual")
    add_compiler_flags("-Wswitch-default")
endif()
################### only used in src ###################

# build sub dir
add_subdirectory(include)
add_subdirectory(callback)
add_subdirectory(common)
add_subdirectory(adaptor)
add_subdirectory(scf)

target_sources(scf PRIVATE ${SCF_SOURCE_FILES})

message("SCF_SOURCE_FILES"  ${SCF_SOURCE_FILES})

target_link_libraries(
        scf
        PUBLIC
        Dependency::rapidjson
        Dependency::secure_c
)

if (BUILD_FUZZ)
    target_link_libraries(scf PUBLIC Dependency::secodefuzz)
endif ()

add_library(SCF::scf ALIAS scf)
