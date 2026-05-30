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
                ${PROJECT_SOURCE_DIR}/src/transport
                ${PROJECT_SOURCE_DIR}/src/crypto
                ${PROJECT_SOURCE_DIR}/src/connection
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
add_subdirectory(transport)
add_subdirectory(crypto)
add_subdirectory(connection)

target_sources(scf PRIVATE ${SCF_SOURCE_FILES})

message("SCF_SOURCE_FILES"  ${SCF_SOURCE_FILES})

target_link_libraries(
        scf
        PUBLIC
        Dependency::rapidjson
        Dependency::secure_c
)

# OpenSSL is needed by default_crypto_engine and kae_provider_engine (direct API calls),
# and by openssl_adaptor (SSL_CTX_new_ex, SSL_CTX_set1_groups_list, etc. for Provider integration).
# Use built OpenSSL when DOWNLOAD_DEPENDENCY is On, otherwise use system OpenSSL
if(DOWNLOAD_DEPENDENCY)
    # OpenSSL was built by cmake/deps/openssl.cmake, targets already defined
    target_link_libraries(scf PUBLIC OpenSSL::SSL OpenSSL::Crypto)
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(scf PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

if (BUILD_FUZZ)
    target_link_libraries(scf PUBLIC Dependency::secodefuzz)
endif ()

add_library(SCF::scf ALIAS scf)
