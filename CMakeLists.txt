# Copyright (C) 2025 by huawei.com

cmake_minimum_required(VERSION 3.14.1)

project(scf CXX C)

cmake_policy(SET CMP0097 NEW)
option(BUILD_TEST "Enable/Disable tests" On)
option(DOWNLOAD_DEPENDENCY "Download Dependecies Automatically" On)
option(ENABLE_COVERAGE "Whether Enable Coverage" Off)
option(BUILD_FUZZ "Enable/Disable fuzz" Off)
option(BUILD_ASAN "Enable/Disable Address Sanitier" Off)

# NOTE the following var is only used when DOWNLOAD_DEPENDENCY is set of Off
set(DOWNLOADED_DEPENDENCY_DIR
        "${PROJECT_SOURCE_DIR}/external"
        CACHE
        STRING
        "Downloeded Dependency Directory, default to PROJECT_SOURCE_DIR/external")
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")
set(CMAKE_EXPORT_COMPILE_COMMANDS On)

# NOTE if install prefix is not specified, default to install in building folder
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set_property(CACHE CMAKE_INSTALL_PREFIX PROPERTY VALUE ${PROJECT_BINARY_DIR})
endif()

include(SetSecureFlags)

if(BUILD_TEST)
    include(CTest)
    enable_testing()
    set(BUILD_ASAN On)
    if(ENABLE_COVERAGE)
        include(SetupCoverage)
        setup_coverage()
    endif()
endif()

set_secure_flags()

# cmake -DCMAKE_BUILD_TYPE=debug or release
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()

if(NOT DEFINED CPU_TYPE)
    set(CPU_TYPE "arm_64")
endif()

message(STATUS "DOWNLOADED_DEPENDENCY_DIR: ${DOWNLOADED_DEPENDENCY_DIR}")
message(STATUS "CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
message(STATUS "BUILD_TEST: ${BUILD_TEST}")
message(STATUS "ENABLE_COVERAGE: ${ENABLE_COVERAGE}")
message(STATUS "CPU_TYPE: ${CPU_TYPE}")
message(STATUS "BUILD_FUZZ: ${BUILD_FUZZ}")

# ------------------------------------------------------------------------------
# Compiler Configuration
# ------------------------------------------------------------------------------

# Build position independent code, even for static lib
set(CMAKE_POSITION_INDEPENDENT_CODE On)

# Set c and cxx standard
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)


# ------------------------------------------------------------------------------
# CMake Modules and Dependency Dependencies
# ------------------------------------------------------------------------------

include(GNUInstallDirs)
# build dir
set(DEPENDENCY_INSTALL_PREFIX_NAME deps)

# build dir
set(CMAKE_DEPENDENCY_INSTALL_PREFIX
        ${CMAKE_BINARY_DIR}/${DEPENDENCY_INSTALL_PREFIX_NAME})
set(CMAKE_DEPENDENCY_INCLUDEDIR
        ${CMAKE_DEPENDENCY_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
set(CMAKE_DEPENDENCY_LIBDIR
        ${CMAKE_DEPENDENCY_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})


message("CMAKE_BINARY_DIR: "  ${CMAKE_BINARY_DIR})

message("CMAKE_DEPENDENCY_INSTALL_PREFIX:  " ${CMAKE_DEPENDENCY_INSTALL_PREFIX})
message("CMAKE_DEPENDENCY_INCLUDEDIR:  " ${CMAKE_DEPENDENCY_INCLUDEDIR})
message("CMAKE_DEPENDENCY_LIBDIR:  " ${CMAKE_DEPENDENCY_LIBDIR})

# We use FetchContent to handle src-only dependencies
include(FetchContent)
set(FETCHCONTENT_BASE_DIR ${CMAKE_DEPENDENCY_INSTALL_PREFIX}/src)

# External dependencies
include(ExternalProject)

if(BUILD_TEST OR BUILD_FUZZ)
    include(deps/gtest)
endif()

if(BUILD_FUZZ)
    message("building fuzz test now")
    include(deps/secodefuzz)
endif ()

# include deps/xx cmake
include(deps/rapidjson)
include(deps/libboundscheck)

# ------------------------------------------------------------------------------
# Project Configuration
# ------------------------------------------------------------------------------

#
# .a output dir  # /
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
        ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
# .so output dir
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
        ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
# .h output dir
set(CMAKE_INCLUDE_OUTPUT_DIRECTORY
        ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})

set(CMAKE_CONFIG_OUTPUT_DIRECTORY
        ${CMAKE_INSTALL_PREFIX}/config)

# create output dir
file(MAKE_DIRECTORY ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})
file(MAKE_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
file(MAKE_DIRECTORY ${CMAKE_INCLUDE_OUTPUT_DIRECTORY})
file(MAKE_DIRECTORY ${CMAKE_CONFIG_OUTPUT_DIRECTORY})
execute_process(
        COMMAND chmod 700 ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}
        COMMAND chmod 700 ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
        COMMAND chmod 700 ${CMAKE_INCLUDE_OUTPUT_DIRECTORY}
        COMMAND chmod 700 ${CMAKE_CONFIG_OUTPUT_DIRECTORY}
)
message("CMAKE_ARCHIVE_OUTPUT_DIRECTORY:  " ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})
message("CMAKE_LIBRARY_OUTPUT_DIRECTORY:  " ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
message("CMAKE_INCLUDE_OUTPUT_DIRECTORY:  " ${CMAKE_INCLUDE_OUTPUT_DIRECTORY})
message("CMAKE_CONFIG_OUTPUT_DIRECTORY:  " ${CMAKE_CONFIG_OUTPUT_DIRECTORY})

set(SCF_SRC_DIR ${PROJECT_SOURCE_DIR}/src)
add_subdirectory(src)
add_subdirectory(config)

if(BUILD_TEST)
    add_compiler_flags("-Wno-sign-compare")
    add_subdirectory(test) # unit test
endif()

if(BUILD_FUZZ)
    add_subdirectory(fuzz)
endif ()

get_property(scf_link_options DIRECTORY PROPERTY LINK_OPTIONS)
message(STATUS "==============================================================")
message(STATUS "User Options and Configurations")
message(STATUS "==============================================================")
message(STATUS "CMake Version             : ${CMAKE_VERSION}")
message(STATUS "Build Type                : ${CMAKE_BUILD_TYPE}")
message(STATUS "CPU Type                  : ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "Compiler                  : ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Compiler Version          : ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "C++ Standard              : ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler Flags            : \n${CMAKE_CXX_FLAGS}")
message(STATUS "Linker Flags              : \n${scf_link_options}")
message(STATUS "CMAKE_INSTALL_PREFIX      : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "CMAKE_DEPENDENCY_SRCDIR   : ${CMAKE_DEPENDENCY_SRCDIR}")
message(STATUS "(opt) DOWNLOAD_DEPENDENCY : ${DOWNLOAD_DEPENDENCY}")
message(STATUS "(opt) BUILD_TEST          : ${BUILD_TEST}")
message(STATUS "(opt) BUILD_COVERAGE      : ${BUILD_COVERAGE}")
message(STATUS "(opt) BUILD_FUZZ          : ${BUILD_FUZZ}")
message(STATUS "(opt) BUILD_ASAN          : ${BUILD_ASAN}")
message(STATUS "==============================================================")
