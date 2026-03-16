# Copyright (C) 2025 by huawei.com

# ------------------------------------------------------------------------------
# Configure the build process of rapidjson c library
# ------------------------------------------------------------------------------

message("build rapidjson start")

set(TMP_EXTRA_ARGS
        PREFIX
        ${DEPENDENCY_INSTALL_PREFIX_NAME}
        CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPENDENCY_INSTALL_PREFIX}
        -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
        -DCMAKE_SKIP_RPATH=True
        -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
        LOG_DOWNLOAD
        On
        LOG_CONFIGURE
        On
        LOG_BUILD
        On
        LOG_INSTALL
        On)

if(NOT DOWNLOAD_DEPENDENCY)
    ExternalProject_Add(
            rapidjson
            SOURCE_DIR ${DOWNLOADED_DEPENDENCY_DIR}/rapidjson
            ${TMP_EXTRA_ARGS})
else()
    ExternalProject_Add(
            rapidjson
            GIT_REPOSITORY
            https://gitcode.com/gh_mirrors/rap/rapidjson.git
            GIT_TAG master
            GIT_SUBMODULES_RECURSE Off
            GIT_SUBMODULES ""
            GIT_SHALLOW On
            ${TMP_EXTRA_ARGS})
endif()

add_library(librapidjson INTERFACE)
target_include_directories(librapidjson
#        PUBLIC
        INTERFACE ${CMAKE_DEPENDENCY_INCLUDEDIR})
add_dependencies(librapidjson rapidjson)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Dependency::rapidjson ALIAS librapidjson)

message("build rapidjson end")
