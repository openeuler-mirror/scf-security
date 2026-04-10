# Copyright (C) 2025 by huawei.com

if(NOT DOWNLOAD_DEPENDENCY)
    # Use system-installed rapidjson from RPM
    add_library(librapidjson INTERFACE)
    target_include_directories(librapidjson INTERFACE /usr/include)
    add_library(Dependency::rapidjson ALIAS librapidjson)
else()
    # Use FetchContent to download from source
    if(NOT EXISTS "${DOWNLOADED_DEPENDENCY_DIR}/rapidjson")
        set(FETCH_CONTENT_URL https://gitcode.com/GitHub_Trending/ra/rapidjson.git)
    endif()

    ExternalProject_Add(rapidjson
        GIT_REPOSITORY ${FETCH_CONTENT_URL}
        GIT_TAG master
        GIT_SUBMODULES_RECURSE Off
        GIT_SHALLOW On
        PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPENDENCY_INSTALL_PREFIX}
                   -DCMAKE_SKIP_RPATH=True)

    add_library(librapidjson INTERFACE)
    target_include_directories(librapidjson INTERFACE ${CMAKE_DEPENDENCY_INCLUDEDIR})
    add_dependencies(librapidjson rapidjson)
    add_library(Dependency::rapidjson ALIAS librapidjson)
endif()