# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set(_libboundscheck_src "${DOWNLOADED_DEPENDENCY_DIR}/libboundscheck")
if(EXISTS "${_libboundscheck_src}")
    message(STATUS "Using local source for libboundscheck: ${_libboundscheck_src}")
    ExternalProject_Add(
            libboundscheck-src
            PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
            SOURCE_DIR ${_libboundscheck_src}
            CONFIGURE_COMMAND ""
            BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
            DOWNLOAD_COMMAND ""
            UPDATE_COMMAND ""
            INSTALL_COMMAND mkdir -p ${CMAKE_DEPENDENCY_INCLUDEDIR}
            COMMAND mkdir -p ${CMAKE_DEPENDENCY_LIBDIR}
            COMMAND cp -af include/securec.h ${CMAKE_DEPENDENCY_INCLUDEDIR}
            COMMAND cp -af include/securectype.h ${CMAKE_DEPENDENCY_INCLUDEDIR}
            COMMAND cp -af lib/libboundscheck${CMAKE_SHARED_LIBRARY_SUFFIX} ${CMAKE_DEPENDENCY_LIBDIR}/
            BUILD_IN_SOURCE On
            EXCLUDE_FROM_ALL true
            LOG_CONFIGURE On
            LOG_BUILD On
            LOG_INSTALL On)
else()
    ExternalProject_Add(
            libboundscheck-src
            GIT_REPOSITORY https://atomgit.com/openeuler/libboundscheck.git
            GIT_TAG master
            GIT_SHALLOW On
            PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
            CONFIGURE_COMMAND ""
            BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
            UPDATE_COMMAND ""
            INSTALL_COMMAND  mkdir -p ${CMAKE_DEPENDENCY_INCLUDEDIR}
            COMMAND mkdir -p ${CMAKE_DEPENDENCY_LIBDIR}
            COMMAND cp -af include/securec.h ${CMAKE_DEPENDENCY_INCLUDEDIR}
            COMMAND cp -af include/securectype.h ${CMAKE_DEPENDENCY_INCLUDEDIR}
            COMMAND cp -af lib/libboundscheck${CMAKE_SHARED_LIBRARY_SUFFIX} ${CMAKE_DEPENDENCY_LIBDIR}
            BUILD_IN_SOURCE On
            EXCLUDE_FROM_ALL true
            LOG_DOWNLOAD On
            LOG_CONFIGURE On
            LOG_BUILD On
            LOG_INSTALL On)
endif()

add_library(libboundscheck-itf INTERFACE)
target_link_directories(libboundscheck-itf INTERFACE ${CMAKE_DEPENDENCY_LIBDIR})
target_link_libraries(libboundscheck-itf
        INTERFACE libboundscheck${CMAKE_SHARED_LIBRARY_SUFFIX})
add_dependencies(libboundscheck-itf libboundscheck-src)

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Dependency::secure_c ALIAS libboundscheck-itf)

add_compile_options(-lboundscheck)