# ------------------------------------------------------------------------------
# Configure the build process of secodefuzz
# ------------------------------------------------------------------------------

set(TMP_EXTRA_ARGS
        PREFIX
        ${DEPENDENCY_INSTALL_PREFIX_NAME}
        CMAKE_ARGS
        # NOTE this is xxxxing wired why they are not following standards
        -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPENDENCY_INSTALL_PREFIX}
        BUILD_COMMAND
        ${CMAKE_MAKE_PROGRAM}
        Secodefuzz
        INSTALL_COMMAND
        mkdir
        -p
        ${CMAKE_DEPENDENCY_INCLUDEDIR}/secodefuzz
        COMMAND
        cp
        -af
        Secodefuzz/secodeFuzz.h
        ${CMAKE_DEPENDENCY_INCLUDEDIR}/secodefuzz
        COMMAND
        cp
        -af
        examples/xml-lib/libxml2-2.6.26/include/libxml
        ${CMAKE_DEPENDENCY_INCLUDEDIR}
        COMMAND
        cp
        -af
        examples/out-bin-x64/libSecodefuzz.a
        ${CMAKE_DEPENDENCY_LIBDIR}
        BUILD_IN_SOURCE
        On
        EXCLUDE_FROM_ALL
        True
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
            secodefuzz
            SOURCE_DIR ${DOWNLOADED_DEPENDENCY_DIR}/secodefuzz
            ${TMP_EXTRA_ARGS})
else()
    ExternalProject_Add(
            secodefuzz
            GIT_REPOSITORY
            https://codehub-dg-y.huawei.com/software-engineering-research-community/fuzz/secodefuzz.git
            GIT_TAG v2.4.8
            GIT_SHALLOW On
            ${TMP_EXTRA_ARGS})
endif()

add_library(libsecodefuzz STATIC IMPORTED)
add_dependencies(libsecodefuzz secodefuzz)

set_target_properties(
        libsecodefuzz
        PROPERTIES
        IMPORTED_LOCATION
        ${CMAKE_DEPENDENCY_LIBDIR}/libSecodefuzz${CMAKE_STATIC_LIBRARY_SUFFIX})

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Dependency::secodefuzz ALIAS libsecodefuzz)