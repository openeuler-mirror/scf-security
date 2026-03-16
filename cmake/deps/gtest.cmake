# ------------------------------------------------------------------------------
# Configure the build process of gtest
# ------------------------------------------------------------------------------

if(DOWNLOAD_DEPENDENCY)
  set(DOWNLOAD_ARGS
      GIT_REPOSITORY https://atomgit.com/GitHub_Trending/go/googletest.git
      GIT_TAG v1.15.2 GIT_SHALLOW On)
else()
  set(DOWNLOAD_ARGS SOURCE_DIR ${DOWNLOADED_DEPENDENCY_DIR}/gtest
                    DOWNLOAD_COMMAND "")
endif()

ExternalProject_Add(
  gtest
  ${DOWNLOAD_ARGS}
  PREFIX ${DEPENDENCY_INSTALL_PREFIX_NAME}
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_DEPENDENCY_INSTALL_PREFIX}
             -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DCMAKE_SKIP_RPATH=True
  EXCLUDE_FROM_ALL Off
  LOG_DOWNLOAD On
  LOG_CONFIGURE On
  LOG_BUILD On
  LOG_INSTALL On)

add_library(libgtest STATIC IMPORTED)
set_property(
  TARGET libgtest
  PROPERTY IMPORTED_LOCATION
           ${CMAKE_DEPENDENCY_LIBDIR}/libgtest${CMAKE_STATIC_LIBRARY_SUFFIX})
add_dependencies(libgtest gtest)

add_library(libgtest_main STATIC IMPORTED)
set_property(
  TARGET libgtest_main
  PROPERTY
    IMPORTED_LOCATION
    ${CMAKE_DEPENDENCY_LIBDIR}/libgtest_main${CMAKE_STATIC_LIBRARY_SUFFIX})
add_dependencies(libgtest_main gtest)

add_library(libgtest_interface INTERFACE)
target_link_libraries(libgtest_interface INTERFACE libgtest libgtest_main)
target_include_directories(libgtest_interface
                           INTERFACE ${CMAKE_DEPENDENCY_INCLUDEDIR})

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Dependency::gtest ALIAS libgtest_interface)
