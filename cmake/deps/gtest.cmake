# ------------------------------------------------------------------------------
# Configure the build process of gtest
# ------------------------------------------------------------------------------

if(DOWNLOAD_DEPENDENCY)
  ExternalProject_Add(
    gtest
    GIT_REPOSITORY https://atomgit.com/GitHub_Trending/go/googletest.git
    GIT_TAG v1.15.2
    GIT_SHALLOW On
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

  set(SCF_GTEST_LIBRARIES libgtest libgtest_main)
  set(SCF_GTEST_INCLUDE_DIRS ${CMAKE_DEPENDENCY_INCLUDEDIR})
else()
  find_package(GTest REQUIRED)
  if(TARGET GTest::gtest)
    set(SCF_GTEST_LIBRARIES GTest::gtest GTest::gtest_main)
  else()
    set(SCF_GTEST_LIBRARIES GTest::GTest GTest::Main)
  endif()
endif()

add_library(libgtest_interface INTERFACE)
target_link_libraries(libgtest_interface INTERFACE ${SCF_GTEST_LIBRARIES})
if(SCF_GTEST_INCLUDE_DIRS)
  target_include_directories(libgtest_interface
                             INTERFACE ${SCF_GTEST_INCLUDE_DIRS})
endif()

# -----------------------------
# Alias Target for External Use
# -----------------------------
add_library(Dependency::gtest ALIAS libgtest_interface)
