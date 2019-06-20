# stop if cmake version below 3.5
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(libitspki C CXX)

# guard against in-source builds and bad build-type strings
include(cmake/safeguards.cmake)

# detect operating system and host processor
message(STATUS "We are on a ${CMAKE_SYSTEM_NAME} system")
message(STATUS "The host processor is ${CMAKE_HOST_SYSTEM_PROCESSOR}")

include(GNUInstallDirs)
message("CMAKE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}")
IF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT) 
	SET(CMAKE_INSTALL_PREFIX "/usr/share/${CMAKE_PROJECT_NAME}" CACHE PATH "Foo install prefix" FORCE) 
ENDIF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT) 
message("CMAKE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}")

set(INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Installation directory for executables")
set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Installation directory for libraries")
set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")
set(INSTALL_MAN_DIR "${CMAKE_INSTALL_PREFIX}/share/man" CACHE PATH "Installation directory for manual pages")
set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")
message("INSTALL_BIN_DIR ${INSTALL_BIN_DIR}")
message("INSTALL_LIB_DIR ${INSTALL_LIB_DIR}")
message("INSTALL_INC_DIR ${INSTALL_INC_DIR}")
message("INSTALL_PKGCONFIG_DIR ${INSTALL_PKGCONFIG_DIR}")

# place binaries and libraries according to GNU standards
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_INCLUDE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_INCLUDEDIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})
message("CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
message("CMAKE_INCLUDE_OUTPUT_DIRECTORY ${CMAKE_INCLUDE_OUTPUT_DIRECTORY}")
message("CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")

# example how to set c++ compiler flags for GNU
if(CMAKE_CXX_COMPILER_ID MATCHES GNU)
    set(CMAKE_CXX_FLAGS         "${CMAKE_CXX_FLAGS} -Wall -Wno-unknown-pragmas -Wno-sign-compare -Woverloaded-virtual -Wwrite-strings -Wno-unused")
    set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g3")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage")
endif()

if(CMAKE_C_COMPILER_ID MATCHES GNU)
    set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wno-unknown-pragmas -Wno-sign-compare -Wwrite-strings -Wno-unused")
    set(CMAKE_C_FLAGS_DEBUG   "-O0 -g3")
    set(CMAKE_C_FLAGS_RELEASE "-O3")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
endif()

# get git hash
include(cmake/git_revision.cmake)

# project version
set(VERSION_MAJOR 1)
set(VERSION_MINOR 0)
set(VERSION_PATCH 0)

# configure header file
configure_file(
    ${PROJECT_SOURCE_DIR}/cmake/config.h.in
    ${PROJECT_BINARY_DIR}/config.h
    )

add_subdirectory(src)
add_subdirectory(src/include)

# set cdash buildname
set(BUILDNAME
    "${CMAKE_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}-${cmake_build_type_tolower}"
    CACHE STRING
    "Name of build on the dashboard"
    )

# allow to report to a cdash dashboard
include(CTest)

# fetch googletest
include(cmake/googletest.cmake)
fetch_googletest(
    ${PROJECT_SOURCE_DIR}/cmake
    ${PROJECT_BINARY_DIR}/googletest
    )

# enable testing
enable_testing()

# define tests
add_subdirectory(test)

# cpack
include(cmake/packaging.cmake)


#coverage
message("PROJECT_NAME ${PROJECT_NAME}")
message("PROJECT_TEST_NAME ${PROJECT_TEST_NAME}")
message("CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}")

if(CMAKE_BUILD_TYPE STREQUAL "coverage" OR CODE_COVERAGE)
	include(cmake/CodeCoverage.cmake)
	APPEND_COVERAGE_COMPILER_FLAGS()

	set(COVERAGE_GCOVR_EXCLUDES '_builds/*')
	SETUP_TARGET_FOR_COVERAGE_GCOVR_HTML(NAME ${PROJECT_NAME}_coverage EXECUTABLE ctest -j 2)
endif()

message("At the end of main CMakeLists")
