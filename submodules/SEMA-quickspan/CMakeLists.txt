cmake_minimum_required (VERSION 2.6)
project (gspan)
# The version number.
set(QUICKSPAN_VERSION_MAJOR 0)
set(QUICKSPAN_VERSION_MINOR 1)
set(QUICKSPAN_PERFORMANCE 1)

# Mode
set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -O3 -g -std=c++11 -lpthread ")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -std=c++11 -lpthread")

# Packages
find_package(OpenMP)
if (OPENMP_FOUND)
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif()
 
# configure a header file to pass some of the CMake settings
# to the source code
configure_file(
  "${PROJECT_SOURCE_DIR}/config.h.in"
  "${PROJECT_SOURCE_DIR}/include/config.h"
  )
 
# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
set(QUICKSPAN_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/include")
set(QUICKSPAN_SOURCE_DIR "${PROJECT_SOURCE_DIR}/src")
set(QUICKSPAN_TEMPLATES_DIR "${PROJECT_SOURCE_DIR}/templates")

include_directories(${QUICKSPAN_INCLUDE_DIR})

set(HEADERS
  "${QUICKSPAN_INCLUDE_DIR}/common.h"
  "${QUICKSPAN_INCLUDE_DIR}/database.h"
  "${QUICKSPAN_INCLUDE_DIR}/graph.h"
  "${QUICKSPAN_INCLUDE_DIR}/quickspanspan.h"
  "${QUICKSPAN_INCLUDE_DIR}/history.h"
  "${QUICKSPAN_INCLUDE_DIR}/output.h")

set(SOURCES
  "${QUICKSPAN_SOURCE_DIR}/history.cc"
  "${QUICKSPAN_SOURCE_DIR}/database.cc"
  "${QUICKSPAN_SOURCE_DIR}/output.cc"
  "${QUICKSPAN_SOURCE_DIR}/quickspan.cc"
  "${QUICKSPAN_SOURCE_DIR}/quickspan_count.cc"
  "${QUICKSPAN_SOURCE_DIR}/quickspan_execute.cc"
  "${QUICKSPAN_SOURCE_DIR}/quickspan_extend.cc"
  "${QUICKSPAN_SOURCE_DIR}/quickspan_mine.cc"
        "${QUICKSPAN_SOURCE_DIR}/l_malloc.c")

# below is for versioning using git
set(GIT_EXECUTABLE "git")
set(GIT_VERSION "unknown")

# get the git version in GIT_VERSION variable
execute_process(COMMAND
  "${GIT_EXECUTABLE}" describe --tags --dirty
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
  OUTPUT_VARIABLE GIT_VERSION
  ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

message(STATUS "Version: ${GIT_VERSION}")

# Generate a cc file based on a template and append it to the sources
configure_file("${QUICKSPAN_TEMPLATES_DIR}/version.cc.in" "${QUICKSPAN_SOURCE_DIR}/version.cc" @ONLY)
list(APPEND SOURCES "${QUICKSPAN_SOURCE_DIR}/version.cc")

# add the executable
add_executable(gspan ${SOURCES})
TARGET_LINK_LIBRARIES(gspan -lglog -lgflags -ldl)
