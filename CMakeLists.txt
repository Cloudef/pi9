CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(pi9)
set(PI9_NAME "pi9")
set(PI9_DESCRIPTION "9p server abstraction library")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${pi9_SOURCE_DIR}/CMake)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)

if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
   set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wall -Wextra -Wno-variadic-macros -Wno-long-long")
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wno-variadic-macros -Wno-long-long")
endif ()

if (UNIX AND CMAKE_COMPILER_IS_GNUCC)
   set(CMAKE_POSITION_INDEPENDENT_CODE ON)
   if (${CMAKE_VERSION} VERSION_LESS 2.8.9)
      add_definitions(-fPIC)
   endif ()
endif ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -D_DEFAULT_SOURCE")

include_directories(
   ${CMAKE_CURRENT_SOURCE_DIR}/src
   ${CMAKE_CURRENT_SOURCE_DIR}/lib/chck)

add_subdirectory(lib)
add_subdirectory(src)
add_subdirectory(bin)

file(COPY src/pi9.h src/pi9_string.h DESTINATION include/pi9)
