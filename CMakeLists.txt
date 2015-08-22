CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(pi9)
set(PI9_NAME "pi9")
set(PI9_DESCRIPTION "9p server abstraction library")

OPTION(PI9_BUILD_BINARIES "Build binaries" ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${pi9_SOURCE_DIR}/CMake)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)

if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
   set(ldflags -Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now)
   set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${ldflags}")
   set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${ldflags}")
   set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${ldflags}")
   add_definitions(
      -Wall -Wextra -Wno-variadic-macros -Wno-long-long -Wformat=2 -Winit-self -Wfloat-equal
      -Wcast-align -Wpointer-arith -Wmissing-prototypes -Wsuggest-attribute=pure -Wsuggest-attribute=const)
   add_definitions(-fstack-protector-strong -fstack-check -pie -flto)
endif ()

if (UNIX AND CMAKE_COMPILER_IS_GNUCC)
   set(CMAKE_POSITION_INDEPENDENT_CODE ON)
   if (${CMAKE_VERSION} VERSION_LESS 2.8.9)
      add_definitions(-fPIC)
   endif ()
endif ()

add_definitions(-std=c99 -D_DEFAULT_SOURCE)

include_directories(
   ${CMAKE_CURRENT_SOURCE_DIR}/src
   ${CMAKE_CURRENT_SOURCE_DIR}/lib/chck)

add_subdirectory(lib)
add_subdirectory(src)

if (PI9_BUILD_BINARIES)
   add_subdirectory(bin)
endif ()

file(COPY src/pi9.h src/pi9_string.h DESTINATION include/pi9)
