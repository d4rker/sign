cmake_minimum_required(VERSION 2.8.5)

set(BUILD_TYPE "test")
set(MYPROJECT ${BUILD_TYPE})
project(${MYPROJECT} C)

#-----------------------------------------------------------------------------
# Options for building

option(BUILD_COVERAGE "Compile with test coverage flags." OFF)
option(BUILD_VALGRIND "Compile with debug symbols." ON)
option(BUILD_DOCUMENTATION "Build the Doxygen documentation." OFF)
option(CMAKE_VERBOSE_MAKEFILE "Verbose build." OFF)

if(CONTINUOUS_INTEGRATION AND BUILD_TYPE STREQUAL "test")
    set(BUILD_COVERAGE "ON")
    set(BUILD_VALGRIND "ON")
endif()

execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion OUTPUT_VARIABLE C_COMPILER_VERSION)

#-----------------------------------------------------------------------------
# Source Definitions

if(CONTINUOUS_INTEGRATION)
  add_definitions(-DCONTINUOUS_INTEGRATION)
endif()

if(BUILD_TYPE STREQUAL "test")
  add_definitions(-DTESTING)
endif()

add_definitions(-DuECC_OPTIMIZATION_LEVEL=4)
#-----------------------------------------------------------------------------
# Print system information and build options

message(STATUS "\n\n=============================================")
message(STATUS "            - General -")
message(STATUS "CMake version:          ${CMAKE_VERSION}")
message(STATUS "System:                 ${CMAKE_SYSTEM}")
message(STATUS "Processor:              ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "             - Build -")
message(STATUS "Compiler version:       ${CMAKE_C_COMPILER_ID} ${C_COMPILER_VERSION}")
message(STATUS "Compiler:               ${CMAKE_C_COMPILER}")
message(STATUS "Linker:                 ${CMAKE_LINKER}")
message(STATUS "Archiver:               ${CMAKE_AR}")
message(STATUS "            - Options -")
message(STATUS "Build type:             ${BUILD_TYPE}")
message(STATUS "Verbose:                ${CMAKE_VERBOSE_MAKEFILE}")
message(STATUS "Documentation:          ${BUILD_DOCUMENTATION}  (make doc)")
message(STATUS "Coverage flags:         ${BUILD_COVERAGE}")
message(STATUS "Debug symbols:          ${BUILD_VALGRIND}")
message(STATUS "SECP256k1 library:      uECC ")
message(STATUS "\n=============================================\n\n")

#-----------------------------------------------------------------------------
# Collect all binaries into bin subdirectory

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH  ${CMAKE_CURRENT_BINARY_DIR}/lib)

#-----------------------------------------------------------------------------
# Compiler

if(BUILD_VALGRIND)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -O0 -g")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Os")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra -Wall -Wpedantic -Werror -Wstrict-prototypes -Wmissing-prototypes -Werror-implicit-function-declaration -Wpointer-arith -std=gnu99 -ffunction-sections -fdata-sections -Wchar-subscripts -Wcomment -Wformat=2 -Wimplicit-int -Wmain -Wparentheses -Wsequence-point -Wreturn-type -Wswitch -Wtrigraphs -Wunused -Wuninitialized -Wunknown-pragmas -Wfloat-equal -Wundef -Wshadow -Wbad-function-cast -Wwrite-strings -Wsign-compare -Waggregate-return  -Wmissing-declarations -Wformat -Wmissing-format-attribute -Wno-deprecated-declarations -Wpacked -Wredundant-decls -Wnested-externs -Wmultichar -Wformat-nonliteral -Winit-self -Wformat-security -Wold-style-definition -Wmissing-include-dirs -Wswitch-default -Wattributes -Wcast-qual")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-implicit-fallthrough")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all -Wno-unused-function -Wno-missing-field-initializers -Wno-long-long")

#-----------------------------------------------------------------------------
# Test coverage flags
#-----------------------------------------------------------------------------
# Build Documentation
#-----------------------------------------------------------------------------
# Build

message(STATUS "C Flags:          ${CMAKE_C_FLAGS}")

add_subdirectory(src)

if(BUILD_TYPE STREQUAL "test")
    add_subdirectory(tests)
    enable_testing()
endif()

#-----------------------------------------------------------------------------
# Clean
set(removefiles "bin/*.* lib/*.*")
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${removefiles}")
