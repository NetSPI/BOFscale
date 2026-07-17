cmake_minimum_required(VERSION 3.18)
project(bofscale )

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set_property(CACHE CMAKE_INSTALL_PREFIX PROPERTY VALUE ${CMAKE_SOURCE_DIR}/dist)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)

message("-- Building for ${CMAKE_CXX_COMPILER_ID} compiler")

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(LINK_SCRIPT ${CMAKE_SOURCE_DIR}/link.ld)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(LINK_SCRIPT ${CMAKE_SOURCE_DIR}/link32.ld)
endif()

string(TOLOWER ${CMAKE_SYSTEM_PROCESSOR} ARCH)

if(${ARCH} MATCHES "amd64" OR ${ARCH} MATCHES "x86_64")
    set(ARCH "x64")
else()
    set(ARCH "x86")
endif()

include_directories(${CMAKE_SOURCE_DIR}/beacon/)

#Main beacon compat layer and loader for standalone exection
add_subdirectory(beacon)

#BOF-PE projects
add_subdirectory(tailscale)
add_subdirectory(tailscaled)
add_subdirectory(socksportfwd)

