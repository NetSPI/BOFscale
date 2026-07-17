
cmake_minimum_required(VERSION 3.15)

set(BOFPE_NAME socksportfwd.${ARCH})
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
 
add_library(${BOFPE_NAME} SHARED main.cpp)
set_target_properties(${BOFPE_NAME} PROPERTIES SUFFIX ".o")

#add_executable(${BOFPE_NAME} main.cpp)
target_include_directories(${BOFPE_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/beacon ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(${BOFPE_NAME} beacon rpcrt4)
target_link_directories(${BOFPE_NAME} PRIVATE ${CMAKE_SOURCE_DIR})
target_compile_definitions(${BOFPE_NAME} PRIVATE _WIN32_WINNT=0x600 RPC_NO_WINDOWS_H _WINSOCK_DEPRECATED_NO_WARNINGS)

if (CMAKE_C_COMPILER_ID MATCHES "MSVC|Clang")
    target_compile_options(${BOFPE_NAME} PRIVATE /GS- /MT /EHa)
    target_link_options(${BOFPE_NAME} PRIVATE /MERGE:.gfids=. /MERGE:_RDATA=. /MERGE:.data=. /MERGE:.rdata=. /MERGE:.pdata=. /SECTION:.,RW /MERGE:.discard_data=.discard)
    target_link_libraries(${BOFPE_NAME} "ntdll")

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_link_options(${BOFPE_NAME} PRIVATE /SAFESEH)
    endif()

else()
    target_link_options(${BOFPE_NAME} PRIVATE -fexceptions -static -T${LINK_SCRIPT} -Wl,--strip-debug)
endif()

install(TARGETS ${BOFPE_NAME} DESTINATION "pe/")
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/socksportfwd_ost_bof.s1.py DESTINATION "ost/")
