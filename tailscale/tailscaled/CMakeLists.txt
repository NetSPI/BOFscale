
# Path to your Go source
set(GO_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tailscale/cmd/tailscaled)
set(GO_SRC_CLI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tailscale/cmd/tailscale)

# Output binary or DLL
set(GO_OUTPUT ${CMAKE_BINARY_DIR}/tailscaled.${ARCH}/tailscaled.${ARCH}.o)

set(GO_OUTPUT_EXE ${CMAKE_BINARY_DIR}/tailscaled.${ARCH}/tailscaled.exe)
set(GO_OUTPUT_CLI_EXE ${CMAKE_BINARY_DIR}/tailscaled.${ARCH}/tailscale.exe)

set(GO_OUTPUT_LINUX ${CMAKE_BINARY_DIR}/tailscaled.${ARCH}/tailscaled)

if(${ARCH} MATCHES "x64")
    set(GO_COMPILER "x86_64-w64-mingw32-gcc")
    set(GO_ARCH "amd64")
else()
    set(GO_COMPILER "i686-w64-mingw32-gcc")
    set(GO_ARCH "386")
endif()

add_custom_command(
    OUTPUT ${GO_OUTPUT}
    COMMAND ${CMAKE_COMMAND} -E env
        GOOS=windows GOARCH=${GO_ARCH} CGO_ENABLED=1
        CC=${GO_COMPILER}
		CGO_CFLAGS="-I${CMAKE_SOURCE_DIR}/beacon" 
		CGO_LDFLAGS="-L$<TARGET_FILE_DIR:beacon>" 		
        go build -trimpath -buildmode=c-shared -ldflags=\"-s -w\" -tags "ts_omit_acme ts_omit_aws ts_omit_bakedroots ts_omit_bird ts_omit_capture ts_omit_cli ts_omit_clientupdate ts_omit_kube ts_omit_posture ts_omit_netlog ts_omit_syspolicy ts_omit_webclient ts_omit_logtail ts_omit_clientmetrics bofpe" -o ${GO_OUTPUT}
    WORKING_DIRECTORY ${GO_SRC_DIR}
    DEPENDS ${GO_SRC_DIR}
)

add_custom_command(
    OUTPUT ${GO_OUTPUT_EXE}
    COMMAND ${CMAKE_COMMAND} -E env
        GOOS=windows GOARCH=${GO_ARCH}
        go build -trimpath -ldflags=\"-s -w\" -tags "ts_omit_acme ts_omit_aws ts_omit_bakedroots ts_omit_bird ts_omit_capture ts_omit_cli ts_omit_clientupdate ts_omit_kube ts_omit_posture ts_omit_netlog ts_omit_syspolicy ts_omit_webclient ts_omit_logtail ts_omit_clientmetrics"  -o ${GO_OUTPUT_EXE}
    WORKING_DIRECTORY ${GO_SRC_DIR}
    DEPENDS ${GO_SRC_DIR}
)

add_custom_command(
    OUTPUT ${GO_OUTPUT_CLI_EXE}
    COMMAND ${CMAKE_COMMAND} -E env
        GOOS=windows GOARCH=${GO_ARCH}
        go build -trimpath -ldflags=\"-s -w\" -o ${GO_OUTPUT_CLI_EXE}
    WORKING_DIRECTORY ${GO_SRC_CLI_DIR}
    DEPENDS ${GO_SRC_CLI_DIR}
)

add_custom_command(
    OUTPUT ${GO_OUTPUT_LINUX}
    COMMAND ${CMAKE_COMMAND} -E env
        GOOS=linux GOARCH=${GO_ARCH} CC=clang
        go build -trimpath -ldflags=\"-s -w\" -tags "ts_omit_acme ts_omit_aws ts_omit_bakedroots ts_omit_bird ts_omit_capture ts_omit_cli ts_omit_clientupdate ts_omit_kube ts_omit_posture ts_omit_netlog ts_omit_syspolicy ts_omit_webclient ts_omit_logtail ts_omit_clientmetrics" -o ${GO_OUTPUT_LINUX}
    WORKING_DIRECTORY ${GO_SRC_DIR}
    DEPENDS ${GO_SRC_DIR}
)

add_custom_target(tailscaled.${ARCH} ALL DEPENDS ${GO_OUTPUT})
add_custom_target(tailscaled_cmd.${ARCH} ALL DEPENDS ${GO_OUTPUT_EXE})
add_custom_target(tailscale_cmd.${ARCH} ALL DEPENDS ${GO_OUTPUT_CLI_EXE})
add_custom_target(tailscaled_linux.${ARCH} ALL DEPENDS ${GO_OUTPUT_LINUX})
add_dependencies(tailscaled.${ARCH} beacon)

install(FILES ${GO_OUTPUT} DESTINATION "pe/")
install(FILES ${GO_OUTPUT_EXE} DESTINATION "${ARCH}/")
install(FILES ${GO_OUTPUT_CLI_EXE} DESTINATION "${ARCH}/")
install(FILES ${GO_OUTPUT_LINUX} DESTINATION "${ARCH}/")
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/${ARCH}/wintun.dll DESTINATION "${ARCH}/")
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/tailscaled_ost_bof.s1.py DESTINATION "ost/")
