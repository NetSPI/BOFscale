# BOFScale

BOF-PE modules for tailscale operations.

## Components

| Target | Description |
|---|---|
| `tailscale` | Cut-down tailscale CLI client BOF (C++) |
| `tailscaled` | RFC 6455 websocket compatible tailscale daemon: BOF (Go/CGO), Windows exe, CLI, Linux binary |
| `socksportfwd` | SOCKS port forwarding BOF (C++) |

## Prerequisites

- CMake 3.18+
- MSVC (Visual Studio 2022) or a cross-compilation toolchain
- Go 1.21+ and mingw-w64 (for `tailscaled` targets)

## Building

### Windows (MSVC)

```
mkdir build-x64
cd build-x64
cmake -DCMAKE_BUILD_TYPE=MinSizeRel ..
cmake --build . --config MinSizeRel
cmake --install . --config MinSizeRel
```

Artifacts are installed to `build-x64/dist/` by default. Override with `-DCMAKE_INSTALL_PREFIX=<path>`.

### Linux (cross-compile)

Using the `ccob/windows-llvm-cross-msvc` container image:

```
# x64
mkdir build-x86_64 && cd build-x86_64
cmake -DCMAKE_BUILD_TYPE=MinSizeRel \
      -DCMAKE_TOOLCHAIN_FILE=/opt/toolchain/x86_64-pc-windows-msvc.cmake ..
cmake --build . -j$(nproc)
cmake --install .

# x86
mkdir build-x86 && cd build-x86
cmake -DCMAKE_BUILD_TYPE=MinSizeRel \
      -DCMAKE_TOOLCHAIN_FILE=/opt/toolchain/i386-pc-windows-msvc.cmake ..
cmake --build . -j$(nproc)
cmake --install .
```

## CI

The GitHub Actions workflow (`.github/workflows/build.yml`) cross-compiles both x64 and x86 on push to `main` and uploads the combined `bofscale-dist` artifact.
