## Porting the Mbed TLS

- Download the Mbed TLS release 3.5.1 [source code](https://github.com/Mbed-TLS/mbedtls)
- Create a `toolchain.cmake` file with the following content:

```cmake
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR armv7e-m)
set(CMAKE_STAGING_PREFIX <path_to_the_result_folder>/libmbedtls)
set(CMAKE_C_COMPILER <your_nix_path_to>-gcc-arm-embedded-12.3.rel1/bin/arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER <your_nix_path_to>-gcc-arm-embedded-12.3.rel1/bin/arm-none-eabi-g++)
set(CMAKE_MAKE_PROGRAM=<your_nix_path_to>-gnumake-4.4.1/bin/make)
set(CMAKE_STRIP <your_nix_path_to>-gcc-arm-embedded-12.3.rel1/bin/arm-none-eabi-strip)
set(CMAKE_FIND_ROOT_PATH <your_nix_path_to>-gcc-arm-embedded-12.3.rel1/arm-none-eabi)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcpu=cortex-m4 -mthumb -O0")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcpu=cortex-m4 -mthumb -O0")
set(CMAKE_EXE_LINKER_FLAGS "--specs=nosys.specs")
```

- Configure to crypto_baremetal:

```bash
./mbedtls/scripts/config.py -w ./include/mbedtls/mbedtls_config.h crypto_baremetal
```

- Toggle the flags in `mbedtls_config.h`

- Build the source using CMake in a separate directory:

```bash
mkdir mbedtls_build && cd mbedtls_build

# Configuring (necessary force that compiler works to CMake)
cmake -DCMAKE_C_COMPILER_WORKS=1 -DCMAKE_BUILD_TYPE=Release \
-DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
-DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF \
-DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
-DCMAKE_TOOLCHAIN_FILE=../toolchain.cmake ../mbedtls-3.5.1

# Compiling and installing
make all install
```

- The resulting static library will be in `<path_to_the_result_folder>/libmbedtls`