cmake_minimum_required(VERSION 3.25)
project(wolftpm_attestation_bench LANGUAGES C)

set(CMAKE_C_EXTENSIONS ON)

add_compile_definitions(
    _DEFAULT_SOURCE
    WOLFTPM_V185
    WOLFTPM_PQC
    WOLFTPM_MLDSA
    WOLFTPM_MLKEM
)

find_package(wolfssl 5.9 CONFIG REQUIRED)

set(WOLFTPM_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolftpm")
if(NOT EXISTS "${WOLFTPM_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "wolfTPM is missing under attestation/third_party/wolftpm")
endif()

if(NOT DEFINED WOLFTPM_WOLFSSL_PREFIX)
    set(WOLFTPM_WOLFSSL_PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/.local")
endif()

set(WITH_WOLFSSL "${WOLFTPM_WOLFSSL_PREFIX}" CACHE PATH "wolfSSL prefix" FORCE)
set(WOLFTPM_EXAMPLES no CACHE STRING "" FORCE)
set(WOLFTPM_FWTPM no CACHE STRING "" FORCE)
set(WOLFTPM_INTERFACE SWTPM CACHE STRING "" FORCE)
set(BUILD_SHARED_LIBS ON CACHE BOOL "" FORCE)

add_subdirectory(
    "${WOLFTPM_SOURCE_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}/wolftpm"
    EXCLUDE_FROM_ALL
)

if(TARGET wolfssl::wolftpm)
    set(WOLFTPM_TARGET wolfssl::wolftpm)
elseif(TARGET wolftpm)
    set(WOLFTPM_TARGET wolftpm)
else()
    message(FATAL_ERROR "wolfTPM CMake target not found")
endif()

add_executable(attestation_bench
    src/main.c
    src/attestation.c
    src/crypto_profile.c
    src/metrics.c
    src/options.c
    src/transport_trace.c
    src/verifier.c
)

target_compile_features(attestation_bench PRIVATE c_std_11)
target_compile_options(attestation_bench PRIVATE
    $<$<C_COMPILER_ID:Clang,GNU>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>
)
target_include_directories(attestation_bench PRIVATE "${WOLFTPM_SOURCE_DIR}")
target_link_libraries(attestation_bench PRIVATE ${WOLFTPM_TARGET} wolfssl::wolfssl)
