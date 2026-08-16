cmake_minimum_required(VERSION 3.25)

project(wolftpm_attestation_bench VERSION 2.0.0 LANGUAGES C)

# wolfTPM's Linux transport uses POSIX interfaces such as usleep(). Keep GNU/POSIX
# declarations visible even when the application requests a specific C standard.
set(CMAKE_C_EXTENSIONS ON)

# Build one common stack with both classical and TPM 2.0 v1.85 PQC enabled.
# Runtime --crypto selection changes the key/profile only, not the binary.
add_compile_definitions(
    _DEFAULT_SOURCE
    WOLFTPM_V185
    WOLFTPM_PQC
    WOLFTPM_MLDSA
    WOLFTPM_MLKEM
)

include(CTest)

# wolfSSL is the only dependency installed into .local. wolfTPM itself is
# intentionally built directly from third_party/wolftpm so edits to the source
# tree are picked up by the normal application build.
find_package(wolfssl 5.9 CONFIG REQUIRED)

set(WOLFTPM_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolftpm")
if(NOT EXISTS "${WOLFTPM_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "wolfTPM submodule is missing. Run: git submodule update --init --recursive")
endif()

# Configure the patched wolfTPM subproject before adding it. Keep the client
# build minimal and use the SWTPM/Microsoft-simulator socket transport.
if(NOT DEFINED WOLFTPM_WOLFSSL_PREFIX)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.local/include/wolfssl")
        set(_wolftpm_wolfssl_default "${CMAKE_CURRENT_SOURCE_DIR}/.local")
    elseif(EXISTS "/opt/wolftpm/include/wolfssl")
        set(_wolftpm_wolfssl_default "/opt/wolftpm")
    else()
        set(_wolftpm_wolfssl_default "${CMAKE_CURRENT_SOURCE_DIR}/.local")
    endif()
    set(WOLFTPM_WOLFSSL_PREFIX "${_wolftpm_wolfssl_default}" CACHE PATH
        "wolfSSL installation prefix used by patched wolfTPM")
endif()
set(WITH_WOLFSSL "${WOLFTPM_WOLFSSL_PREFIX}" CACHE PATH "wolfSSL prefix" FORCE)
set(WOLFTPM_EXAMPLES no CACHE STRING "Build wolfTPM examples" FORCE)
set(WOLFTPM_FWTPM no CACHE STRING "Build fwTPM server in host app build" FORCE)
set(WOLFTPM_INTERFACE SWTPM CACHE STRING "wolfTPM transport" FORCE)
set(BUILD_SHARED_LIBS ON CACHE BOOL "Build shared libraries" FORCE)

add_subdirectory(
    "${WOLFTPM_SOURCE_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}/third_party/wolftpm"
    EXCLUDE_FROM_ALL
)

# wolfTPM has used both a normal target and a namespaced alias across CMake
# revisions. Accept either so the top-level project stays stable.
if(TARGET wolfssl::wolftpm)
    set(ATTESTATION_WOLFTPM_TARGET wolfssl::wolftpm)
elseif(TARGET wolftpm)
    set(ATTESTATION_WOLFTPM_TARGET wolftpm)
else()
    message(FATAL_ERROR "Vendored wolfTPM did not define a usable CMake target")
endif()

add_executable(
    wolftpm_demo
    src/main.c
    src/attestation.c
    src/crypto_profile.c
    src/metrics.c
    src/options.c
    src/transport_trace.c
    src/verifier.c
)

target_compile_features(wolftpm_demo PRIVATE c_std_11)

target_compile_options(
    wolftpm_demo
    PRIVATE
        $<$<C_COMPILER_ID:Clang,GNU>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>
)

target_link_libraries(
    wolftpm_demo
    PRIVATE
        ${ATTESTATION_WOLFTPM_TARGET}
        wolfssl::wolfssl
)

# tpm2_metrics.h is a thesis-only header added directly to the vendored source.
# The explicit include keeps this robust even if upstream wolfTPM's CMake target
# does not automatically expose a newly-added public header directory.
target_include_directories(
    wolftpm_demo
    PRIVATE
        "${WOLFTPM_SOURCE_DIR}"
)

install(TARGETS wolftpm_demo RUNTIME DESTINATION bin)

if(BUILD_TESTING)
    add_test(
        NAME simulator_smoke_pq
        COMMAND wolftpm_demo --crypto pq --iterations 1 --warmup 0 --quiet
    )
    add_test(
        NAME simulator_smoke_rsa
        COMMAND wolftpm_demo --crypto rsa --iterations 1 --warmup 0 --quiet
    )
    set_tests_properties(
        simulator_smoke_pq
        simulator_smoke_rsa
        PROPERTIES
            LABELS "integration"
            TIMEOUT 60
    )
endif()
