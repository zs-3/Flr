cmake_minimum_required(VERSION 3.16)
project(kvm C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Compiler flags
add_compile_options(-Wall -Wextra -Wpedantic -Werror)

# Build type options
option(KVM_ENABLE_ASAN "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(KVM_ENABLE_ASAN)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/mir
)

# Build MIR library
set(MIR_SOURCES
    third_party/mir/mir.c
    third_party/mir/mir-gen.c
    third_party/mir/mir-alloc-default.c
    third_party/mir/mir-code-alloc-default.c
)

add_library(mir_lib STATIC ${MIR_SOURCES})
target_compile_options(mir_lib PRIVATE "SHELL:-include stdarg.h" "SHELL:-include stddef.h" "SHELL:-include stdint.h" -w -fno-sanitize=undefined)

# KVM library sources
file(GLOB_RECURSE KVM_CORE_SOURCES src/core/*.c)
file(GLOB_RECURSE KVM_BYTECODE_SOURCES src/bytecode/*.c)
file(GLOB_RECURSE KVM_INTERP_SOURCES src/interp/*.c)
file(GLOB_RECURSE KVM_JIT_SOURCES src/jit/*.c)
file(GLOB_RECURSE KVM_FFI_SOURCES src/ffi/*.c)

set(KVM_SOURCES
    ${KVM_CORE_SOURCES}
    ${KVM_BYTECODE_SOURCES}
    ${KVM_INTERP_SOURCES}
    ${KVM_JIT_SOURCES}
    ${KVM_FFI_SOURCES}
)

add_library(vm STATIC ${KVM_SOURCES})
target_link_libraries(vm PUBLIC mir_lib ${CMAKE_DL_LIBS} m)

# CLI runner target
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/tools/kvm.c")
    add_executable(kvm src/tools/kvm.c)
    target_link_libraries(kvm PRIVATE vm)
endif()

# Test runner target
file(GLOB_RECURSE KVM_UNIT_TEST_SOURCES tests/unit/*.c)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/kvm_tests.c")
    add_executable(kvm_tests tests/kvm_tests.c ${KVM_UNIT_TEST_SOURCES})
    target_link_libraries(kvm_tests PRIVATE vm)
endif()

# Differential test runner
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/diff/test_diff.c")
    add_executable(kvm_diff_tests tests/diff/test_diff.c)
    target_link_libraries(kvm_diff_tests PRIVATE vm)
endif()

# Bytecode validator fuzzer
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz/fuzz_validator.c")
    add_executable(kvm_fuzz_validator tests/fuzz/fuzz_validator.c)
    target_link_libraries(kvm_fuzz_validator PRIVATE vm)
endif()

# Benchmark suite
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/benchmarks.c")
    add_executable(kvm_benchmarks benchmarks/benchmarks.c)
    target_link_libraries(kvm_benchmarks PRIVATE vm)
endif()

# Embedding C API example target
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/embed.c")
    add_executable(kvm_embed_example examples/embed.c)
    target_link_libraries(kvm_embed_example PRIVATE vm)
endif()
