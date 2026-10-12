# KVM: Register-Based Virtual Machine with MIR JIT & Deterministic Ownership

KVM is a high-performance, register-based virtual machine written in C11. It features a MIR-based JIT compiler for hot functions, a deterministic ownership-based memory model with zero GC overhead or reference counting, a complete bytecode toolchain (assembler, disassembler, validator, binary reader/writer), and a C Foreign Function Interface (FFI).

---

## Key Features

1. **Language & Constraints:** Written in ISO C11 (`-Wall -Wextra -Wpedantic -Werror` clean). Zero external dependencies besides the vendor-pinned [MIR JIT compiler](https://github.com/vnmakarov/mir) (`third_party/mir/`).
2. **NaN-Boxed Value Representation:** 64-bit tagged values supporting inline 48-bit signed integers (`int48`), double precision floats, booleans, nils, heap object pointers, and native function handles.
3. **Deterministic Memory Model:** Zero garbage collection and zero reference counting overhead by default. Every object has a unique owner register. Destruction is recursive and immediate upon `MOVE`/`DROP` or automatic scope/frame exit sweep.
4. **Bytecode Toolchain:**
   - **Text Assembler (`.kasm`):** Assembles human-readable text code into binary bytecode.
   - **Disassembler:** Decodes bytecode binaries into annotated assembly text.
   - **Static Validator:** Verifies register bounds, basic block CFGs, uninitialized uses, and borrow scopes using a linear-time worklist dataflow analysis.
5. **MIR JIT Compiler:** Hot function entry counters trigger JIT compilation using MIR, emitting native x86_64 code directly operating on VM register arrays.
6. **C FFI & Embedding API:** Native symbol registration and `dlopen`/`dlsym` library loading with signature marshalling.

---

## Repository Layout

```
include/kvm/         Public headers (value.h, vm.h, bytecode.h, ffi.h, jit.h, errors.h)
src/core/            Value representation, size-class pool allocator, heap objects, ownership runtime
src/bytecode/        Binary reader/writer, static validator, text assembler, disassembler
src/interp/          Register-file interpreter and call frame stack
src/jit/             MIR JIT translation, tiering counters, and trampolines
src/ffi/             Foreign function binding and C dynamic library loader
src/tools/kvm.c      Command-line runner CLI tool
examples/embed.c     Embedding C API example
tests/unit/          Unit test suite per module
tests/diff/          Differential test runner (Interpreter vs JIT)
tests/programs/      32 .kasm test programs covering VM opcodes & edge cases
tests/fuzz/          Bytecode validator fuzzer (100,000 iterations)
docs/                DECISIONS.md, BYTECODE.md, MEMORY.md, BENCHMARKS.md
```

---

## Build Instructions

KVM uses CMake (minimum version 3.16) wrapped in a convenient `Makefile`.

### Standard Build
```bash
make build
```
This builds the `vm` static library, the `kvm` CLI binary, `kvm_embed_example`, and all test executables under `build/`.

### AddressSanitizer & UBSan Build
```bash
make asan
```
This creates a sanitize-enabled debug build under `build_asan/`.

---

## CLI Tool Usage (`kvm`)

The `kvm` CLI binary provides three primary commands: `run`, `asm`, and `dis`.

### 1. Running Programs (`kvm run`)
Runs a `.kasm` assembly file or a `.kbc` binary bytecode file directly:
```bash
./build/kvm run tests/programs/01_add.kasm
```

### 2. Assembling Code (`kvm asm`)
Assembles a text `.kasm` file into a binary `.kbc` bytecode file:
```bash
./build/kvm asm tests/programs/01_add.kasm /tmp/program.kbc
```

### 3. Disassembling Bytecode (`kvm dis`)
Decodes and prints disassembly with register annotations to `stdout`:
```bash
./build/kvm dis /tmp/program.kbc
```

---

## Running Test Suites

Run the complete test suite:

```bash
# 1. Unit Tests
./build/kvm_tests

# 2. Differential Testing (Interpreter vs JIT)
./build/kvm_diff_tests

# 3. Bytecode Validator Fuzzer (100,000 iterations)
./build/kvm_fuzz_validator

# 4. Performance Benchmarks
./build/kvm_benchmarks
```

To run all tests with JIT disabled:
```bash
KVM_JIT=off ./build/kvm_diff_tests
```

To test under AddressSanitizer & UBSan:
```bash
make asan
./build_asan/kvm_tests
./build_asan/kvm_diff_tests
./build_asan/kvm_fuzz_validator
```

---

## C Embedding Example

An example demonstrating embedding `libvm` in a C application is provided in `examples/embed.c`.

To compile and run:
```bash
gcc -Iinclude examples/embed.c -Lbuild -lvm -ldl -lm -o embed_example
./embed_example
```
