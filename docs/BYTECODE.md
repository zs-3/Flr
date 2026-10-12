# KVM Bytecode Specification

## 1. File Format
KVM bytecode files (`.kbc`) use a little-endian binary layout:

### Header
- `magic` [4 bytes]: `\x7fKBC` (`0x43424b7f`)
- `version` [2 bytes]: `1`
- `flags` [2 bytes]: Bit flags (reserved)
- `const_pool_count` [4 bytes]
- `func_count` [4 bytes]
- `ffi_sig_count` [4 bytes]
- `type_desc_count` [4 bytes]
- `entry_func_idx` [4 bytes]

### Sections
1. **Constant Pool Table**
2. **FFI Signature Table**
3. **Type Descriptor Table**
4. **Function Table**

## 2. Instruction Encoding
Fixed 32-bit (4-byte) encoding:
- `Opcode` [8 bits]
- `Operand A / R_dest` [8 bits]
- `Operand B / R_src1` [8 bits]
- `Operand C / R_src2` [8 bits]

For immediate/offset forms:
- `Opcode` [8 bits]
- `Operand A` [8 bits]
- `Immediate / Offset` [16 bits signed/unsigned]

## 3. Instruction Set
- **Constants & Moves**: `LOADK`, `LOADI`, `LOADNIL`, `LOADBOOL`, `MOVE`
- **Arithmetic**: `ADD`, `SUB`, `MUL`, `DIV`, `MOD`, `NEG` (int/float/generic variants)
- **Comparison & Branching**: `EQ`, `LT`, `LE`, `NOT`, `JMP`, `JMPIF`, `JMPIFNOT`, `JLT`, `JLE`, `JEQ`, `JNLT`, `JNLE`, `JNEQ`
- **Calls & Return**: `CALL`, `CALLNATIVE`, `TAILCALL`, `RETURN`
- **Memory & Ownership**: `NEWOBJ`, `NEWARRAY`, `GETFIELD`, `SETFIELD`, `GETINDEX`, `SETINDEX`, `DROP`, `BORROW`, `BORROWMUT`, `ENDBORROW`, `COPYREF`
- **FFI**: `FFICALL`
- **Misc**: `LOOPHINT`, `SAFEPOINT`, `TRAP`
