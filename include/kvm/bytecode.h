#ifndef KVM_BYTECODE_H
#define KVM_BYTECODE_H

#include "kvm/value.h"
#include "kvm/allocator.h"
#include "kvm/errors.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#define KVM_BYTECODE_MAGIC   0x43424b7fU /* \x7fKBC */
#define KVM_BYTECODE_VERSION 1

typedef uint32_t KvmInstruction;

typedef enum {
    /* Constants & Moves */
    OP_LOADK = 1,
    OP_LOADI,
    OP_LOADNIL,
    OP_LOADBOOL,
    OP_MOVE,

    /* Arithmetic (generic, int, float) */
    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_MOD,
    OP_NEG,

    OP_IADD,
    OP_ISUB,
    OP_IMUL,
    OP_IDIV,
    OP_IMOD,
    OP_INEG,

    OP_FADD,
    OP_FSUB,
    OP_FMUL,
    OP_FDIV,
    OP_FNEG,

    /* Comparison & Branching */
    OP_EQ,
    OP_LT,
    OP_LE,
    OP_NOT,

    OP_JMP,
    OP_JMPIF,
    OP_JMPIFNOT,

    OP_JLT,
    OP_JLE,
    OP_JEQ,
    OP_JNLT,
    OP_JNLE,
    OP_JNEQ,

    /* Calls & Return */
    OP_CALL,
    OP_CALLNATIVE,
    OP_TAILCALL,
    OP_RETURN,

    /* Memory & Ownership */
    OP_NEWOBJ,
    OP_NEWARRAY,
    OP_GETFIELD,
    OP_SETFIELD,
    OP_GETINDEX,
    OP_SETINDEX,
    OP_DROP,
    OP_BORROW,
    OP_BORROWMUT,
    OP_ENDBORROW,
    OP_COPYREF,

    /* Opt-in RC */
    OP_NEWRC,
    OP_RCCLONE,
    OP_RCDROP,

    /* Foreign */
    OP_FFICALL,

    /* Misc */
    OP_LOOPHINT,
    OP_SAFEPOINT,
    OP_TRAP,

    OP_MAX_OPCODE
} KvmOpcode;

#define KVM_OPCODE(inst)    ((uint8_t)((inst) & 0xFFU))
#define KVM_REG_A(inst)     ((uint8_t)(((inst) >> 8) & 0xFFU))
#define KVM_REG_B(inst)     ((uint8_t)(((inst) >> 16) & 0xFFU))
#define KVM_REG_C(inst)     ((uint8_t)(((inst) >> 24) & 0xFFU))
#define KVM_IMM16(inst)     ((uint16_t)(((inst) >> 16) & 0xFFFFU))
#define KVM_SIMM16(inst)    ((int16_t)((int16_t)(((inst) >> 16) & 0xFFFFU)))

#define KVM_ENCODE_ABC(op, a, b, c) \
    ((KvmInstruction)(((uint32_t)(op) & 0xFFU) | \
                     (((uint32_t)(a) & 0xFFU) << 8) | \
                     (((uint32_t)(b) & 0xFFU) << 16) | \
                     (((uint32_t)(c) & 0xFFU) << 24)))

#define KVM_ENCODE_ABI(op, a, imm) \
    ((KvmInstruction)(((uint32_t)(op) & 0xFFU) | \
                     (((uint32_t)(a) & 0xFFU) << 8) | \
                     (((uint32_t)(imm) & 0xFFFFU) << 16)))

#define KVM_ENCODE_ABSI(op, a, simm) \
    KVM_ENCODE_ABI(op, a, (uint16_t)(simm))

typedef struct KvmFfiSig {
    char *symbol_name;
    char *sig_str;
} KvmFfiSig;

typedef struct KvmTypeDesc {
    char *name;
    size_t field_count;
    char **field_names;
} KvmTypeDesc;

typedef struct KvmFunction {
    char *name;
    uint16_t arity;
    uint16_t reg_count;

    size_t const_count;
    Value *const_pool;

    size_t code_count;
    KvmInstruction *code;

    size_t line_table_count;
    uint32_t *line_table;

    uint32_t entry_count;
    uint32_t loop_count;
    uint32_t *loop_counters;

    void *jit_code;
    bool interp_only;
    uint32_t deopt_count;
} KvmFunction;

typedef struct KvmBytecode {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint32_t entry_func_idx;

    size_t const_count;
    Value *const_pool;

    size_t func_count;
    KvmFunction **functions;

    size_t ffi_sig_count;
    KvmFfiSig *ffi_sigs;

    size_t type_desc_count;
    KvmTypeDesc *type_descs;
} KvmBytecode;

KvmBytecode *kvm_bytecode_create(void);
void kvm_bytecode_destroy(KvmAllocator *alloc, KvmBytecode *bc);

KvmFunction *kvm_function_create(const char *name, uint16_t arity, uint16_t reg_count);
void kvm_function_destroy(KvmAllocator *alloc, KvmFunction *fn);

const char *kvm_opcode_name(KvmOpcode op);

KvmStatus kvm_bytecode_write_file(const KvmBytecode *bc, const char *filepath);
KvmStatus kvm_bytecode_write_bytes(const KvmBytecode *bc, uint8_t **out_buf, size_t *out_size);
KvmStatus kvm_bytecode_read_bytes(const uint8_t *buf, size_t size, KvmBytecode **out_bc);
KvmStatus kvm_bytecode_read_file(const char *filepath, KvmBytecode **out_bc);

KvmStatus kvm_bytecode_validate(const KvmBytecode *bc, char *err_msg, size_t err_msg_cap);
KvmStatus kvm_bytecode_assemble(const char *source, KvmBytecode **out_bc, char *err_msg, size_t err_cap);
void kvm_bytecode_disassemble(const KvmBytecode *bc, FILE *out);

#endif /* KVM_BYTECODE_H */
