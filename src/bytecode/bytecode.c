#include "kvm/bytecode.h"
#include "kvm/ownership.h"
#include <stdlib.h>
#include <string.h>

const char *kvm_opcode_name(KvmOpcode op) {
    switch (op) {
    case OP_LOADK: return "LOADK";
    case OP_LOADI: return "LOADI";
    case OP_LOADNIL: return "LOADNIL";
    case OP_LOADBOOL: return "LOADBOOL";
    case OP_MOVE: return "MOVE";
    case OP_ADD: return "ADD";
    case OP_SUB: return "SUB";
    case OP_MUL: return "MUL";
    case OP_DIV: return "DIV";
    case OP_MOD: return "MOD";
    case OP_NEG: return "NEG";
    case OP_IADD: return "IADD";
    case OP_ISUB: return "ISUB";
    case OP_IMUL: return "IMUL";
    case OP_IDIV: return "IDIV";
    case OP_IMOD: return "IMOD";
    case OP_INEG: return "INEG";
    case OP_FADD: return "FADD";
    case OP_FSUB: return "FSUB";
    case OP_FMUL: return "FMUL";
    case OP_FDIV: return "FDIV";
    case OP_FNEG: return "FNEG";
    case OP_EQ: return "EQ";
    case OP_LT: return "LT";
    case OP_LE: return "LE";
    case OP_NOT: return "NOT";
    case OP_JMP: return "JMP";
    case OP_JMPIF: return "JMPIF";
    case OP_JMPIFNOT: return "JMPIFNOT";
    case OP_JLT: return "JLT";
    case OP_JLE: return "JLE";
    case OP_JEQ: return "JEQ";
    case OP_JNLT: return "JNLT";
    case OP_JNLE: return "JNLE";
    case OP_JNEQ: return "JNEQ";
    case OP_CALL: return "CALL";
    case OP_CALLNATIVE: return "CALLNATIVE";
    case OP_TAILCALL: return "TAILCALL";
    case OP_RETURN: return "RETURN";
    case OP_NEWOBJ: return "NEWOBJ";
    case OP_NEWARRAY: return "NEWARRAY";
    case OP_GETFIELD: return "GETFIELD";
    case OP_SETFIELD: return "SETFIELD";
    case OP_GETINDEX: return "GETINDEX";
    case OP_SETINDEX: return "SETINDEX";
    case OP_DROP: return "DROP";
    case OP_BORROW: return "BORROW";
    case OP_BORROWMUT: return "BORROWMUT";
    case OP_ENDBORROW: return "ENDBORROW";
    case OP_COPYREF: return "COPYREF";
    case OP_NEWRC: return "NEWRC";
    case OP_RCCLONE: return "RCCLONE";
    case OP_RCDROP: return "RCDROP";
    case OP_FFICALL: return "FFICALL";
    case OP_LOOPHINT: return "LOOPHINT";
    case OP_SAFEPOINT: return "SAFEPOINT";
    case OP_TRAP: return "TRAP";
    default: return "UNKNOWN";
    }
}

KvmBytecode *kvm_bytecode_create(void) {
    KvmBytecode *bc = (KvmBytecode *)calloc(1, sizeof(KvmBytecode));
    if (!bc) return NULL;
    bc->magic = KVM_BYTECODE_MAGIC;
    bc->version = KVM_BYTECODE_VERSION;
    return bc;
}

KvmFunction *kvm_function_create(const char *name, uint16_t arity, uint16_t reg_count) {
    KvmFunction *fn = (KvmFunction *)calloc(1, sizeof(KvmFunction));
    if (!fn) return NULL;
    if (name) {
        fn->name = strdup(name);
    }
    fn->arity = arity;
    fn->reg_count = reg_count;
    return fn;
}

void kvm_function_destroy(KvmAllocator *alloc, KvmFunction *fn) {
    if (!fn) return;
    if (fn->name) free(fn->name);
    if (fn->const_pool) {
        for (size_t i = 0; i < fn->const_count; i++) {
            if (IS_POINTER(fn->const_pool[i])) {
                kvm_ownership_drop(alloc, VALUE_TO_HEAP_OBJ(fn->const_pool[i]));
            }
        }
        free(fn->const_pool);
    }
    if (fn->code) free(fn->code);
    if (fn->line_table) free(fn->line_table);
    if (fn->loop_counters) free(fn->loop_counters);
    free(fn);
}

void kvm_bytecode_destroy(KvmAllocator *alloc, KvmBytecode *bc) {
    if (!bc) return;
    if (bc->const_pool) {
        for (size_t i = 0; i < bc->const_count; i++) {
            if (IS_POINTER(bc->const_pool[i])) {
                kvm_ownership_drop(alloc, VALUE_TO_HEAP_OBJ(bc->const_pool[i]));
            }
        }
        free(bc->const_pool);
    }
    if (bc->functions) {
        for (size_t i = 0; i < bc->func_count; i++) {
            kvm_function_destroy(alloc, bc->functions[i]);
        }
        free(bc->functions);
    }
    if (bc->ffi_sigs) {
        for (size_t i = 0; i < bc->ffi_sig_count; i++) {
            if (bc->ffi_sigs[i].symbol_name) free(bc->ffi_sigs[i].symbol_name);
            if (bc->ffi_sigs[i].sig_str) free(bc->ffi_sigs[i].sig_str);
        }
        free(bc->ffi_sigs);
    }
    if (bc->type_descs) {
        for (size_t i = 0; i < bc->type_desc_count; i++) {
            if (bc->type_descs[i].name) free(bc->type_descs[i].name);
            if (bc->type_descs[i].field_names) {
                for (size_t j = 0; j < bc->type_descs[i].field_count; j++) {
                    if (bc->type_descs[i].field_names[j]) free(bc->type_descs[i].field_names[j]);
                }
                free(bc->type_descs[i].field_names);
            }
        }
        free(bc->type_descs);
    }
    free(bc);
}
