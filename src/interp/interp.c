#include "kvm/vm.h"
#include "kvm/heap.h"
#include "kvm/ownership.h"
#include "kvm/ffi.h"
#include "kvm/jit.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

extern KvmStatus kvm_interp_execute(KvmVM *vm, KvmFunction *fn, Value *args, uint16_t arg_count, Value *out_result);

KvmStatus kvm_vm_run_function(KvmVM *vm, KvmFunction *fn, Value *args, uint16_t arg_count, Value *out_result) {
    return kvm_interp_execute(vm, fn, args, arg_count, out_result);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

KvmStatus kvm_interp_execute(KvmVM *vm, KvmFunction *fn, Value *args, uint16_t arg_count, Value *out_result) {
    if (!vm || !fn) return KVM_ERR_INVALID_ARGUMENT;

    KvmAllocator *alloc = kvm_vm_get_allocator(vm);
    size_t reg_count = fn->reg_count > 0 ? fn->reg_count : 16;
    Value *regs = calloc(reg_count, sizeof(Value));
    if (!regs) return KVM_ERR_OUT_OF_MEMORY;

    for (size_t i = 0; i < reg_count; i++) {
        regs[i] = NIL_VAL;
    }

    for (uint16_t i = 0; i < arg_count && i < reg_count; i++) {
        regs[i] = args[i];
    }

    fn->entry_count++;

    /* Check JIT compilation threshold if JIT is enabled */
    if (vm->config.enable_jit && !fn->interp_only) {
        if (!fn->jit_code && fn->entry_count >= vm->config.jit_threshold) {
            if (!vm->jctx) {
                vm->jctx = kvm_jit_init(vm);
            }
            if (vm->jctx) {
                if (kvm_jit_compile_function(vm->jctx, fn)) {
                    vm->jit_compile_count++;
                }
            }
        }
        if (fn->jit_code) {
            Value jres = kvm_jit_call(fn, vm, regs);
            if (out_result) *out_result = jres;

            for (size_t i = 0; i < reg_count; i++) {
                if (IS_POINTER(regs[i]) && (!IS_POINTER(jres) || VALUE_TO_HEAP_OBJ(regs[i]) != VALUE_TO_HEAP_OBJ(jres))) {
                    kvm_ownership_drop(alloc, VALUE_TO_HEAP_OBJ(regs[i]));
                    regs[i] = NIL_VAL;
                }
            }
            free(regs);

            const char *err = kvm_vm_get_last_error(vm);
            if (err && err[0] != '\0') {
                if (strstr(err, "Division by zero")) return KVM_ERR_DIV_BY_ZERO;
                if (strstr(err, "trap") || strstr(err, "Trap")) return KVM_ERR_VERIFIER_FAILURE;
            }
            return KVM_OK;
        }
    }

    size_t pc = 0;
    size_t code_count = fn->code_count;
    KvmInstruction *code = fn->code;
    KvmBytecode *bc = (KvmBytecode*)kvm_vm_get_bytecode(vm);

#if (defined(__GNUC__) || defined(__clang__)) && !defined(KVM_NO_COMPUTED_GOTO)
    #define USE_COMPUTED_GOTO 1
#else
    #define USE_COMPUTED_GOTO 0
#endif

#if USE_COMPUTED_GOTO
    static const void *dispatch_table[OP_MAX_OPCODE] = {
        [0] = &&do_OP_LOADK,
        [OP_LOADK] = &&do_OP_LOADK,
        [OP_LOADI] = &&do_OP_LOADI,
        [OP_LOADNIL] = &&do_OP_LOADNIL,
        [OP_LOADBOOL] = &&do_OP_LOADBOOL,
        [OP_MOVE] = &&do_OP_MOVE,
        [OP_ADD] = &&do_OP_ADD,
        [OP_SUB] = &&do_OP_SUB,
        [OP_MUL] = &&do_OP_MUL,
        [OP_DIV] = &&do_OP_DIV,
        [OP_MOD] = &&do_OP_MOD,
        [OP_NEG] = &&do_OP_NEG,
        [OP_IADD] = &&do_OP_IADD,
        [OP_ISUB] = &&do_OP_ISUB,
        [OP_IMUL] = &&do_OP_IMUL,
        [OP_IDIV] = &&do_OP_IDIV,
        [OP_IMOD] = &&do_OP_IMOD,
        [OP_INEG] = &&do_OP_INEG,
        [OP_FADD] = &&do_OP_FADD,
        [OP_FSUB] = &&do_OP_FSUB,
        [OP_FMUL] = &&do_OP_FMUL,
        [OP_FDIV] = &&do_OP_FDIV,
        [OP_FNEG] = &&do_OP_FNEG,
        [OP_EQ] = &&do_OP_EQ,
        [OP_LT] = &&do_OP_LT,
        [OP_LE] = &&do_OP_LE,
        [OP_NOT] = &&do_OP_NOT,
        [OP_JMP] = &&do_OP_JMP,
        [OP_JMPIF] = &&do_OP_JMPIF,
        [OP_JMPIFNOT] = &&do_OP_JMPIFNOT,
        [OP_JLT] = &&do_OP_JLT,
        [OP_JLE] = &&do_OP_JLE,
        [OP_JEQ] = &&do_OP_JEQ,
        [OP_CALL] = &&do_OP_CALL,
        [OP_RETURN] = &&do_OP_RETURN,
        [OP_NEWOBJ] = &&do_OP_NEWOBJ,
        [OP_NEWARRAY] = &&do_OP_NEWARRAY,
        [OP_GETFIELD] = &&do_OP_GETFIELD,
        [OP_SETFIELD] = &&do_OP_SETFIELD,
        [OP_GETINDEX] = &&do_OP_GETINDEX,
        [OP_SETINDEX] = &&do_OP_SETINDEX,
        [OP_DROP] = &&do_OP_DROP,
        [OP_BORROW] = &&do_OP_BORROW,
        [OP_BORROWMUT] = &&do_OP_BORROWMUT,
        [OP_ENDBORROW] = &&do_OP_ENDBORROW,
        [OP_NEWRC] = &&do_OP_NEWRC,
        [OP_RCCLONE] = &&do_OP_RCCLONE,
        [OP_RCDROP] = &&do_OP_RCDROP,
        [OP_FFICALL] = &&do_OP_FFICALL,
        [OP_LOOPHINT] = &&do_OP_LOOPHINT,
        [OP_TRAP] = &&do_OP_TRAP,
    };

    #define DISPATCH() do { \
        if (pc >= code_count) goto do_end; \
        KvmInstruction inst_ = code[pc]; \
        KvmOpcode op_ = KVM_OPCODE(inst_); \
        if (op_ >= OP_MAX_OPCODE || !dispatch_table[op_]) goto do_next; \
        goto *dispatch_table[op_]; \
    } while (0)

    DISPATCH();

#else
    #define DISPATCH() break
    while (pc < code_count) {
        KvmInstruction inst = code[pc];
        KvmOpcode op = KVM_OPCODE(inst);
        switch (op) {
#endif

#if USE_COMPUTED_GOTO
do_OP_LOADK: {
#else
case OP_LOADK: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint16_t imm = KVM_IMM16(inst);
    if (imm < fn->const_count) {
        regs[a] = fn->const_pool[imm];
    }
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_LOADI: {
#else
case OP_LOADI: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    int16_t simm = KVM_SIMM16(inst);
    regs[a] = INT48_VAL((int64_t)simm);
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_LOADNIL: {
#else
case OP_LOADNIL: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    regs[a] = NIL_VAL;
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_LOADBOOL: {
#else
case OP_LOADBOOL: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    regs[a] = BOOL_VAL(b != 0);
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_MOVE: {
#else
case OP_MOVE: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    regs[a] = kvm_ownership_move(&regs[b]);
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_ADD:
do_OP_IADD: {
#else
case OP_ADD:
case OP_IADD: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    int64_t v1 = VALUE_TO_INT48(regs[b]);
    int64_t v2 = VALUE_TO_INT48(regs[c]);
    regs[a] = INT48_VAL(v1 + v2);
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_SUB:
do_OP_ISUB: {
#else
case OP_SUB:
case OP_ISUB: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    int64_t v1 = VALUE_TO_INT48(regs[b]);
    int64_t v2 = VALUE_TO_INT48(regs[c]);
    regs[a] = INT48_VAL(v1 - v2);
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_MUL:
do_OP_IMUL: {
#else
case OP_MUL:
case OP_IMUL: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    int64_t v1 = VALUE_TO_INT48(regs[b]);
    int64_t v2 = VALUE_TO_INT48(regs[c]);
    regs[a] = INT48_VAL(v1 * v2);
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_DIV:
do_OP_IDIV: {
#else
case OP_DIV:
case OP_IDIV: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    int64_t d = VALUE_TO_INT48(regs[c]);
    if (d == 0) {
        kvm_vm_set_error(vm, "Division by zero");
        free(regs);
        return KVM_ERR_DIV_BY_ZERO;
    }
    regs[a] = INT48_VAL(VALUE_TO_INT48(regs[b]) / d);
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_MOD:
do_OP_IMOD: {
#else
case OP_MOD:
case OP_IMOD: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    int64_t d = VALUE_TO_INT48(regs[c]);
    if (d == 0) {
        kvm_vm_set_error(vm, "Modulo by zero");
        free(regs);
        return KVM_ERR_DIV_BY_ZERO;
    }
    regs[a] = INT48_VAL(VALUE_TO_INT48(regs[b]) % d);
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_NEG:
do_OP_INEG: {
#else
case OP_NEG:
case OP_INEG: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    regs[a] = INT48_VAL(-VALUE_TO_INT48(regs[b]));
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_FADD: {
#else
case OP_FADD: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    regs[a] = DOUBLE_VAL(VALUE_TO_DOUBLE(regs[b]) + VALUE_TO_DOUBLE(regs[c]));
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_FSUB: {
#else
case OP_FSUB: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    regs[a] = DOUBLE_VAL(VALUE_TO_DOUBLE(regs[b]) - VALUE_TO_DOUBLE(regs[c]));
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_FMUL: {
#else
case OP_FMUL: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    regs[a] = DOUBLE_VAL(VALUE_TO_DOUBLE(regs[b]) * VALUE_TO_DOUBLE(regs[c]));
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_FDIV: {
#else
case OP_FDIV: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    regs[a] = DOUBLE_VAL(VALUE_TO_DOUBLE(regs[b]) / VALUE_TO_DOUBLE(regs[c]));
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_FNEG: {
#else
case OP_FNEG: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    regs[a] = DOUBLE_VAL(-VALUE_TO_DOUBLE(regs[b]));
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_EQ: {
#else
case OP_EQ: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    regs[a] = BOOL_VAL(regs[b] == regs[c]);
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_LT: {
#else
case OP_LT: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    if (IS_INT48(regs[b]) && IS_INT48(regs[c])) {
        regs[a] = BOOL_VAL(VALUE_TO_INT48(regs[b]) < VALUE_TO_INT48(regs[c]));
    } else {
        regs[a] = BOOL_VAL(VALUE_TO_DOUBLE(regs[b]) < VALUE_TO_DOUBLE(regs[c]));
    }
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_LE: {
#else
case OP_LE: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    if (IS_INT48(regs[b]) && IS_INT48(regs[c])) {
        regs[a] = BOOL_VAL(VALUE_TO_INT48(regs[b]) <= VALUE_TO_INT48(regs[c]));
    } else {
        regs[a] = BOOL_VAL(VALUE_TO_DOUBLE(regs[b]) <= VALUE_TO_DOUBLE(regs[c]));
    }
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_NOT: {
#else
case OP_NOT: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    regs[a] = BOOL_VAL(IS_NIL(regs[b]) || (IS_BOOL(regs[b]) && !VALUE_TO_BOOL(regs[b])));
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_JMP: {
#else
case OP_JMP: {
#endif
    KvmInstruction inst = code[pc];
    int16_t simm = KVM_SIMM16(inst);
    pc = (size_t)((int64_t)pc + 1 + simm);
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_JMPIF: {
#else
case OP_JMPIF: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    int16_t simm = KVM_SIMM16(inst);
    bool cond = !IS_NIL(regs[a]) && (!IS_BOOL(regs[a]) || VALUE_TO_BOOL(regs[a]));
    if (cond) {
        pc = (size_t)((int64_t)pc + 1 + simm);
    } else {
        pc++;
    }
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_JMPIFNOT: {
#else
case OP_JMPIFNOT: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    int16_t simm = KVM_SIMM16(inst);
    bool cond = IS_NIL(regs[a]) || (IS_BOOL(regs[a]) && !VALUE_TO_BOOL(regs[a]));
    if (cond) {
        pc = (size_t)((int64_t)pc + 1 + simm);
    } else {
        pc++;
    }
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_JLT: {
#else
case OP_JLT: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t cmp_a = KVM_CMP_REG_A(inst);
    uint8_t cmp_b = KVM_CMP_REG_B(inst);
    int16_t cmp_simm = KVM_CMP_SIMM16(inst);
    int64_t v1 = VALUE_TO_INT48(regs[cmp_a]);
    int64_t v2 = VALUE_TO_INT48(regs[cmp_b]);
    if (v1 < v2) {
        pc = (size_t)((int64_t)pc + 1 + cmp_simm);
    } else {
        pc++;
    }
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_JLE: {
#else
case OP_JLE: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t cmp_a = KVM_CMP_REG_A(inst);
    uint8_t cmp_b = KVM_CMP_REG_B(inst);
    int16_t cmp_simm = KVM_CMP_SIMM16(inst);
    int64_t v1 = VALUE_TO_INT48(regs[cmp_a]);
    int64_t v2 = VALUE_TO_INT48(regs[cmp_b]);
    if (v1 <= v2) {
        pc = (size_t)((int64_t)pc + 1 + cmp_simm);
    } else {
        pc++;
    }
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_JEQ: {
#else
case OP_JEQ: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t cmp_a = KVM_CMP_REG_A(inst);
    uint8_t cmp_b = KVM_CMP_REG_B(inst);
    int16_t cmp_simm = KVM_CMP_SIMM16(inst);
    if (regs[cmp_a] == regs[cmp_b]) {
        pc = (size_t)((int64_t)pc + 1 + cmp_simm);
    } else {
        pc++;
    }
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_CALL: {
#else
case OP_CALL: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    Value func_val = regs[b];
    if (IS_INT48(func_val)) {
        uint32_t fidx = (uint32_t)VALUE_TO_INT48(func_val);
        if (bc && fidx < bc->func_count) {
            KvmFunction *callee = bc->functions[fidx];
            Value res;
            KvmStatus status = kvm_vm_run_function(vm, callee, &regs[b + 1], c, &res);
            if (status != KVM_OK) {
                free(regs);
                return status;
            }
            regs[a] = res;
        }
    }
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_RETURN: {
#else
case OP_RETURN: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    Value ret_val = regs[a];
    if (out_result) *out_result = ret_val;

    for (size_t i = 0; i < reg_count; i++) {
        if (i != a && IS_POINTER(regs[i]) && (!IS_POINTER(ret_val) || VALUE_TO_HEAP_OBJ(regs[i]) != VALUE_TO_HEAP_OBJ(ret_val))) {
            kvm_ownership_drop(alloc, VALUE_TO_HEAP_OBJ(regs[i]));
            regs[i] = NIL_VAL;
        }
    }
    free(regs);
    return KVM_OK;
}

#if USE_COMPUTED_GOTO
do_OP_NEWOBJ: {
#else
case OP_NEWOBJ: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint16_t imm = KVM_IMM16(inst);
    if (bc && imm < bc->type_desc_count) {
        KvmRecord *rec = kvm_record_create(alloc, imm, bc->type_descs[imm].field_count);
        regs[a] = HEAP_OBJ_TO_VALUE(rec);
    }
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_NEWARRAY: {
#else
case OP_NEWARRAY: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    KvmArray *arr = kvm_array_create(alloc, 0);
    regs[a] = HEAP_OBJ_TO_VALUE(arr);
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_GETFIELD: {
#else
case OP_GETFIELD: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    if (IS_POINTER(regs[b])) {
        KvmRecord *rec = (KvmRecord *)VALUE_TO_HEAP_OBJ(regs[b]);
        if (c < rec->field_count) {
            regs[a] = rec->fields[c];
        }
    }
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_SETFIELD: {
#else
case OP_SETFIELD: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    if (IS_POINTER(regs[a])) {
        KvmRecord *rec = (KvmRecord *)VALUE_TO_HEAP_OBJ(regs[a]);
        if (b < rec->field_count) {
            rec->fields[b] = kvm_ownership_move(&regs[c]);
        }
    }
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_GETINDEX: {
#else
case OP_GETINDEX: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    if (IS_POINTER(regs[b])) {
        KvmArray *arr = (KvmArray *)VALUE_TO_HEAP_OBJ(regs[b]);
        int64_t idx = VALUE_TO_INT48(regs[c]);
        if (idx >= 0 && (size_t)idx < arr->length) {
            regs[a] = arr->items[idx];
        }
    }
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_SETINDEX: {
#else
case OP_SETINDEX: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t c = KVM_REG_C(inst);
    if (IS_POINTER(regs[a])) {
        KvmArray *arr = (KvmArray *)VALUE_TO_HEAP_OBJ(regs[a]);
        int64_t idx = VALUE_TO_INT48(regs[b]);
        if (idx >= 0) {
            kvm_array_set(alloc, arr, (size_t)idx, kvm_ownership_move(&regs[c]));
        }
    }
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_DROP: {
#else
case OP_DROP: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    kvm_ownership_drop(alloc, VALUE_TO_HEAP_OBJ(regs[a]));
    regs[a] = NIL_VAL;
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_BORROW: {
#else
case OP_BORROW: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    regs[a] = kvm_ownership_borrow(regs[b], false);
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_BORROWMUT: {
#else
case OP_BORROWMUT: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    regs[a] = kvm_ownership_borrow(regs[b], true);
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_ENDBORROW: {
#else
case OP_ENDBORROW: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    regs[a] = NIL_VAL;
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_NEWRC: {
#else
case OP_NEWRC: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    KvmRcBox *rc = kvm_rcbox_create(alloc, kvm_ownership_move(&regs[b]));
    regs[a] = HEAP_OBJ_TO_VALUE(rc);
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_RCCLONE: {
#else
case OP_RCCLONE: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    if (IS_POINTER(regs[b])) {
        KvmRcBox *rc = (KvmRcBox *)VALUE_TO_HEAP_OBJ(regs[b]);
        rc->refcount++;
        regs[a] = regs[b];
    }
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_RCDROP: {
#else
case OP_RCDROP: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    if (IS_POINTER(regs[a])) {
        KvmRcBox *rc = (KvmRcBox *)VALUE_TO_HEAP_OBJ(regs[a]);
        if (--rc->refcount == 0) {
            kvm_ownership_drop(alloc, (KvmHeapObject *)rc);
        }
        regs[a] = NIL_VAL;
    }
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_FFICALL: {
#else
case OP_FFICALL: {
#endif
    KvmInstruction inst = code[pc];
    uint8_t a = KVM_REG_A(inst);
    uint8_t b = KVM_REG_B(inst);
    uint8_t sig_idx = KVM_REG_C(inst);
    if (bc && sig_idx < bc->ffi_sig_count) {
        KvmFfiSig *sig = &bc->ffi_sigs[sig_idx];
        Value res;
        KvmStatus status = kvm_ffi_call(vm, sig->symbol_name, sig->sig_str, 1, &regs[b], &res);
        if (status != KVM_OK) {
            free(regs);
            return status;
        }
        regs[a] = res;
    }
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_LOOPHINT: {
#else
case OP_LOOPHINT: {
#endif
    fn->loop_count++;
    pc++;
    DISPATCH();
}

#if USE_COMPUTED_GOTO
do_OP_TRAP: {
#else
case OP_TRAP: {
#endif
    kvm_vm_set_error(vm, "Runtime trap at pc=%zu", pc);
    free(regs);
    return KVM_ERR_VERIFIER_FAILURE;
}

#if USE_COMPUTED_GOTO
do_next:
    pc++;
    DISPATCH();

do_end:
    free(regs);
    return KVM_OK;
#else
default:
    pc++;
    break;
}
}
free(regs);
return KVM_OK;
#endif
}

#pragma GCC diagnostic pop
