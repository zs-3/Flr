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

    size_t pc = 0;
    size_t code_count = fn->code_count;
    KvmInstruction *code = fn->code;

    fn->entry_count++;

    KvmBytecode *bc = (KvmBytecode*)kvm_vm_get_bytecode(vm);

    while (pc < code_count) {
        KvmInstruction inst = code[pc];
        KvmOpcode op = KVM_OPCODE(inst);
        uint8_t a = KVM_REG_A(inst);
        uint8_t b = KVM_REG_B(inst);
        uint8_t c = KVM_REG_C(inst);
        uint16_t imm = KVM_IMM16(inst);
        int16_t simm = KVM_SIMM16(inst);

        switch (op) {
            case OP_LOADK: {
                if (imm < fn->const_count) {
                    regs[a] = fn->const_pool[imm];
                }
                pc++;
                break;
            }
            case OP_LOADI: {
                regs[a] = INT48_VAL((int64_t)simm);
                pc++;
                break;
            }
            case OP_LOADNIL: {
                regs[a] = NIL_VAL;
                pc++;
                break;
            }
            case OP_LOADBOOL: {
                regs[a] = BOOL_VAL(b != 0);
                pc++;
                break;
            }
            case OP_MOVE: {
                regs[a] = kvm_ownership_move(&regs[b]);
                pc++;
                break;
            }
            case OP_ADD:
            case OP_IADD: {
                int64_t v1 = VALUE_TO_INT48(regs[b]);
                int64_t v2 = VALUE_TO_INT48(regs[c]);
                regs[a] = INT48_VAL(v1 + v2);
                pc++;
                break;
            }
            case OP_SUB:
            case OP_ISUB: {
                int64_t v1 = VALUE_TO_INT48(regs[b]);
                int64_t v2 = VALUE_TO_INT48(regs[c]);
                regs[a] = INT48_VAL(v1 - v2);
                pc++;
                break;
            }
            case OP_MUL:
            case OP_IMUL: {
                int64_t v1 = VALUE_TO_INT48(regs[b]);
                int64_t v2 = VALUE_TO_INT48(regs[c]);
                regs[a] = INT48_VAL(v1 * v2);
                pc++;
                break;
            }
            case OP_DIV:
            case OP_IDIV: {
                int64_t d = VALUE_TO_INT48(regs[c]);
                if (d == 0) {
                    kvm_vm_set_error(vm, "Division by zero");
                    free(regs);
                    return KVM_ERR_DIV_BY_ZERO;
                }
                regs[a] = INT48_VAL(VALUE_TO_INT48(regs[b]) / d);
                pc++;
                break;
            }
            case OP_MOD:
            case OP_IMOD: {
                int64_t d = VALUE_TO_INT48(regs[c]);
                if (d == 0) {
                    kvm_vm_set_error(vm, "Modulo by zero");
                    free(regs);
                    return KVM_ERR_DIV_BY_ZERO;
                }
                regs[a] = INT48_VAL(VALUE_TO_INT48(regs[b]) % d);
                pc++;
                break;
            }
            case OP_NEG:
            case OP_INEG: {
                regs[a] = INT48_VAL(-VALUE_TO_INT48(regs[b]));
                pc++;
                break;
            }
            case OP_FADD: {
                regs[a] = DOUBLE_VAL(VALUE_TO_DOUBLE(regs[b]) + VALUE_TO_DOUBLE(regs[c]));
                pc++;
                break;
            }
            case OP_FSUB: {
                regs[a] = DOUBLE_VAL(VALUE_TO_DOUBLE(regs[b]) - VALUE_TO_DOUBLE(regs[c]));
                pc++;
                break;
            }
            case OP_FMUL: {
                regs[a] = DOUBLE_VAL(VALUE_TO_DOUBLE(regs[b]) * VALUE_TO_DOUBLE(regs[c]));
                pc++;
                break;
            }
            case OP_FDIV: {
                regs[a] = DOUBLE_VAL(VALUE_TO_DOUBLE(regs[b]) / VALUE_TO_DOUBLE(regs[c]));
                pc++;
                break;
            }
            case OP_FNEG: {
                regs[a] = DOUBLE_VAL(-VALUE_TO_DOUBLE(regs[b]));
                pc++;
                break;
            }
            case OP_EQ: {
                regs[a] = BOOL_VAL(regs[b] == regs[c]);
                pc++;
                break;
            }
            case OP_LT: {
                if (IS_INT48(regs[b]) && IS_INT48(regs[c])) {
                    regs[a] = BOOL_VAL(VALUE_TO_INT48(regs[b]) < VALUE_TO_INT48(regs[c]));
                } else {
                    regs[a] = BOOL_VAL(VALUE_TO_DOUBLE(regs[b]) < VALUE_TO_DOUBLE(regs[c]));
                }
                pc++;
                break;
            }
            case OP_LE: {
                if (IS_INT48(regs[b]) && IS_INT48(regs[c])) {
                    regs[a] = BOOL_VAL(VALUE_TO_INT48(regs[b]) <= VALUE_TO_INT48(regs[c]));
                } else {
                    regs[a] = BOOL_VAL(VALUE_TO_DOUBLE(regs[b]) <= VALUE_TO_DOUBLE(regs[c]));
                }
                pc++;
                break;
            }
            case OP_NOT: {
                regs[a] = BOOL_VAL(IS_NIL(regs[b]) || (IS_BOOL(regs[b]) && !VALUE_TO_BOOL(regs[b])));
                pc++;
                break;
            }
            case OP_JMP: {
                pc = (size_t)((int64_t)pc + 1 + simm);
                break;
            }
            case OP_JMPIF: {
                bool cond = !IS_NIL(regs[a]) && (!IS_BOOL(regs[a]) || VALUE_TO_BOOL(regs[a]));
                if (cond) {
                    pc = (size_t)((int64_t)pc + 1 + simm);
                } else {
                    pc++;
                }
                break;
            }
            case OP_JMPIFNOT: {
                bool cond = IS_NIL(regs[a]) || (IS_BOOL(regs[a]) && !VALUE_TO_BOOL(regs[a]));
                if (cond) {
                    pc = (size_t)((int64_t)pc + 1 + simm);
                } else {
                    pc++;
                }
                break;
            }
            case OP_JLT: {
                int64_t v1 = VALUE_TO_INT48(regs[a]);
                int64_t v2 = VALUE_TO_INT48(regs[b]);
                if (v1 < v2) {
                    pc = (size_t)((int64_t)pc + 1 + simm);
                } else {
                    pc++;
                }
                break;
            }
            case OP_JLE: {
                int64_t v1 = VALUE_TO_INT48(regs[a]);
                int64_t v2 = VALUE_TO_INT48(regs[b]);
                if (v1 <= v2) {
                    pc = (size_t)((int64_t)pc + 1 + simm);
                } else {
                    pc++;
                }
                break;
            }
            case OP_JEQ: {
                if (regs[a] == regs[b]) {
                    pc = (size_t)((int64_t)pc + 1 + simm);
                } else {
                    pc++;
                }
                break;
            }
            case OP_CALL: {
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
                break;
            }
            case OP_RETURN: {
                if (out_result) *out_result = regs[a];
                for (size_t i = 0; i < reg_count; i++) {
                    if (IS_POINTER(regs[i])) {
                        kvm_ownership_drop(alloc, VALUE_TO_HEAP_OBJ(regs[i]));
                        regs[i] = NIL_VAL;
                    }
                }
                free(regs);
                return KVM_OK;
            }
            case OP_NEWOBJ: {
                if (bc && imm < bc->type_desc_count) {
                    KvmRecord *rec = kvm_record_create(alloc, imm, bc->type_descs[imm].field_count);
                    regs[a] = HEAP_OBJ_TO_VALUE(rec);
                }
                pc++;
                break;
            }
            case OP_NEWARRAY: {
                KvmArray *arr = kvm_array_create(alloc, 0);
                regs[a] = HEAP_OBJ_TO_VALUE(arr);
                pc++;
                break;
            }
            case OP_GETFIELD: {
                if (IS_POINTER(regs[b])) {
                    KvmRecord *rec = (KvmRecord *)VALUE_TO_HEAP_OBJ(regs[b]);
                    if (c < rec->field_count) {
                        regs[a] = rec->fields[c];
                    }
                }
                pc++;
                break;
            }
            case OP_SETFIELD: {
                if (IS_POINTER(regs[a])) {
                    KvmRecord *rec = (KvmRecord *)VALUE_TO_HEAP_OBJ(regs[a]);
                    if (b < rec->field_count) {
                        rec->fields[b] = kvm_ownership_move(&regs[c]);
                    }
                }
                pc++;
                break;
            }
            case OP_GETINDEX: {
                if (IS_POINTER(regs[b])) {
                    KvmArray *arr = (KvmArray *)VALUE_TO_HEAP_OBJ(regs[b]);
                    int64_t idx = VALUE_TO_INT48(regs[c]);
                    if (idx >= 0 && (size_t)idx < arr->length) {
                        regs[a] = arr->items[idx];
                    }
                }
                pc++;
                break;
            }
            case OP_SETINDEX: {
                if (IS_POINTER(regs[a])) {
                    KvmArray *arr = (KvmArray *)VALUE_TO_HEAP_OBJ(regs[a]);
                    int64_t idx = VALUE_TO_INT48(regs[b]);
                    if (idx >= 0) {
                        kvm_array_set(alloc, arr, (size_t)idx, kvm_ownership_move(&regs[c]));
                    }
                }
                pc++;
                break;
            }
            case OP_DROP: {
                kvm_ownership_drop(alloc, VALUE_TO_HEAP_OBJ(regs[a]));
                regs[a] = NIL_VAL;
                pc++;
                break;
            }
            case OP_BORROW: {
                regs[a] = kvm_ownership_borrow(regs[b], false);
                pc++;
                break;
            }
            case OP_BORROWMUT: {
                regs[a] = kvm_ownership_borrow(regs[b], true);
                pc++;
                break;
            }
            case OP_ENDBORROW: {
                regs[a] = NIL_VAL;
                pc++;
                break;
            }
            case OP_NEWRC: {
                KvmRcBox *rc = kvm_rcbox_create(alloc, kvm_ownership_move(&regs[b]));
                regs[a] = HEAP_OBJ_TO_VALUE(rc);
                pc++;
                break;
            }
            case OP_RCCLONE: {
                if (IS_POINTER(regs[b])) {
                    KvmRcBox *rc = (KvmRcBox *)VALUE_TO_HEAP_OBJ(regs[b]);
                    rc->refcount++;
                    regs[a] = regs[b];
                }
                pc++;
                break;
            }
            case OP_RCDROP: {
                if (IS_POINTER(regs[a])) {
                    KvmRcBox *rc = (KvmRcBox *)VALUE_TO_HEAP_OBJ(regs[a]);
                    if (--rc->refcount == 0) {
                        kvm_ownership_drop(alloc, (KvmHeapObject *)rc);
                    }
                    regs[a] = NIL_VAL;
                }
                pc++;
                break;
            }
            case OP_FFICALL: {
                if (bc && imm < bc->ffi_sig_count) {
                    KvmFfiSig *sig = &bc->ffi_sigs[imm];
                    Value res;
                    KvmStatus status = kvm_ffi_call(vm, sig->symbol_name, sig->sig_str, c, &regs[b], &res);
                    if (status != KVM_OK) {
                        free(regs);
                        return status;
                    }
                    regs[a] = res;
                }
                pc++;
                break;
            }
            case OP_LOOPHINT: {
                fn->loop_count++;
                pc++;
                break;
            }
            case OP_TRAP: {
                kvm_vm_set_error(vm, "Runtime trap at pc=%zu", pc);
                free(regs);
                return KVM_ERR_VERIFIER_FAILURE;
            }
            default:
                pc++;
                break;
        }
    }

    free(regs);
    return KVM_OK;
}
