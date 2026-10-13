#include "kvm/jit.h"
#include "kvm/heap.h"
#include "kvm/ownership.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "mir.h"
#include "mir-gen.h"
#pragma GCC diagnostic pop

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct KvmJitContext {
    KvmVM *vm;
    MIR_context_t ctx;
};

static Value jit_helper_add(KvmVM *vm, Value v1, Value v2) {
    (void)vm;
    if (IS_INT48(v1) && IS_INT48(v2)) {
        return INT48_VAL(VALUE_TO_INT48(v1) + VALUE_TO_INT48(v2));
    }
    if (IS_DOUBLE(v1) && IS_DOUBLE(v2)) {
        return DOUBLE_VAL(VALUE_TO_DOUBLE(v1) + VALUE_TO_DOUBLE(v2));
    }
    return NIL_VAL;
}

static Value jit_helper_sub(KvmVM *vm, Value v1, Value v2) {
    (void)vm;
    if (IS_INT48(v1) && IS_INT48(v2)) {
        return INT48_VAL(VALUE_TO_INT48(v1) - VALUE_TO_INT48(v2));
    }
    if (IS_DOUBLE(v1) && IS_DOUBLE(v2)) {
        return DOUBLE_VAL(VALUE_TO_DOUBLE(v1) - VALUE_TO_DOUBLE(v2));
    }
    return NIL_VAL;
}

static Value jit_helper_mul(KvmVM *vm, Value v1, Value v2) {
    (void)vm;
    if (IS_INT48(v1) && IS_INT48(v2)) {
        return INT48_VAL(VALUE_TO_INT48(v1) * VALUE_TO_INT48(v2));
    }
    if (IS_DOUBLE(v1) && IS_DOUBLE(v2)) {
        return DOUBLE_VAL(VALUE_TO_DOUBLE(v1) * VALUE_TO_DOUBLE(v2));
    }
    return NIL_VAL;
}

static Value jit_helper_div(KvmVM *vm, Value v1, Value v2) {
    if (IS_INT48(v1) && IS_INT48(v2)) {
        int64_t d = VALUE_TO_INT48(v2);
        if (d == 0) {
            kvm_vm_set_error(vm, KVM_ERR_DIV_BY_ZERO, "Division by zero");
            return NIL_VAL;
        }
        return INT48_VAL(VALUE_TO_INT48(v1) / d);
    }
    if (IS_DOUBLE(v1) && IS_DOUBLE(v2)) {
        return DOUBLE_VAL(VALUE_TO_DOUBLE(v1) / VALUE_TO_DOUBLE(v2));
    }
    return NIL_VAL;
}

static Value jit_helper_mod(KvmVM *vm, Value v1, Value v2) {
    if (IS_INT48(v1) && IS_INT48(v2)) {
        int64_t d = VALUE_TO_INT48(v2);
        if (d == 0) {
            kvm_vm_set_error(vm, KVM_ERR_DIV_BY_ZERO, "Modulo by zero");
            return NIL_VAL;
        }
        return INT48_VAL(VALUE_TO_INT48(v1) % d);
    }
    return NIL_VAL;
}

static Value jit_helper_call(KvmVM *vm, Value func_val, Value *arg_regs) {
    if (IS_INT48(func_val)) {
        uint32_t fidx = (uint32_t)VALUE_TO_INT48(func_val);
        KvmBytecode *bc = kvm_vm_get_bytecode(vm);
        if (bc && fidx < bc->func_count) {
            KvmFunction *callee = bc->functions[fidx];
            Value res = NIL_VAL;
            kvm_vm_run_function(vm, callee, arg_regs, &res);
            return res;
        }
    }
    return NIL_VAL;
}

static Value jit_helper_drop(KvmVM *vm, Value val) {
    if (IS_POINTER(val)) {
        kvm_ownership_drop(kvm_vm_get_allocator(vm), VALUE_TO_HEAP_OBJ(val));
    }
    return NIL_VAL;
}

static Value jit_helper_move(KvmVM *vm, Value *src_ptr) {
    (void)vm;
    Value v = *src_ptr;
    *src_ptr = NIL_VAL;
    return v;
}

static Value jit_helper_trap(KvmVM *vm, int64_t pc) {
    kvm_vm_set_error(vm, KVM_ERR_VERIFIER_FAILURE, "Runtime trap at pc=%ld", (long)pc);
    return NIL_VAL;
}

static Value jit_helper_newarray(KvmVM *vm) {
    KvmArray *arr = kvm_array_create(kvm_vm_get_allocator(vm), 0);
    return HEAP_OBJ_TO_VALUE(arr);
}

static Value jit_helper_newobj(KvmVM *vm, int64_t type_idx) {
    KvmBytecode *bc = kvm_vm_get_bytecode(vm);
    if (bc && (size_t)type_idx < bc->type_desc_count) {
        KvmRecord *rec = kvm_record_create(kvm_vm_get_allocator(vm), (uint16_t)type_idx, bc->type_descs[type_idx].field_count);
        return HEAP_OBJ_TO_VALUE(rec);
    }
    return NIL_VAL;
}

static Value jit_helper_frame_exit(KvmVM *vm, int64_t reg_count, Value *regs, Value ret_val, int64_t ret_reg) {
    if (!vm || !regs) return ret_val;
    KvmAllocator *alloc = kvm_vm_get_allocator(vm);
    size_t count = reg_count > 0 ? (size_t)reg_count : 16;

    for (size_t i = count; i > 0; i--) {
        size_t idx = i - 1;
        if ((int64_t)idx == ret_reg) continue;
        Value v = regs[idx];
        if (IS_POINTER(v) && (!IS_POINTER(ret_val) || VALUE_TO_HEAP_OBJ(v) != VALUE_TO_HEAP_OBJ(ret_val))) {
            kvm_ownership_drop(alloc, VALUE_TO_HEAP_OBJ(v));
            regs[idx] = NIL_VAL;
            vm->frame_exit_sweep_count++;
        }
    }
    return ret_val;
}

KvmJitContext *kvm_jit_init(KvmVM *vm) {
    KvmJitContext *jctx = calloc(1, sizeof(KvmJitContext));
    if (!jctx) return NULL;
    jctx->vm = vm;
    jctx->ctx = MIR_init();
    MIR_gen_init(jctx->ctx);
    return jctx;
}

void kvm_jit_destroy(KvmJitContext *jctx) {
    if (!jctx) return;
    MIR_gen_finish(jctx->ctx);
    MIR_finish(jctx->ctx);
    free(jctx);
}

typedef Value (*JitFuncPtr)(KvmVM *vm, Value *regs);

Value kvm_jit_call(KvmFunction *fn, KvmVM *vm, Value *registers) {
    if (!fn || !fn->jit_code) return NIL_VAL;
    __extension__ JitFuncPtr fptr = (JitFuncPtr)(uintptr_t)fn->jit_code;
    return fptr(vm, registers);
}

bool kvm_jit_compile_function(KvmJitContext *jctx, KvmFunction *fn) {
    if (!jctx || !fn || fn->interp_only) return false;

    MIR_context_t ctx = jctx->ctx;
    MIR_module_t m = MIR_new_module(ctx, fn->name);

    MIR_type_t res_type = MIR_T_I64;

    char func_sym[256];
    snprintf(func_sym, sizeof(func_sym), "jit_func_%s_%p", fn->name, (void*)fn);
    MIR_item_t mir_func_item = MIR_new_func(ctx, func_sym, 1, &res_type, 2, MIR_T_I64, "vm", MIR_T_I64, "regs");
    MIR_func_t mir_func = MIR_get_item_func(ctx, mir_func_item);

    MIR_reg_t vm_reg = MIR_reg(ctx, "vm", mir_func);
    MIR_reg_t regs_reg = MIR_reg(ctx, "regs", mir_func);

    MIR_item_t proto_helper2    = MIR_new_proto(ctx, "proto_h2", 1, &res_type, 3, MIR_T_I64, "p1", MIR_T_I64, "v1", MIR_T_I64, "v2");
    MIR_item_t proto_helper1    = MIR_new_proto(ctx, "proto_h1", 1, &res_type, 2, MIR_T_I64, "p1", MIR_T_I64, "v1");
    MIR_item_t proto_call       = MIR_new_proto(ctx, "proto_call", 1, &res_type, 3, MIR_T_I64, "p1", MIR_T_I64, "v1", MIR_T_I64, "v2");
    MIR_item_t proto_newarray   = MIR_new_proto(ctx, "proto_newarray", 1, &res_type, 1, MIR_T_I64, "vm");
    MIR_item_t proto_frame_exit = MIR_new_proto(ctx, "proto_frame_exit", 1, &res_type, 5, MIR_T_I64, "vm", MIR_T_I64, "reg_count", MIR_T_I64, "regs", MIR_T_I64, "ret_val", MIR_T_I64, "ret_reg");

    MIR_item_t import_add        = MIR_new_import(ctx, "jit_helper_add");
    MIR_item_t import_sub        = MIR_new_import(ctx, "jit_helper_sub");
    MIR_item_t import_mul        = MIR_new_import(ctx, "jit_helper_mul");
    MIR_item_t import_div        = MIR_new_import(ctx, "jit_helper_div");
    MIR_item_t import_mod        = MIR_new_import(ctx, "jit_helper_mod");
    MIR_item_t import_call       = MIR_new_import(ctx, "jit_helper_call");
    MIR_item_t import_drop       = MIR_new_import(ctx, "jit_helper_drop");
    MIR_item_t import_move       = MIR_new_import(ctx, "jit_helper_move");
    MIR_item_t import_trap       = MIR_new_import(ctx, "jit_helper_trap");
    MIR_item_t import_newarray   = MIR_new_import(ctx, "jit_helper_newarray");
    MIR_item_t import_newobj     = MIR_new_import(ctx, "jit_helper_newobj");
    MIR_item_t import_frame_exit = MIR_new_import(ctx, "jit_helper_frame_exit");

    MIR_load_external(ctx, "jit_helper_add",        (void*)(uintptr_t)jit_helper_add);
    MIR_load_external(ctx, "jit_helper_sub",        (void*)(uintptr_t)jit_helper_sub);
    MIR_load_external(ctx, "jit_helper_mul",        (void*)(uintptr_t)jit_helper_mul);
    MIR_load_external(ctx, "jit_helper_div",        (void*)(uintptr_t)jit_helper_div);
    MIR_load_external(ctx, "jit_helper_mod",        (void*)(uintptr_t)jit_helper_mod);
    MIR_load_external(ctx, "jit_helper_call",       (void*)(uintptr_t)jit_helper_call);
    MIR_load_external(ctx, "jit_helper_drop",       (void*)(uintptr_t)jit_helper_drop);
    MIR_load_external(ctx, "jit_helper_move",       (void*)(uintptr_t)jit_helper_move);
    MIR_load_external(ctx, "jit_helper_trap",       (void*)(uintptr_t)jit_helper_trap);
    MIR_load_external(ctx, "jit_helper_newarray",   (void*)(uintptr_t)jit_helper_newarray);
    MIR_load_external(ctx, "jit_helper_newobj",     (void*)(uintptr_t)jit_helper_newobj);
    MIR_load_external(ctx, "jit_helper_frame_exit", (void*)(uintptr_t)jit_helper_frame_exit);

    MIR_reg_t saved_vm_reg = MIR_new_func_reg(ctx, mir_func, MIR_T_I64, "saved_vm");
    MIR_reg_t saved_regs_reg = MIR_new_func_reg(ctx, mir_func, MIR_T_I64, "saved_regs");
    MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, saved_vm_reg), MIR_new_reg_op(ctx, vm_reg)));
    MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_reg_op(ctx, regs_reg)));

    MIR_label_t *labels = calloc(fn->code_count, sizeof(MIR_label_t));
    for (size_t pc = 0; pc < fn->code_count; pc++) {
        labels[pc] = MIR_new_label(ctx);
    }

    MIR_reg_t r_val0 = MIR_new_func_reg(ctx, mir_func, MIR_T_I64, "r0");
    MIR_reg_t r_val1 = MIR_new_func_reg(ctx, mir_func, MIR_T_I64, "r1");
    MIR_reg_t r_res  = MIR_new_func_reg(ctx, mir_func, MIR_T_I64, "rres");
    MIR_reg_t r_addr = MIR_new_func_reg(ctx, mir_func, MIR_T_I64, "raddr");

    for (size_t pc = 0; pc < fn->code_count; pc++) {
        MIR_append_insn(ctx, mir_func_item, labels[pc]);
        KvmInstruction inst = fn->code[pc];
        KvmOpcode op = KVM_OPCODE(inst);
        uint8_t a = KVM_REG_A(inst);
        uint8_t b = KVM_REG_B(inst);
        uint8_t c = KVM_REG_C(inst);
        uint16_t imm = KVM_IMM16(inst);
        int16_t simm = KVM_SIMM16(inst);

        switch (op) {
            case OP_LOADK: {
                Value k = fn->const_pool[imm];
                int64_t addr_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, addr_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1), MIR_new_int_op(ctx, k)));
                break;
            }
            case OP_LOADI: {
                Value val = INT48_VAL((int64_t)simm);
                int64_t addr_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, addr_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1), MIR_new_int_op(ctx, val)));
                break;
            }
            case OP_LOADNIL: {
                int64_t addr_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, addr_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1), MIR_new_int_op(ctx, NIL_VAL)));
                break;
            }
            case OP_MOVE: {
                int64_t b_off = b * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, b_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_call_insn(ctx, 5, MIR_new_ref_op(ctx, proto_helper1), MIR_new_ref_op(ctx, import_move), MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, saved_vm_reg), MIR_new_reg_op(ctx, r_addr)));
                int64_t a_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, a_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1), MIR_new_reg_op(ctx, r_res)));
                break;
            }
            case OP_ADD: {
                int64_t b_off = b * sizeof(Value);
                int64_t c_off = c * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, b_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val0), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, c_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val1), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_call_insn(ctx, 6, MIR_new_ref_op(ctx, proto_helper2), MIR_new_ref_op(ctx, import_add), MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, saved_vm_reg), MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val1)));
                int64_t a_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, a_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1), MIR_new_reg_op(ctx, r_res)));
                break;
            }
            case OP_SUB:
            case OP_ISUB: {
                int64_t b_off = b * sizeof(Value);
                int64_t c_off = c * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, b_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val0), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, c_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val1), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_call_insn(ctx, 6, MIR_new_ref_op(ctx, proto_helper2), MIR_new_ref_op(ctx, import_sub), MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, saved_vm_reg), MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val1)));
                int64_t a_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, a_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1), MIR_new_reg_op(ctx, r_res)));
                break;
            }
            case OP_MUL:
            case OP_IMUL: {
                int64_t b_off = b * sizeof(Value);
                int64_t c_off = c * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, b_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val0), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, c_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val1), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_call_insn(ctx, 6, MIR_new_ref_op(ctx, proto_helper2), MIR_new_ref_op(ctx, import_mul), MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, saved_vm_reg), MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val1)));
                int64_t a_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, a_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1), MIR_new_reg_op(ctx, r_res)));
                break;
            }
            case OP_DIV:
            case OP_IDIV: {
                int64_t b_off = b * sizeof(Value);
                int64_t c_off = c * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, b_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val0), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, c_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val1), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_call_insn(ctx, 6, MIR_new_ref_op(ctx, proto_helper2), MIR_new_ref_op(ctx, import_div), MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, saved_vm_reg), MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val1)));
                int64_t a_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, a_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1), MIR_new_reg_op(ctx, r_res)));
                break;
            }
            case OP_MOD:
            case OP_IMOD: {
                int64_t b_off = b * sizeof(Value);
                int64_t c_off = c * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, b_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val0), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, c_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val1), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_call_insn(ctx, 6, MIR_new_ref_op(ctx, proto_helper2), MIR_new_ref_op(ctx, import_mod), MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, saved_vm_reg), MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val1)));
                int64_t a_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, a_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1), MIR_new_reg_op(ctx, r_res)));
                break;
            }
            case OP_IADD: {
                int64_t b_off = b * sizeof(Value);
                int64_t c_off = c * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, b_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val0), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, c_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val1), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));

                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_LSH, MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val0), MIR_new_int_op(ctx, 16)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_RSH, MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val0), MIR_new_int_op(ctx, 16)));

                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_LSH, MIR_new_reg_op(ctx, r_val1), MIR_new_reg_op(ctx, r_val1), MIR_new_int_op(ctx, 16)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_RSH, MIR_new_reg_op(ctx, r_val1), MIR_new_reg_op(ctx, r_val1), MIR_new_int_op(ctx, 16)));

                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val1)));

                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_LSH, MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, r_res), MIR_new_int_op(ctx, 16)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_URSH, MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, r_res), MIR_new_int_op(ctx, 16)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_OR, MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, r_res), MIR_new_int_op(ctx, (KVM_TAG_PREFIX | (KVM_TAG_INT48 << 48)))));

                int64_t a_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, a_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1), MIR_new_reg_op(ctx, r_res)));
                break;
            }
            case OP_CALL: {
                int64_t b_off = b * sizeof(Value);
                int64_t args_off = (b + 1) * sizeof(Value);

                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, b_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val0), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));

                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_val1), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, args_off)));

                MIR_append_insn(ctx, mir_func_item, MIR_new_call_insn(ctx, 6, MIR_new_ref_op(ctx, proto_call), MIR_new_ref_op(ctx, import_call), MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, saved_vm_reg), MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val1)));

                int64_t a_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, a_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1), MIR_new_reg_op(ctx, r_res)));
                break;
            }
            case OP_JMP: {
                size_t target_pc = pc + 1 + simm;
                if (target_pc < fn->code_count) {
                    MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_JMP, MIR_new_label_op(ctx, labels[target_pc])));
                }
                break;
            }
            case OP_JLE: {
                uint8_t cmp_a = KVM_CMP_REG_A(inst);
                uint8_t cmp_b = KVM_CMP_REG_B(inst);
                int16_t cmp_simm = KVM_CMP_SIMM16(inst);

                int64_t a_off = cmp_a * sizeof(Value);
                int64_t b_off = cmp_b * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, a_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val0), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, b_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val1), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));

                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_LSH, MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val0), MIR_new_int_op(ctx, 16)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_RSH, MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val0), MIR_new_int_op(ctx, 16)));

                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_LSH, MIR_new_reg_op(ctx, r_val1), MIR_new_reg_op(ctx, r_val1), MIR_new_int_op(ctx, 16)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_RSH, MIR_new_reg_op(ctx, r_val1), MIR_new_reg_op(ctx, r_val1), MIR_new_int_op(ctx, 16)));

                size_t target_pc = pc + 1 + cmp_simm;
                if (target_pc < fn->code_count) {
                    MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_BLE, MIR_new_label_op(ctx, labels[target_pc]), MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val1)));
                }
                break;
            }
            case OP_JLT: {
                uint8_t cmp_a = KVM_CMP_REG_A(inst);
                uint8_t cmp_b = KVM_CMP_REG_B(inst);
                int16_t cmp_simm = KVM_CMP_SIMM16(inst);

                int64_t a_off = cmp_a * sizeof(Value);
                int64_t b_off = cmp_b * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, a_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val0), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, b_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val1), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));

                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_LSH, MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val0), MIR_new_int_op(ctx, 16)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_RSH, MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val0), MIR_new_int_op(ctx, 16)));

                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_LSH, MIR_new_reg_op(ctx, r_val1), MIR_new_reg_op(ctx, r_val1), MIR_new_int_op(ctx, 16)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_RSH, MIR_new_reg_op(ctx, r_val1), MIR_new_reg_op(ctx, r_val1), MIR_new_int_op(ctx, 16)));

                size_t target_pc = pc + 1 + cmp_simm;
                if (target_pc < fn->code_count) {
                    MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_BLT, MIR_new_label_op(ctx, labels[target_pc]), MIR_new_reg_op(ctx, r_val0), MIR_new_reg_op(ctx, r_val1)));
                }
                break;
            }
            case OP_NEWARRAY: {
                MIR_append_insn(ctx, mir_func_item, MIR_new_call_insn(ctx, 4, MIR_new_ref_op(ctx, proto_newarray), MIR_new_ref_op(ctx, import_newarray), MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, saved_vm_reg)));
                int64_t a_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, a_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1), MIR_new_reg_op(ctx, r_res)));
                break;
            }
            case OP_NEWOBJ: {
                MIR_append_insn(ctx, mir_func_item, MIR_new_call_insn(ctx, 5, MIR_new_ref_op(ctx, proto_helper1), MIR_new_ref_op(ctx, import_newobj), MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, saved_vm_reg), MIR_new_int_op(ctx, (int64_t)imm)));
                int64_t a_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, a_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1), MIR_new_reg_op(ctx, r_res)));
                break;
            }
            case OP_RETURN: {
                int64_t a_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, a_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_res), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_call_insn(ctx, 8, MIR_new_ref_op(ctx, proto_frame_exit), MIR_new_ref_op(ctx, import_frame_exit), MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, saved_vm_reg), MIR_new_int_op(ctx, (int64_t)fn->reg_count), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_reg_op(ctx, r_res), MIR_new_int_op(ctx, (int64_t)a)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_ret_insn(ctx, 1, MIR_new_reg_op(ctx, r_res)));
                break;
            }
            case OP_DROP: {
                int64_t a_off = a * sizeof(Value);
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_ADD, MIR_new_reg_op(ctx, r_addr), MIR_new_reg_op(ctx, saved_regs_reg), MIR_new_int_op(ctx, a_off)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_reg_op(ctx, r_val0), MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_call_insn(ctx, 5, MIR_new_ref_op(ctx, proto_helper1), MIR_new_ref_op(ctx, import_drop), MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, saved_vm_reg), MIR_new_reg_op(ctx, r_val0)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_insn(ctx, MIR_MOV, MIR_new_mem_op(ctx, MIR_T_I64, 0, r_addr, 0, 1), MIR_new_int_op(ctx, NIL_VAL)));
                break;
            }
            case OP_TRAP: {
                MIR_append_insn(ctx, mir_func_item, MIR_new_call_insn(ctx, 5, MIR_new_ref_op(ctx, proto_helper1), MIR_new_ref_op(ctx, import_trap), MIR_new_reg_op(ctx, r_res), MIR_new_reg_op(ctx, saved_vm_reg), MIR_new_int_op(ctx, (int64_t)pc)));
                MIR_append_insn(ctx, mir_func_item, MIR_new_ret_insn(ctx, 1, MIR_new_int_op(ctx, NIL_VAL)));
                break;
            }
            default: {
                break;
            }
        }
    }

    MIR_finish_func(ctx);
    MIR_finish_module(ctx);

    MIR_load_module(ctx, m);
    MIR_link(ctx, MIR_set_gen_interface, NULL);

    void *code_ptr = MIR_gen(ctx, mir_func_item);
    free(labels);

    if (code_ptr) {
        fn->jit_code = code_ptr;
        return true;
    }

    fn->interp_only = true;
    return false;
}
