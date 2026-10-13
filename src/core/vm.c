#include "kvm/vm.h"
#include "kvm/heap.h"
#include "kvm/ffi.h"
#include "kvm/jit.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

KvmVMConfig kvm_vm_default_config(void) {
    KvmVMConfig config;
    config.initial_stack_size = 65536; // 64K value slots
    config.enable_jit = true;
    config.jit_threshold = 1000;
    config.jit_loop_threshold = 500;
    config.code_cache_max_bytes = 64 * 1024 * 1024;

    const char *env_jit = getenv("KVM_JIT");
    if (env_jit && strcmp(env_jit, "off") == 0) {
        config.enable_jit = false;
    }
    const char *env_thresh = getenv("KVM_JIT_THRESHOLD");
    if (env_thresh) {
        config.jit_threshold = (uint32_t)atoi(env_thresh);
    }

    return config;
}

KvmVM *kvm_vm_create(const KvmVMConfig *config) {
    KvmVMConfig cfg = config ? *config : kvm_vm_default_config();
    KvmVM *vm = calloc(1, sizeof(KvmVM));
    if (!vm) return NULL;

    vm->config = cfg;
    vm->last_status = KVM_OK;
    kvm_allocator_init(&vm->allocator);
    kvm_ffi_table_init(&vm->ffi_table);

    vm->stack_capacity = cfg.initial_stack_size;
    vm->stack = calloc(vm->stack_capacity, sizeof(Value));
    if (!vm->stack) {
        kvm_allocator_destroy(&vm->allocator);
        free(vm);
        return NULL;
    }
    vm->stack_top = 0;

    return vm;
}

void kvm_vm_destroy(KvmVM *vm) {
    if (!vm) return;
    if (vm->jctx) {
        kvm_jit_destroy(vm->jctx);
        vm->jctx = NULL;
    }
    kvm_ffi_table_destroy(&vm->ffi_table);
    if (vm->stack) free(vm->stack);
    kvm_allocator_destroy(&vm->allocator);
    free(vm);
}

Value *kvm_vm_reserve_stack(KvmVM *vm, size_t needed) {
    if (vm->stack_top + needed > vm->stack_capacity) {
        size_t new_cap = vm->stack_capacity * 2;
        while (vm->stack_top + needed > new_cap) {
            new_cap *= 2;
        }
        Value *new_stack = realloc(vm->stack, new_cap * sizeof(Value));
        if (!new_stack) return NULL;
        memset(new_stack + vm->stack_capacity, 0, (new_cap - vm->stack_capacity) * sizeof(Value));
        vm->stack = new_stack;
        vm->stack_capacity = new_cap;
    }
    return &vm->stack[vm->stack_top];
}

KvmStatus kvm_vm_load_bytecode(KvmVM *vm, const KvmBytecode *bc) {
    if (!vm || !bc) return KVM_ERR_INVALID_ARGUMENT;
    vm->bytecode = (KvmBytecode *)bc;
    /* Run validator to ensure return_mask and static validation are populated */
    char err[256];
    KvmStatus status = kvm_bytecode_validate(bc, err, sizeof(err));
    if (status != KVM_OK) {
        kvm_vm_set_error(vm, status, "%s", err);
        return status;
    }
    return KVM_OK;
}

const char *kvm_vm_get_last_error(KvmVM *vm) {
    return vm ? vm->last_error : "Null VM handle";
}

void kvm_vm_set_error(KvmVM *vm, KvmStatus status, const char *fmt, ...) {
    if (!vm) return;
    vm->last_status = status;
    if (fmt) {
        va_list args;
        va_start(args, fmt);
        vsnprintf(vm->last_error, sizeof(vm->last_error), fmt, args);
        va_end(args);
    }
}

void kvm_vm_get_stats(const KvmVM *vm, KvmVMStats *stats) {
    if (!vm || !stats) return;
    stats->allocator_stats = kvm_allocator_get_stats(&vm->allocator);
    stats->frame_exit_sweep_count = vm->frame_exit_sweep_count;
    stats->jit_compile_count = vm->jit_compile_count;
    stats->deopt_count = vm->deopt_count;
}

KvmAllocator *kvm_vm_get_allocator(KvmVM *vm) {
    return vm ? &vm->allocator : NULL;
}

KvmBytecode *kvm_vm_get_bytecode(KvmVM *vm) {
    return vm ? vm->bytecode : NULL;
}

KvmStatus kvm_vm_run_entry(KvmVM *vm, Value *out_result) {
    if (!vm || !vm->bytecode) return KVM_ERR_INVALID_ARGUMENT;
    if (vm->bytecode->entry_func_idx >= vm->bytecode->func_count) {
        kvm_vm_set_error(vm, KVM_ERR_CORRUPT_BYTECODE, "Entry function index out of bounds");
        return KVM_ERR_CORRUPT_BYTECODE;
    }

    KvmFunction *fn = vm->bytecode->functions[vm->bytecode->entry_func_idx];
    vm->stack_top = 0;
    Value *entry_regs = kvm_vm_reserve_stack(vm, fn->reg_count > 0 ? fn->reg_count : 16);
    if (!entry_regs) return KVM_ERR_OUT_OF_MEMORY;

    return kvm_vm_run_function(vm, fn, entry_regs, out_result);
}
