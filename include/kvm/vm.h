#ifndef KVM_VM_H
#define KVM_VM_H

#include "kvm/value.h"
#include "kvm/allocator.h"
#include "kvm/bytecode.h"
#include "kvm/errors.h"
#include "kvm/ownership.h"
#include "kvm/heap.h"
#include "kvm/ffi.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct KvmJitContext KvmJitContext;

typedef struct KvmVMConfig {
    size_t initial_stack_size;
    bool enable_jit;
    uint32_t jit_threshold;
    uint32_t jit_loop_threshold;
    size_t code_cache_max_bytes;
} KvmVMConfig;

typedef struct KvmVMStats {
    KvmAllocStats allocator_stats;
    uint64_t frame_exit_sweep_count;
    uint64_t jit_compile_count;
    uint64_t deopt_count;
} KvmVMStats;

typedef struct KvmVM {
    KvmVMConfig config;
    KvmAllocator allocator;
    KvmBytecode *bytecode;
    char last_error[512];
    uint64_t frame_exit_sweep_count;
    uint64_t jit_compile_count;
    uint64_t deopt_count;

    Value *stack;
    size_t stack_capacity;
    size_t stack_top;

    KvmJitContext *jctx;
    KvmFfiTable ffi_table;
} KvmVM;

KvmVMConfig kvm_vm_default_config(void);
KvmVM *kvm_vm_create(const KvmVMConfig *config);
void kvm_vm_destroy(KvmVM *vm);

KvmStatus kvm_vm_load_bytecode(KvmVM *vm, const KvmBytecode *bc);
KvmBytecode *kvm_vm_get_bytecode(KvmVM *vm);
KvmStatus kvm_vm_run_entry(KvmVM *vm, Value *out_result);
KvmStatus kvm_vm_run_function(KvmVM *vm, KvmFunction *fn, Value *args, uint16_t arg_count, Value *out_result);

const char *kvm_vm_get_last_error(KvmVM *vm);
void kvm_vm_set_error(KvmVM *vm, const char *fmt, ...);
void kvm_vm_get_stats(const KvmVM *vm, KvmVMStats *stats);

KvmAllocator *kvm_vm_get_allocator(KvmVM *vm);

#endif /* KVM_VM_H */
