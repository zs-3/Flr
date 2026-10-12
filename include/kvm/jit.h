#ifndef KVM_JIT_H
#define KVM_JIT_H

#include "kvm/value.h"
#include "kvm/bytecode.h"
#include "kvm/vm.h"

typedef struct KvmJitContext KvmJitContext;

KvmJitContext *kvm_jit_init(KvmVM *vm);
void kvm_jit_destroy(KvmJitContext *ctx);

bool kvm_jit_compile_function(KvmJitContext *ctx, KvmFunction *fn);
Value kvm_jit_call(KvmFunction *fn, KvmVM *vm, Value *registers);

#endif /* KVM_JIT_H */
