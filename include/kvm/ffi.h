#ifndef KVM_FFI_H
#define KVM_FFI_H

#include "kvm/value.h"
#include "kvm/bytecode.h"
#include "kvm/errors.h"

typedef struct KvmVM KvmVM;

typedef Value (*KvmNativeFn)(KvmVM *vm, int arg_count, Value *args);

typedef struct KvmNativeBinding {
    char *name;
    KvmNativeFn fnptr;
    char *signature;
} KvmNativeBinding;

typedef struct KvmFfiTable {
    size_t count;
    size_t capacity;
    KvmNativeBinding *bindings;
    void **dl_handles;
    size_t dl_count;
    size_t dl_capacity;
} KvmFfiTable;

void kvm_ffi_table_init(KvmFfiTable *table);
void kvm_ffi_table_destroy(KvmFfiTable *table);

KvmStatus kvm_register_native(KvmVM *vm, const char *name, KvmNativeFn fnptr, const char *signature);
KvmStatus kvm_load_library(KvmVM *vm, const char *path);
KvmNativeFn kvm_ffi_lookup(KvmVM *vm, const char *name, const char *signature);

KvmStatus kvm_ffi_call(KvmVM *vm, const char *symbol_name, const char *signature, int arg_count, Value *args, Value *out_result);

#endif /* KVM_FFI_H */
