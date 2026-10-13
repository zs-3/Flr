#include "kvm/ffi.h"
#include "kvm/vm.h"
#include "kvm/heap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <math.h>

void kvm_ffi_table_init(KvmFfiTable *table) {
    if (!table) return;
    memset(table, 0, sizeof(KvmFfiTable));
}

void kvm_ffi_table_destroy(KvmFfiTable *table) {
    if (!table) return;
    for (size_t i = 0; i < table->count; i++) {
        if (table->bindings[i].name) free(table->bindings[i].name);
        if (table->bindings[i].signature) free(table->bindings[i].signature);
    }
    if (table->bindings) free(table->bindings);

    for (size_t i = 0; i < table->dl_count; i++) {
        if (table->dl_handles[i]) dlclose(table->dl_handles[i]);
    }
    if (table->dl_handles) free(table->dl_handles);

    memset(table, 0, sizeof(KvmFfiTable));
}

// Built-in Libc functions wrapper helpers
static Value native_strlen(KvmVM *vm, int arg_count, Value *args) {
    (void)vm;
    if (arg_count < 1) return INT48_VAL(0);
    Value str_val = args[0];
    if (IS_POINTER(str_val)) {
        KvmHeapObject *obj = VALUE_TO_HEAP_OBJ(str_val);
        if (obj->header.kind == KVM_KIND_STRING) {
            KvmString *str = (KvmString *)obj;
            return INT48_VAL((int64_t)str->length);
        }
    }
    return INT48_VAL(0);
}

static Value native_sqrt(KvmVM *vm, int arg_count, Value *args) {
    (void)vm;
    if (arg_count < 1) return DOUBLE_VAL(0.0);
    double val = VALUE_TO_DOUBLE(args[0]);
    return DOUBLE_VAL(sqrt(val));
}

static Value native_abs(KvmVM *vm, int arg_count, Value *args) {
    (void)vm;
    if (arg_count < 1) return INT48_VAL(0);
    int64_t val = VALUE_TO_INT48(args[0]);
    return INT48_VAL(val < 0 ? -val : val);
}

KvmStatus kvm_register_native(KvmVM *vm, const char *name, KvmNativeFn fnptr, const char *signature) {
    if (!vm || !name || !fnptr || !signature) return KVM_ERR_INVALID_ARGUMENT;
    KvmFfiTable *t = &vm->ffi_table;
    if (t->count >= t->capacity) {
        size_t new_cap = t->capacity == 0 ? 16 : t->capacity * 2;
        KvmNativeBinding *new_b = (KvmNativeBinding *)realloc(t->bindings, new_cap * sizeof(KvmNativeBinding));
        if (!new_b) return KVM_ERR_OUT_OF_MEMORY;
        t->bindings = new_b;
        t->capacity = new_cap;
    }
    t->bindings[t->count].name = strdup(name);
    t->bindings[t->count].fnptr = fnptr;
    t->bindings[t->count].signature = strdup(signature);
    t->count++;
    return KVM_OK;
}

KvmStatus kvm_load_library(KvmVM *vm, const char *path) {
    if (!vm || !path) return KVM_ERR_INVALID_ARGUMENT;
    void *handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        kvm_vm_set_error(vm, KVM_ERR_FFI_SYMBOL_NOT_FOUND, "Failed to load library '%s': %s", path, dlerror());
        return KVM_ERR_FFI_SYMBOL_NOT_FOUND;
    }
    KvmFfiTable *t = &vm->ffi_table;
    if (t->dl_count >= t->dl_capacity) {
        size_t new_cap = t->dl_capacity == 0 ? 8 : t->dl_capacity * 2;
        void **new_handles = (void **)realloc(t->dl_handles, new_cap * sizeof(void *));
        if (!new_handles) {
            dlclose(handle);
            return KVM_ERR_OUT_OF_MEMORY;
        }
        t->dl_handles = new_handles;
        t->dl_capacity = new_cap;
    }
    t->dl_handles[t->dl_count++] = handle;
    return KVM_OK;
}

KvmNativeFn kvm_ffi_lookup(KvmVM *vm, const char *name, const char *signature) {
    if (!vm || !name) return NULL;
    KvmFfiTable *t = &vm->ffi_table;
    for (size_t i = 0; i < t->count; i++) {
        if (strcmp(t->bindings[i].name, name) == 0) {
            if (!signature || strcmp(t->bindings[i].signature, signature) == 0) {
                return t->bindings[i].fnptr;
            }
        }
    }
    return NULL;
}

KvmStatus kvm_ffi_call(KvmVM *vm, const char *symbol_name, const char *signature, int arg_count, Value *args, Value *out_result) {
    if (!vm || !symbol_name) return KVM_ERR_INVALID_ARGUMENT;

    // Check custom registered native bindings first
    KvmNativeFn registered_fn = kvm_ffi_lookup(vm, symbol_name, signature);
    if (registered_fn) {
        Value res = registered_fn(vm, arg_count, args);
        if (out_result) *out_result = res;
        return KVM_OK;
    }

    // Built-in standard functions
    if (strcmp(symbol_name, "strlen") == 0) {
        Value res = native_strlen(vm, arg_count, args);
        if (out_result) *out_result = res;
        return KVM_OK;
    } else if (strcmp(symbol_name, "sqrt") == 0) {
        Value res = native_sqrt(vm, arg_count, args);
        if (out_result) *out_result = res;
        return KVM_OK;
    } else if (strcmp(symbol_name, "abs") == 0) {
        Value res = native_abs(vm, arg_count, args);
        if (out_result) *out_result = res;
        return KVM_OK;
    }

    // Lookup symbol via dlsym across default process / loaded dynamic libraries
    void *sym = dlsym(RTLD_DEFAULT, symbol_name);
    if (!sym) {
        KvmFfiTable *t = &vm->ffi_table;
        for (size_t i = 0; i < t->dl_count && !sym; i++) {
            sym = dlsym(t->dl_handles[i], symbol_name);
        }
    }

    if (!sym) {
        kvm_vm_set_error(vm, KVM_ERR_FFI_SYMBOL_NOT_FOUND, "FFI symbol '%s' not found", symbol_name);
        return KVM_ERR_FFI_SYMBOL_NOT_FOUND;
    }

    // Marshalling based on argument count and symbol types
    if (arg_count == 0) {
        __extension__ int64_t (*fn0)(void) = (int64_t (*)(void))(uintptr_t)sym;
        int64_t ret = fn0();
        if (out_result) *out_result = INT48_VAL(ret);
        return KVM_OK;
    } else if (arg_count == 1) {
        int64_t arg0 = 0;
        if (IS_INT48(args[0])) {
            arg0 = VALUE_TO_INT48(args[0]);
        } else if (IS_POINTER(args[0])) {
            KvmHeapObject *obj = VALUE_TO_HEAP_OBJ(args[0]);
            if (obj->header.kind == KVM_KIND_STRING) {
                arg0 = (intptr_t)((KvmString *)obj)->data;
            } else {
                arg0 = (intptr_t)obj;
            }
        }
        __extension__ int64_t (*fn1)(int64_t) = (int64_t (*)(int64_t))(uintptr_t)sym;
        int64_t ret = fn1(arg0);
        if (out_result) *out_result = INT48_VAL(ret);
        return KVM_OK;
    } else if (arg_count == 2) {
        int64_t arg0 = IS_INT48(args[0]) ? VALUE_TO_INT48(args[0]) : 0;
        int64_t arg1 = IS_INT48(args[1]) ? VALUE_TO_INT48(args[1]) : 0;
        __extension__ int64_t (*fn2)(int64_t, int64_t) = (int64_t (*)(int64_t, int64_t))(uintptr_t)sym;
        int64_t ret = fn2(arg0, arg1);
        if (out_result) *out_result = INT48_VAL(ret);
        return KVM_OK;
    }

    if (out_result) *out_result = NIL_VAL;
    return KVM_OK;
}
