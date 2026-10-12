#include <stdio.h>
#include <stdlib.h>
#include "kvm/vm.h"
#include "kvm/bytecode.h"

static Value native_add_ten(KvmVM *vm, int arg_count, Value *args) {
    (void)vm;
    if (arg_count < 1 || !IS_INT48(args[0])) {
        return INT48_VAL(0);
    }
    int64_t val = VALUE_TO_INT48(args[0]);
    return INT48_VAL(val + 10);
}

int main(void) {
    printf("=== KVM C Embedding Example ===\n");

    KvmVMConfig config = kvm_vm_default_config();
    config.enable_jit = true;
    config.jit_threshold = 10;

    KvmVM *vm = kvm_vm_create(&config);
    if (!vm) {
        fprintf(stderr, "Failed to create VM instance\n");
        return 1;
    }

    kvm_register_native(vm, "add_ten", native_add_ten, "i64(i64)");

    const char *kasm_src =
        ".ffi_sig \"add_ten\" \"i64(i64)\"\n"
        ".function \"main\" arity=0 regs=4\n"
        "LOADI r1, 32\n"
        "FFICALL r0, r1, 0\n"
        "RETURN r0\n"
        ".end\n";

    KvmBytecode *bc = NULL;
    char err[256] = {0};
    if (kvm_bytecode_assemble(kasm_src, &bc, err, sizeof(err)) != KVM_OK) {
        fprintf(stderr, "Assembly failed: %s\n", err);
        kvm_vm_destroy(vm);
        return 1;
    }

    if (kvm_vm_load_bytecode(vm, bc) != KVM_OK) {
        fprintf(stderr, "Load failed\n");
        kvm_bytecode_destroy(NULL, bc);
        kvm_vm_destroy(vm);
        return 1;
    }

    Value result;
    KvmStatus status = kvm_vm_run_entry(vm, &result);

    if (status == KVM_OK && IS_INT48(result)) {
        printf("Successfully executed embedded program!\n");
        printf("Result from add_ten(32): %ld\n", (long)VALUE_TO_INT48(result));
    } else {
        fprintf(stderr, "Execution error (status %d): %s\n", status, kvm_vm_get_last_error(vm));
    }

    kvm_bytecode_destroy(NULL, bc);
    kvm_vm_destroy(vm);

    printf("=== KVM Embedding Clean Exit ===\n");
    return 0;
}
