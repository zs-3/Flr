#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "kvm/bytecode.h"

static void build_base_bytecode(uint8_t **out_buf, size_t *out_size) {
    KvmBytecode *bc = kvm_bytecode_create();
    bc->entry_func_idx = 0;
    bc->const_count = 2;
    bc->const_pool = malloc(2 * sizeof(Value));
    bc->const_pool[0] = DOUBLE_VAL(42.0);
    bc->const_pool[1] = INT48_VAL(10);

    bc->func_count = 1;
    bc->functions = malloc(sizeof(KvmFunction*));
    bc->functions[0] = kvm_function_create("main", 0, 4);

    bc->functions[0]->code_count = 3;
    bc->functions[0]->code = malloc(3 * sizeof(KvmInstruction));
    bc->functions[0]->code[0] = KVM_ENCODE_ABC(OP_LOADI, 0, 10, 0);
    bc->functions[0]->code[1] = KVM_ENCODE_ABC(OP_LOADI, 1, 20, 0);
    bc->functions[0]->code[2] = KVM_ENCODE_ABC(OP_RETURN, 0, 0, 0);

    kvm_bytecode_write_bytes(bc, out_buf, out_size);
    kvm_bytecode_destroy(NULL, bc);
}

int main(void) {
    printf("--- Running Bytecode Validator Fuzzer (100,000 iterations) ---\n");

    uint8_t *base_buf = NULL;
    size_t base_size = 0;
    build_base_bytecode(&base_buf, &base_size);

    uint32_t seed = 123456789;

    for (int iter = 0; iter < 100000; iter++) {
        size_t mut_size = base_size;
        uint8_t *mut_buf = malloc(mut_size);
        memcpy(mut_buf, base_buf, mut_size);

        seed = seed * 1664525u + 1013904223u;
        int num_mutations = 1 + (seed % 5);

        for (int m = 0; m < num_mutations; m++) {
            seed = seed * 1664525u + 1013904223u;
            size_t pos = seed % mut_size;
            seed = seed * 1664525u + 1013904223u;
            mut_buf[pos] ^= (uint8_t)(seed & 0xFF);
        }

        KvmBytecode *bc = NULL;
        if (kvm_bytecode_read_bytes(mut_buf, mut_size, &bc) == KVM_OK && bc != NULL) {
            char err[256] = {0};
            kvm_bytecode_validate(bc, err, sizeof(err));
            kvm_bytecode_destroy(NULL, bc);
        }

        free(mut_buf);
    }

    free(base_buf);
    printf("--- Fuzzer Completed 100,000 Iterations Successfully ---\n");
    return 0;
}
