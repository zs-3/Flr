#include "kvm/bytecode.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_assembler_and_validator(void) {
    const char *kasm =
        ".function \"main\" arity=0 regs=8\n"
        "  LOADI r0, 10\n"
        "  LOADI r1, 20\n"
        "  IADD r2, r0, r1\n"
        "  MOVE r3, r2\n"
        "  DROP r3\n"
        "  RETURN r0\n"
        ".end\n";

    char err[256] = "";
    KvmBytecode *bc = NULL;
    KvmStatus status = kvm_bytecode_assemble(kasm, &bc, err, sizeof(err));
    printf("Assemble status=%d, err='%s'\n", status, err);
    fflush(stdout);
    assert(status == KVM_OK);
    assert(bc != NULL);
    assert(bc->func_count == 1);

    status = kvm_bytecode_validate(bc, err, sizeof(err));
    printf("Validate status=%d, err='%s'\n", status, err);
    fflush(stdout);
    assert(status == KVM_OK);

    kvm_bytecode_destroy(NULL, bc);
    printf("  [PASS] test_assembler_and_validator\n");
    fflush(stdout);
}

void test_validator_reject_rules(void) {
    char err[256] = "";

    /* Test 1: Register out of range */
    KvmBytecode *bc1 = kvm_bytecode_create();
    KvmFunction *f1 = kvm_function_create("bad_reg", 0, 2);
    f1->code_count = 2;
    f1->code = (KvmInstruction *)calloc(2, sizeof(KvmInstruction));
    f1->code[0] = KVM_ENCODE_ABSI(OP_LOADI, 5, 10);
    f1->code[1] = KVM_ENCODE_ABC(OP_RETURN, 0, 1, 0);
    bc1->func_count = 1;
    bc1->functions = (KvmFunction **)calloc(1, sizeof(KvmFunction *));
    bc1->functions[0] = f1;

    assert(kvm_bytecode_validate(bc1, err, sizeof(err)) == KVM_ERR_VERIFIER_FAILURE);
    kvm_bytecode_destroy(NULL, bc1);

    /* Test 2: Jump out of bounds */
    KvmBytecode *bc2 = kvm_bytecode_create();
    KvmFunction *f2 = kvm_function_create("bad_jmp", 0, 4);
    f2->code_count = 2;
    f2->code = (KvmInstruction *)calloc(2, sizeof(KvmInstruction));
    f2->code[0] = KVM_ENCODE_ABSI(OP_JMP, 0, 100);
    f2->code[1] = KVM_ENCODE_ABC(OP_RETURN, 0, 1, 0);
    bc2->func_count = 1;
    bc2->functions = (KvmFunction **)calloc(1, sizeof(KvmFunction *));
    bc2->functions[0] = f2;

    assert(kvm_bytecode_validate(bc2, err, sizeof(err)) == KVM_ERR_VERIFIER_FAILURE);
    kvm_bytecode_destroy(NULL, bc2);

    /* Test 3: Uninitialized register read */
    KvmBytecode *bc3 = kvm_bytecode_create();
    KvmFunction *f3 = kvm_function_create("uninit_reg", 0, 4);
    f3->code_count = 2;
    f3->code = (KvmInstruction *)calloc(2, sizeof(KvmInstruction));
    f3->code[0] = KVM_ENCODE_ABC(OP_MOVE, 1, 0, 0);
    f3->code[1] = KVM_ENCODE_ABC(OP_RETURN, 0, 1, 0);
    bc3->func_count = 1;
    bc3->functions = (KvmFunction **)calloc(1, sizeof(KvmFunction *));
    bc3->functions[0] = f3;

    assert(kvm_bytecode_validate(bc3, err, sizeof(err)) == KVM_ERR_VERIFIER_FAILURE);
    kvm_bytecode_destroy(NULL, bc3);

    printf("  [PASS] test_validator_reject_rules\n");
    fflush(stdout);
}

void test_reader_writer_roundtrip(void) {
    const char *kasm =
        ".function \"main\" arity=0 regs=8\n"
        "  LOADI r0, 42\n"
        "  RETURN r0\n"
        ".end\n";

    char err[256] = "";
    KvmBytecode *bc_orig = NULL;
    assert(kvm_bytecode_assemble(kasm, &bc_orig, err, sizeof(err)) == KVM_OK);

    uint8_t *buf = NULL;
    size_t size = 0;
    assert(kvm_bytecode_write_bytes(bc_orig, &buf, &size) == KVM_OK);
    assert(buf != NULL && size > 0);

    KvmBytecode *bc_read = NULL;
    assert(kvm_bytecode_read_bytes(buf, size, &bc_read) == KVM_OK);
    assert(bc_read != NULL);

    assert(bc_read->func_count == bc_orig->func_count);
    assert(strcmp(bc_read->functions[0]->name, bc_orig->functions[0]->name) == 0);
    assert(bc_read->functions[0]->code_count == bc_orig->functions[0]->code_count);

    free(buf);
    kvm_bytecode_destroy(NULL, bc_orig);
    kvm_bytecode_destroy(NULL, bc_read);

    printf("  [PASS] test_reader_writer_roundtrip\n");
    fflush(stdout);
}

void run_bytecode_tests(void) {
    printf("Running Bytecode Tests...\n");
    fflush(stdout);
    test_assembler_and_validator();
    test_validator_reject_rules();
    test_reader_writer_roundtrip();
}
