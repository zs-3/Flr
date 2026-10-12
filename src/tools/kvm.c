#include "kvm/vm.h"
#include "kvm/bytecode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_text_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)len + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t read_bytes = fread(buf, 1, (size_t)len, f);
    buf[read_bytes] = '\0';
    fclose(f);
    return buf;
}

static KvmBytecode *load_bytecode_from_file(const char *path) {
    KvmBytecode *bc = NULL;
    size_t len = strlen(path);

    if (len > 5 && strcmp(path + len - 5, ".kasm") == 0) {
        char *src = read_text_file(path);
        if (!src) {
            fprintf(stderr, "Error: Could not open source file '%s'\n", path);
            return NULL;
        }
        char err[256] = {0};
        if (kvm_bytecode_assemble(src, &bc, err, sizeof(err)) != KVM_OK) {
            fprintf(stderr, "Assembly error in '%s': %s\n", path, err);
            free(src);
            return NULL;
        }
        free(src);
    } else {
        if (kvm_bytecode_read_file(path, &bc) != KVM_OK) {
            fprintf(stderr, "Error: Could not read binary bytecode file '%s'\n", path);
            return NULL;
        }
    }

    char val_err[256] = {0};
    if (kvm_bytecode_validate(bc, val_err, sizeof(val_err)) != KVM_OK) {
        fprintf(stderr, "Bytecode validation failed for '%s': %s\n", path, val_err);
        kvm_bytecode_destroy(NULL, bc);
        return NULL;
    }

    return bc;
}

static int cmd_run(const char *filepath) {
    KvmBytecode *bc = load_bytecode_from_file(filepath);
    if (!bc) return 1;

    KvmVMConfig config = kvm_vm_default_config();
    KvmVM *vm = kvm_vm_create(&config);
    if (!vm) {
        fprintf(stderr, "Error: Failed to create KVM instance\n");
        kvm_bytecode_destroy(NULL, bc);
        return 1;
    }

    if (kvm_vm_load_bytecode(vm, bc) != KVM_OK) {
        fprintf(stderr, "Error: Failed to load bytecode into VM\n");
        kvm_bytecode_destroy(NULL, bc);
        kvm_vm_destroy(vm);
        return 1;
    }

    Value result = NIL_VAL;
    KvmStatus status = kvm_vm_run_entry(vm, &result);

    if (status != KVM_OK) {
        fprintf(stderr, "Execution error (status %d): %s\n", status, kvm_vm_get_last_error(vm));
        kvm_bytecode_destroy(NULL, bc);
        kvm_vm_destroy(vm);
        return 1;
    }

    if (IS_INT48(result)) {
        printf("Result: %ld\n", (long)VALUE_TO_INT48(result));
    } else if (IS_DOUBLE(result)) {
        printf("Result: %f\n", VALUE_TO_DOUBLE(result));
    } else if (IS_BOOL(result)) {
        printf("Result: %s\n", VALUE_TO_BOOL(result) ? "true" : "false");
    } else if (IS_NIL(result)) {
        printf("Result: nil\n");
    } else {
        printf("Result: <heap object>\n");
    }

    kvm_bytecode_destroy(NULL, bc);
    kvm_vm_destroy(vm);
    return 0;
}

static int cmd_asm(const char *in_path, const char *out_path) {
    char *src = read_text_file(in_path);
    if (!src) {
        fprintf(stderr, "Error: Could not read source file '%s'\n", in_path);
        return 1;
    }

    KvmBytecode *bc = NULL;
    char err[256] = {0};
    if (kvm_bytecode_assemble(src, &bc, err, sizeof(err)) != KVM_OK) {
        fprintf(stderr, "Assembly error: %s\n", err);
        free(src);
        return 1;
    }
    free(src);

    if (kvm_bytecode_validate(bc, err, sizeof(err)) != KVM_OK) {
        fprintf(stderr, "Validation error: %s\n", err);
        kvm_bytecode_destroy(NULL, bc);
        return 1;
    }

    char target[512];
    if (out_path) {
        snprintf(target, sizeof(target), "%s", out_path);
    } else {
        snprintf(target, sizeof(target), "%s", in_path);
        size_t len = strlen(target);
        if (len > 5 && strcmp(target + len - 5, ".kasm") == 0) {
            strcpy(target + len - 5, ".kbc");
        } else {
            strcat(target, ".kbc");
        }
    }

    if (kvm_bytecode_write_file(bc, target) != KVM_OK) {
        fprintf(stderr, "Error: Could not write output binary '%s'\n", target);
        kvm_bytecode_destroy(NULL, bc);
        return 1;
    }

    printf("Successfully assembled '%s' -> '%s'\n", in_path, target);
    kvm_bytecode_destroy(NULL, bc);
    return 0;
}

static int cmd_dis(const char *filepath) {
    KvmBytecode *bc = load_bytecode_from_file(filepath);
    if (!bc) return 1;

    kvm_bytecode_disassemble(bc, stdout);
    kvm_bytecode_destroy(NULL, bc);
    return 0;
}

static void print_usage(const char *prog_name) {
    printf("Usage:\n");
    printf("  %s run <file.kbc|file.kasm>    Run bytecode or assembly program\n", prog_name);
    printf("  %s asm <file.kasm> [out.kbc]   Assemble .kasm text into .kbc binary\n", prog_name);
    printf("  %s dis <file.kbc|file.kasm>    Disassemble file to stdout\n", prog_name);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    const char *path = argv[2];

    if (strcmp(cmd, "run") == 0) {
        return cmd_run(path);
    } else if (strcmp(cmd, "asm") == 0) {
        const char *out_path = (argc >= 4) ? argv[3] : NULL;
        return cmd_asm(path, out_path);
    } else if (strcmp(cmd, "dis") == 0) {
        return cmd_dis(path);
    } else {
        fprintf(stderr, "Unknown command '%s'\n", cmd);
        print_usage(argv[0]);
        return 1;
    }
}
