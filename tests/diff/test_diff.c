#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "kvm/vm.h"
#include "kvm/bytecode.h"

static int run_program(const char *path, int use_jit, char *out_buf, size_t out_size, uint64_t *out_live_bytes) {
    KvmVMConfig config = kvm_vm_default_config();
    config.enable_jit = use_jit;
    config.jit_threshold = 1;

    KvmVM *vm = kvm_vm_create(&config);
    if (!vm) return -1;

    FILE *f = fopen(path, "r");
    if (!f) {
        kvm_vm_destroy(vm);
        return -2;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *src = malloc(len + 1);
    if (!src) {
        fclose(f);
        kvm_vm_destroy(vm);
        return -2;
    }
    fread(src, 1, len, f);
    src[len] = '\0';
    fclose(f);

    KvmBytecode *bc = NULL;
    char err[256] = {0};
    KvmStatus astats = kvm_bytecode_assemble(src, &bc, err, sizeof(err));
    free(src);

    if (astats != KVM_OK) {
        kvm_vm_destroy(vm);
        return -2;
    }

    if (kvm_vm_load_bytecode(vm, bc) != KVM_OK) {
        kvm_bytecode_destroy(NULL, bc);
        kvm_vm_destroy(vm);
        return -3;
    }

    Value result;
    int status = kvm_vm_run_entry(vm, &result);

    snprintf(out_buf, out_size, "Status: %d, Error: %s", status, kvm_vm_get_last_error(vm));

    KvmVMStats stats;
    kvm_vm_get_stats(vm, &stats);
    *out_live_bytes = stats.allocator_stats.live_bytes;

    kvm_bytecode_destroy(NULL, bc);
    kvm_vm_destroy(vm);
    return 0;
}

int main(void) {
    printf("--- Running Differential Test Suite ---\n");

    const char *base_dir = "tests/programs";
    DIR *dir = opendir(base_dir);
    if (!dir) {
        base_dir = "../tests/programs";
        dir = opendir(base_dir);
    }

    if (!dir) {
        fprintf(stderr, "Failed to open tests/programs directory\n");
        return 1;
    }

    struct dirent *entry;

    char files[100][256];
    int file_count = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".kasm")) {
            snprintf(files[file_count++], 256, "%s", entry->d_name);
        }
    }
    closedir(dir);

    for (int i = 0; i < file_count - 1; i++) {
        for (int j = i + 1; j < file_count; j++) {
            if (strcmp(files[i], files[j]) > 0) {
                char tmp[256];
                strcpy(tmp, files[i]);
                strcpy(files[i], files[j]);
                strcpy(files[j], tmp);
            }
        }
    }

    int total = 0, passed = 0;

    for (int i = 0; i < file_count; i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", base_dir, files[i]);

        char interp_out[512] = {0};
        char jit_out[512] = {0};
        uint64_t interp_live = 0, jit_live = 0;

        printf("Running %s...\n", path);
        fflush(stdout);
        int res_interp = run_program(path, 0, interp_out, sizeof(interp_out), &interp_live);
        int res_jit = run_program(path, 1, jit_out, sizeof(jit_out), &jit_live);

        total++;
        if (res_interp == res_jit && strcmp(interp_out, jit_out) == 0 && interp_live == 0 && jit_live == 0) {
            printf("  [DIFF PASS] %s\n", path);
            passed++;
        } else {
            printf("  [DIFF FAIL] %s\n", path);
            printf("    Interp: res=%d, out='%s', live_bytes=%llu\n", res_interp, interp_out, (unsigned long long)interp_live);
            printf("    JIT:    res=%d, out='%s', live_bytes=%llu\n", res_jit, jit_out, (unsigned long long)jit_live);
        }
    }

    printf("\nDifferential Tests: %d / %d Passed\n", passed, total);
    return (passed == total) ? 0 : 1;
}
