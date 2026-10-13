#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "kvm/vm.h"
#include "kvm/bytecode.h"

static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static double run_kvm_bench_code(const char *src_code, int use_jit) {
    KvmVMConfig config = kvm_vm_default_config();
    config.enable_jit = use_jit;
    config.jit_threshold = 1;

    KvmVM *vm = kvm_vm_create(&config);
    if (!vm) return -1;

    KvmBytecode *bc = NULL;
    char err[256] = {0};
    if (kvm_bytecode_assemble(src_code, &bc, err, sizeof(err)) != KVM_OK) {
        kvm_vm_destroy(vm);
        return -1;
    }

    if (kvm_vm_load_bytecode(vm, bc) != KVM_OK) {
        kvm_bytecode_destroy(NULL, bc);
        kvm_vm_destroy(vm);
        return -1;
    }

    double t0 = get_time_sec();
    Value res;
    kvm_vm_run_entry(vm, &res);
    double t1 = get_time_sec();

    kvm_bytecode_destroy(NULL, bc);
    kvm_vm_destroy(vm);
    return t1 - t0;
}

int main(void) {
    printf("=========================================================\n");
    printf("               KVM PERFORMANCE BENCHMARKS                \n");
    printf("=========================================================\n\n");
    fflush(stdout);

    const char *fib25_kasm =
        ".function \"main\" arity=0 regs=4\n"
        "LOADI r2, 25\n"
        "LOADI r1, 1\n"
        "CALL r0, r1, 1\n"
        "RETURN r0\n"
        ".end\n"
        ".function \"fib\" arity=1 regs=4\n"
        "LOADI r1, 1\n"
        "JLE r0, r1, @base\n"
        "LOADI r1, 1\n"
        "ISUB r2, r0, r1\n"
        "LOADI r1, 1\n"
        "CALL r3, r1, 1\n"
        "LOADI r1, 2\n"
        "ISUB r2, r0, r1\n"
        "LOADI r1, 1\n"
        "CALL r1, r1, 1\n"
        "IADD r0, r3, r1\n"
        "RETURN r0\n"
        "@base:\n"
        "RETURN r0\n"
        ".end\n";

    const char *loop_kasm =
        ".function \"main\" arity=0 regs=4\n"
        ".const_int 10000000\n"
        "LOADI r0, 0\n"
        "LOADI r1, 0\n"
        "LOADK r2, 0\n"
        "LOADI r3, 1\n"
        "@loop:\n"
        "JLT r1, r2, @body\n"
        "RETURN r0\n"
        "@body:\n"
        "IADD r0, r0, r1\n"
        "IADD r1, r1, r3\n"
        "JMP @loop\n"
        ".end\n";

    const char *nested_loop_kasm =
        ".function \"main\" arity=0 regs=6\n"
        "LOADI r0, 0\n"
        "LOADI r1, 0\n"
        "LOADI r2, 1000\n"
        "LOADI r3, 1000\n"
        "LOADI r4, 1\n"
        "@outer:\n"
        "JLT r1, r2, @body_outer\n"
        "RETURN r0\n"
        "@body_outer:\n"
        "LOADI r5, 0\n"
        "@inner:\n"
        "JLT r5, r3, @body_inner\n"
        "IADD r1, r1, r4\n"
        "JMP @outer\n"
        "@body_inner:\n"
        "IADD r0, r0, r5\n"
        "IADD r5, r5, r4\n"
        "JMP @inner\n"
        ".end\n";

    const char *array_fill_sum_kasm =
        ".function \"main\" arity=0 regs=7\n"
        ".const_int 10000\n"
        "NEWARRAY r0\n"
        "LOADI r1, 0\n"
        "LOADK r2, 0\n"
        "LOADI r3, 1\n"
        "@fill_loop:\n"
        "JLT r1, r2, @fill_body\n"
        "JMP @sum_start\n"
        "@fill_body:\n"
        "LOADI r6, 42\n"
        "SETINDEX r0, r1, r6\n"
        "IADD r1, r1, r3\n"
        "JMP @fill_loop\n"
        "@sum_start:\n"
        "LOADI r1, 0\n"
        "LOADI r4, 0\n"
        "@sum_loop:\n"
        "JLT r1, r2, @sum_body\n"
        "DROP r0\n"
        "RETURN r4\n"
        "@sum_body:\n"
        "GETINDEX r5, r0, r1\n"
        "IADD r4, r4, r5\n"
        "IADD r1, r1, r3\n"
        "JMP @sum_loop\n"
        ".end\n";

    const char *float_loop_kasm =
        ".function \"main\" arity=0 regs=6\n"
        ".const_int 100000\n"
        ".const_double 0.0\n"
        ".const_double 1.0\n"
        ".const_double 0.5\n"
        "LOADK r0, 1\n"
        "LOADI r1, 0\n"
        "LOADK r2, 0\n"
        "LOADI r3, 1\n"
        "LOADK r4, 2\n"
        "LOADK r5, 3\n"
        "@loop:\n"
        "JLT r1, r2, @body\n"
        "RETURN r0\n"
        "@body:\n"
        "FADD r0, r0, r4\n"
        "FMUL r0, r0, r5\n"
        "IADD r1, r1, r3\n"
        "JMP @loop\n"
        ".end\n";

    printf("Executing Recursive Fibonacci (fib(25))...\n"); fflush(stdout);
    double kvm_fib_interp = run_kvm_bench_code(fib25_kasm, 0);
    double kvm_fib_jit = run_kvm_bench_code(fib25_kasm, 1);

    printf("Executing Integer Loop Sum (10,000,000 iterations)...\n"); fflush(stdout);
    double kvm_loop_interp = run_kvm_bench_code(loop_kasm, 0);
    double kvm_loop_jit = run_kvm_bench_code(loop_kasm, 1);

    printf("Executing Nested Loop Integer Sum (1,000 x 1,000)...\n"); fflush(stdout);
    double kvm_nested_interp = run_kvm_bench_code(nested_loop_kasm, 0);
    double kvm_nested_jit = run_kvm_bench_code(nested_loop_kasm, 1);

    printf("Executing Array Fill and Sum (10,000 elements)...\n"); fflush(stdout);
    double kvm_arr_interp = run_kvm_bench_code(array_fill_sum_kasm, 0);
    double kvm_arr_jit = run_kvm_bench_code(array_fill_sum_kasm, 1);

    printf("Executing Tight Float Loop (100,000 iterations)...\n"); fflush(stdout);
    double kvm_float_interp = run_kvm_bench_code(float_loop_kasm, 0);
    double kvm_float_jit = run_kvm_bench_code(float_loop_kasm, 1);

    printf("\n1. Benchmark: Recursive Fibonacci (fib(25))\n");
    printf("   - KVM Interpreter : %10.6f s\n", kvm_fib_interp);
    printf("   - KVM MIR JIT     : %10.6f s (Speedup: %.2fx vs Interp)\n\n", kvm_fib_jit, kvm_fib_interp / kvm_fib_jit);

    printf("2. Benchmark: Integer Loop Sum (10,000,000 iterations)\n");
    printf("   - KVM Interpreter : %10.6f s\n", kvm_loop_interp);
    printf("   - KVM MIR JIT     : %10.6f s (Speedup: %.2fx vs Interp)\n\n", kvm_loop_jit, kvm_loop_interp / kvm_loop_jit);

    printf("3. Benchmark: Nested Loop Integer Sum (1,000 x 1,000 iterations)\n");
    printf("   - KVM Interpreter : %10.6f s\n", kvm_nested_interp);
    printf("   - KVM MIR JIT     : %10.6f s (Speedup: %.2fx vs Interp)\n\n", kvm_nested_jit, kvm_nested_interp / kvm_nested_jit);

    printf("4. Benchmark: Array Fill and Sum (10,000 elements)\n");
    printf("   - KVM Interpreter : %10.6f s\n", kvm_arr_interp);
    printf("   - KVM MIR JIT     : %10.6f s (Speedup: %.2fx vs Interp)\n\n", kvm_arr_jit, kvm_arr_interp / kvm_arr_jit);

    printf("5. Benchmark: Tight Float Loop (100,000 iterations)\n");
    printf("   - KVM Interpreter : %10.6f s\n", kvm_float_interp);
    printf("   - KVM MIR JIT     : %10.6f s (Speedup: %.2fx vs Interp)\n\n", kvm_float_jit, kvm_float_interp / kvm_float_jit);

    const char *paths[2] = {"benchmarks/RESULTS.md", "docs/BENCHMARKS.md"};
    for (int p = 0; p < 2; p++) {
        FILE *f_doc = fopen(paths[p], "w");
        if (f_doc) {
            fprintf(f_doc, "# KVM Performance Benchmark Results\n\n");
            fprintf(f_doc, "All benchmark measurements were recorded on Linux x86_64.\n\n");

            fprintf(f_doc, "## 1. Recursive Fibonacci (`fib(25)`)\n\n");
            fprintf(f_doc, "| Implementation | Time (seconds) | Speedup vs KVM Interp |\n");
            fprintf(f_doc, "| :--- | :---: | :---: |\n");
            fprintf(f_doc, "| KVM Interpreter | %.6f s | 1.00x |\n", kvm_fib_interp);
            fprintf(f_doc, "| **KVM MIR JIT** | **%.6f s** | **%.2fx** |\n\n", kvm_fib_jit, kvm_fib_interp / kvm_fib_jit);

            fprintf(f_doc, "## 2. Integer Loop Sum (10,000,000 Iterations)\n\n");
            fprintf(f_doc, "| Implementation | Time (seconds) | Speedup vs KVM Interp |\n");
            fprintf(f_doc, "| :--- | :---: | :---: |\n");
            fprintf(f_doc, "| KVM Interpreter | %.6f s | 1.00x |\n", kvm_loop_interp);
            fprintf(f_doc, "| **KVM MIR JIT** | **%.6f s** | **%.2fx** |\n\n", kvm_loop_jit, kvm_loop_interp / kvm_loop_jit);

            fprintf(f_doc, "## 3. Nested Loop Integer Sum (1,000 x 1,000 Iterations)\n\n");
            fprintf(f_doc, "| Implementation | Time (seconds) | Speedup vs KVM Interp |\n");
            fprintf(f_doc, "| :--- | :---: | :---: |\n");
            fprintf(f_doc, "| KVM Interpreter | %.6f s | 1.00x |\n", kvm_nested_interp);
            fprintf(f_doc, "| **KVM MIR JIT** | **%.6f s** | **%.2fx** |\n\n", kvm_nested_jit, kvm_nested_interp / kvm_nested_jit);

            fprintf(f_doc, "## 4. Array Fill and Sum (10,000 Elements)\n\n");
            fprintf(f_doc, "| Implementation | Time (seconds) | Speedup vs KVM Interp |\n");
            fprintf(f_doc, "| :--- | :---: | :---: |\n");
            fprintf(f_doc, "| KVM Interpreter | %.6f s | 1.00x |\n", kvm_arr_interp);
            fprintf(f_doc, "| **KVM MIR JIT** | **%.6f s** | **%.2fx** |\n\n", kvm_arr_jit, kvm_arr_interp / kvm_arr_jit);

            fprintf(f_doc, "## 5. Tight Float Loop (100,000 Iterations)\n\n");
            fprintf(f_doc, "| Implementation | Time (seconds) | Speedup vs KVM Interp |\n");
            fprintf(f_doc, "| :--- | :---: | :---: |\n");
            fprintf(f_doc, "| KVM Interpreter | %.6f s | 1.00x |\n", kvm_float_interp);
            fprintf(f_doc, "| **KVM MIR JIT** | **%.6f s** | **%.2fx** |\n\n", kvm_float_jit, kvm_float_interp / kvm_float_jit);

            fclose(f_doc);
        }
    }

    return 0;
}
