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

static double run_cmd_bench(const char *cmd) {
    double t0 = get_time_sec();
    int ret = system(cmd);
    double t1 = get_time_sec();
    if (ret != 0) return -1;
    return t1 - t0;
}

int main(void) {
    printf("=========================================================\n");
    printf("               KVM PERFORMANCE BENCHMARKS                \n");
    printf("=========================================================\n\n");

    // Benchmark 1: Recursive Fibonacci fib(35)
    FILE *f_py = fopen("/tmp/bench_fib.py", "w");
    if (f_py) {
        fprintf(f_py, "def fib(n):\n");
        fprintf(f_py, "    if n <= 1: return n\n");
        fprintf(f_py, "    return fib(n-1) + fib(n-2)\n");
        fprintf(f_py, "fib(35)\n");
        fclose(f_py);
    }

    FILE *f_go = fopen("/tmp/bench_fib.go", "w");
    if (f_go) {
        fprintf(f_go, "package main\n");
        fprintf(f_go, "func fib(n int) int {\n");
        fprintf(f_go, "    if n <= 1 { return n }\n");
        fprintf(f_go, "    return fib(n-1) + fib(n-2)\n");
        fprintf(f_go, "}\n");
        fprintf(f_go, "func main() { fib(35) }\n");
        fclose(f_go);
    }
    system("go build -o /tmp/bench_fib_go /tmp/bench_fib.go 2>/dev/null");

    // Benchmark 2: Integer Loop Sum (100,000,000 iterations)
    FILE *f_loop_py = fopen("/tmp/bench_loop.py", "w");
    if (f_loop_py) {
        fprintf(f_loop_py, "s = 0\n");
        fprintf(f_loop_py, "for i in range(100000000):\n");
        fprintf(f_loop_py, "    s += i\n");
        fclose(f_loop_py);
    }

    FILE *f_loop_go = fopen("/tmp/bench_loop.go", "w");
    if (f_loop_go) {
        fprintf(f_loop_go, "package main\n");
        fprintf(f_loop_go, "func main() {\n");
        fprintf(f_loop_go, "    s := 0\n");
        fprintf(f_loop_go, "    for i := 0; i < 100000000; i++ { s += i }\n");
        fprintf(f_loop_go, "}\n");
        fclose(f_loop_go);
    }
    system("go build -o /tmp/bench_loop_go /tmp/bench_loop.go 2>/dev/null");

    const char *fib35_kasm =
        ".function \"main\" arity=0 regs=4\n"
        "LOADI r2, 35\n"
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
        ".const_int 100000000\n"
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

    printf("Executing Recursive Fibonacci (fib(35))...\n");
    fflush(stdout);
    double kvm_fib_interp = run_kvm_bench_code(fib35_kasm, 0);
    double kvm_fib_jit = run_kvm_bench_code(fib35_kasm, 1);
    double py_fib = run_cmd_bench("python3 /tmp/bench_fib.py >/dev/null 2>&1");
    double go_fib = run_cmd_bench("/tmp/bench_fib_go >/dev/null 2>&1");

    printf("Executing Integer Loop Sum (100,000,000 iterations)...\n");
    fflush(stdout);
    double kvm_loop_interp = run_kvm_bench_code(loop_kasm, 0);
    double kvm_loop_jit = run_kvm_bench_code(loop_kasm, 1);
    double py_loop = run_cmd_bench("python3 /tmp/bench_loop.py >/dev/null 2>&1");
    double go_loop = run_cmd_bench("/tmp/bench_loop_go >/dev/null 2>&1");

    printf("\n1. Benchmark: Recursive Fibonacci (fib(35))\n");
    printf("   - KVM Interpreter : %10.6f s\n", kvm_fib_interp);
    printf("   - KVM MIR JIT     : %10.6f s (Speedup: %.2fx vs Interp)\n", kvm_fib_jit, kvm_fib_interp / kvm_fib_jit);
    printf("   - Python 3.12     : %10.6f s\n", py_fib);
    printf("   - Go 1.24 (Native): %10.6f s\n\n", go_fib);

    printf("2. Benchmark: Integer Loop Sum (100,000,000 iterations)\n");
    printf("   - KVM Interpreter : %10.6f s\n", kvm_loop_interp);
    printf("   - KVM MIR JIT     : %10.6f s (Speedup: %.2fx vs Interp)\n", kvm_loop_jit, kvm_loop_interp / kvm_loop_jit);
    printf("   - Python 3.12     : %10.6f s\n", py_loop);
    printf("   - Go 1.24 (Native): %10.6f s\n\n", go_loop);

    const char *paths[2] = {"benchmarks/RESULTS.md", "docs/BENCHMARKS.md"};
    for (int p = 0; p < 2; p++) {
        FILE *f_doc = fopen(paths[p], "w");
        if (f_doc) {
            fprintf(f_doc, "# KVM Performance Benchmark Results\n\n");
            fprintf(f_doc, "All benchmark measurements were recorded on Linux x86_64.\n\n");
            fprintf(f_doc, "## 1. Recursive Fibonacci (`fib(35)`)\n\n");
            fprintf(f_doc, "| Implementation | Time (seconds) | Speedup vs KVM Interp |\n");
            fprintf(f_doc, "| :--- | :---: | :---: |\n");
            fprintf(f_doc, "| KVM Interpreter | %.6f s | 1.00x |\n", kvm_fib_interp);
            fprintf(f_doc, "| **KVM MIR JIT** | **%.6f s** | **%.2fx** |\n", kvm_fib_jit, kvm_fib_interp / kvm_fib_jit);
            fprintf(f_doc, "| Python 3.12 | %.6f s | %.2fx |\n", py_fib, kvm_fib_interp / py_fib);
            fprintf(f_doc, "| Go 1.24 (Native) | %.6f s | %.2fx |\n\n", go_fib, kvm_fib_interp / go_fib);

            fprintf(f_doc, "## 2. Integer Loop Sum (100,000,000 Iterations)\n\n");
            fprintf(f_doc, "| Implementation | Time (seconds) | Speedup vs KVM Interp |\n");
            fprintf(f_doc, "| :--- | :---: | :---: |\n");
            fprintf(f_doc, "| KVM Interpreter | %.6f s | 1.00x |\n", kvm_loop_interp);
            fprintf(f_doc, "| **KVM MIR JIT** | **%.6f s** | **%.2fx** |\n", kvm_loop_jit, kvm_loop_interp / kvm_loop_jit);
            fprintf(f_doc, "| Python 3.12 | %.6f s | %.2fx |\n", py_loop, kvm_loop_interp / py_loop);
            fprintf(f_doc, "| Go 1.24 (Native) | %.6f s | %.2fx |\n\n", go_loop, kvm_loop_interp / go_loop);

            fclose(f_doc);
        }
    }

    return 0;
}
