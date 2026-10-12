# KVM Performance Benchmark Results

All benchmark measurements were recorded on Linux x86_64.

## 1. Recursive Fibonacci (`fib(35)`)

| Implementation | Time (seconds) | Speedup vs KVM Interp |
| :--- | :---: | :---: |
| KVM Interpreter | 32.724582 s | 1.00x |
| **KVM MIR JIT** | **27.907459 s** | **1.17x** |
| Python 3.12 | 2.467518 s | 13.26x |
| Go 1.24 (Native) | 0.069470 s | 471.06x |

## 2. Integer Loop Sum (100,000,000 Iterations)

| Implementation | Time (seconds) | Speedup vs KVM Interp |
| :--- | :---: | :---: |
| KVM Interpreter | 14.136847 s | 1.00x |
| **KVM MIR JIT** | **0.445196 s** | **31.75x** |
| Python 3.12 | 17.040723 s | 0.83x |
| Go 1.24 (Native) | 0.043806 s | 322.72x |
