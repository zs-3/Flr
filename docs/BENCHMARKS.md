# KVM Performance Benchmark Results

All benchmark measurements were recorded on Linux x86_64.

## 1. Recursive Fibonacci (`fib(30)`)

| Implementation | Time (seconds) | Speedup vs KVM Interp |
| :--- | :---: | :---: |
| KVM Interpreter | 0.0000 s | 1.00x |
| **KVM MIR JIT** | **0.0000 s** | **1.11x** |
| Python 3.12 | 0.5264 s | 0.00x |
| Go 1.24 (Native) | 0.0128 s | 0.00x |

## 2. Integer Loop Sum (10,000,000 Iterations)

| Implementation | Time (seconds) | Speedup vs KVM Interp |
| :--- | :---: | :---: |
| KVM Interpreter | 0.0000 s | 1.00x |
| **KVM MIR JIT** | **0.0000 s** | **0.76x** |
| Python 3.12 | 2.0788 s | 0.00x |
| Go 1.24 (Native) | 0.0083 s | 0.00x |
