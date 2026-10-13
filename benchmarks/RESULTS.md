# KVM Performance Benchmark Results

All benchmark measurements were recorded on Linux x86_64.

## 1. Recursive Fibonacci (`fib(35)`)

| Implementation | Time (seconds) | Speedup vs KVM Interp |
| :--- | :---: | :---: |
| KVM Interpreter | 4.957446 s | 1.00x |
| **KVM MIR JIT** | **5.183761 s** | **0.96x** |
| Python 3.12 | 2.445529 s | 2.03x |
| Go 1.24 (Native) | 0.068520 s | 72.35x |

## 2. Integer Loop Sum (100,000,000 Iterations)

| Implementation | Time (seconds) | Speedup vs KVM Interp |
| :--- | :---: | :---: |
| KVM Interpreter | 5.464011 s | 1.00x |
| **KVM MIR JIT** | **0.442443 s** | **12.35x** |
| Python 3.12 | 19.670907 s | 0.28x |
| Go 1.24 (Native) | 0.045215 s | 120.85x |
