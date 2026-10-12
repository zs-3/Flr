# KVM Memory Model Specification

## 1. Overview
KVM employs a deterministic ownership-based memory model with zero garbage collection overhead and no reference counting in the primary execution path.

## 2. Ownership Rules
1. **Single Owner**: Every heap object has exactly one owner at any given point in time (a frame register or a field/element slot in a parent owned object).
2. **Move Semantics**: Assigning or passing an owned value via `MOVE` transfers ownership to the target and clears the source register to `NIL`.
3. **Explicit Destruction**: `DROP` deallocates the target heap object. Containers recursively drop their owned child values in reverse slot order.
4. **Scope Safety**: Compiler/assembler emits `DROP` instructions for live local values before scope exit. The VM interpreter enforces frame-exit sweep upon `RETURN` as a runtime safety net.

## 3. Borrows and References
- `BORROW` creates a shared reference (non-owning pointer).
- `BORROWMUT` creates an exclusive reference.
- References cannot be stored in container owned slots unless explicitly cloned/converted with `COPYREF`.

## 4. Debug Checks (KVM_DEBUG)
- Heap objects hold a header with a 32-bit generation counter and a live flag.
- References record the target's generation counter.
- On dereference, generation counter and live flag are checked. Mismatches trigger an explicit `TRAP`.

## 5. Size-Class Pool Allocator
- Small objects (16, 32, 64, 128, 256 bytes) are serviced from thread-local free-list pools.
- Larger allocations fall back to system `malloc`.
- Allocator tracks stats: `allocations`, `frees`, `live_bytes`, `peak_bytes`.
