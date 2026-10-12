#ifndef KVM_VALUE_H
#define KVM_VALUE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

typedef uint64_t Value;

#define KVM_TAG_PREFIX     0x7FF0000000000000ULL
#define KVM_TAG_MASK       0x7FF0000000000000ULL
#define KVM_TAG_VAL_MASK   0x000F000000000000ULL
#define KVM_PAYLOAD_MASK   0x0000FFFFFFFFFFFFULL
#define KVM_CANON_NAN      0x7FF8000000000000ULL

#define KVM_TAG_NIL           0x0ULL
#define KVM_TAG_BOOL          0x1ULL
#define KVM_TAG_INT48         0x2ULL
#define KVM_TAG_HEAP_OBJ      0x3ULL
#define KVM_TAG_NATIVE_HANDLE 0x4ULL
#define KVM_TAG_BORROW        0x5ULL
#define KVM_TAG_BORROWMUT     0x6ULL

#define KVM_INT48_MIN (-140737488355328LL)
#define KVM_INT48_MAX ( 140737488355327LL)

static inline bool kvm_val_is_double(Value v) {
    return (v & KVM_TAG_PREFIX) != KVM_TAG_PREFIX;
}

static inline bool kvm_val_is_tagged(Value v) {
    return (v & KVM_TAG_PREFIX) == KVM_TAG_PREFIX;
}

static inline uint64_t kvm_val_tag(Value v) {
    return (v >> 48) & 0xFU;
}

static inline bool kvm_val_is_nil(Value v) {
    return kvm_val_is_tagged(v) && kvm_val_tag(v) == 0x0ULL;
}

static inline bool kvm_val_is_bool(Value v) {
    return kvm_val_is_tagged(v) && kvm_val_tag(v) == 0x1ULL;
}

static inline bool kvm_val_is_int48(Value v) {
    return kvm_val_is_tagged(v) && kvm_val_tag(v) == 0x2ULL;
}

static inline bool kvm_val_is_heap_obj(Value v) {
    return kvm_val_is_tagged(v) && kvm_val_tag(v) == 0x3ULL;
}

static inline bool kvm_val_is_native_handle(Value v) {
    return kvm_val_is_tagged(v) && kvm_val_tag(v) == 0x4ULL;
}

static inline bool kvm_val_is_borrow(Value v) {
    return kvm_val_is_tagged(v) && (kvm_val_tag(v) == 0x5ULL || kvm_val_tag(v) == 0x6ULL);
}

static inline bool kvm_val_is_borrow_mut(Value v) {
    return kvm_val_is_tagged(v) && kvm_val_tag(v) == 0x6ULL;
}

static inline Value kvm_val_double(double d) {
    Value v;
    memcpy(&v, &d, sizeof(double));
    if (kvm_val_is_tagged(v)) {
        v = KVM_CANON_NAN;
    }
    return v;
}

static inline double kvm_val_as_double(Value v) {
    double d;
    memcpy(&d, &v, sizeof(double));
    return d;
}

static inline Value kvm_val_nil(void) {
    return KVM_TAG_PREFIX | (0x0ULL << 48);
}

static inline Value kvm_val_bool(bool b) {
    return KVM_TAG_PREFIX | (0x1ULL << 48) | (b ? 1ULL : 0ULL);
}

static inline bool kvm_val_as_bool(Value v) {
    return (v & 1ULL) != 0ULL;
}

static inline Value kvm_val_int48(int64_t i) {
    uint64_t u = (uint64_t)i & KVM_PAYLOAD_MASK;
    return KVM_TAG_PREFIX | (0x2ULL << 48) | u;
}

static inline int64_t kvm_val_as_int48(Value v) {
    uint64_t u = v & KVM_PAYLOAD_MASK;
    if (u & 0x800000000000ULL) {
        u |= 0xFFFF000000000000ULL;
    }
    return (int64_t)u;
}

static inline Value kvm_val_heap_obj(const void *ptr) {
    uint64_t u = (uintptr_t)ptr & KVM_PAYLOAD_MASK;
    return KVM_TAG_PREFIX | (0x3ULL << 48) | u;
}

static inline void *kvm_val_as_heap_obj(Value v) {
    return (void *)(uintptr_t)(v & KVM_PAYLOAD_MASK);
}

static inline Value kvm_val_native_handle(const void *ptr) {
    uint64_t u = (uintptr_t)ptr & KVM_PAYLOAD_MASK;
    return KVM_TAG_PREFIX | (0x4ULL << 48) | u;
}

static inline void *kvm_val_as_native_handle(Value v) {
    return (void *)(uintptr_t)(v & KVM_PAYLOAD_MASK);
}

static inline Value kvm_val_borrow(const void *ptr, bool is_mut) {
    uint64_t u = (uintptr_t)ptr & KVM_PAYLOAD_MASK;
    uint64_t tag = is_mut ? 0x6ULL : 0x5ULL;
    return KVM_TAG_PREFIX | (tag << 48) | u;
}

static inline void *kvm_val_as_borrow(Value v) {
    return (void *)(uintptr_t)(v & KVM_PAYLOAD_MASK);
}

// Convenience macros
#define IS_DOUBLE(v)           kvm_val_is_double(v)
#define IS_INT48(v)            kvm_val_is_int48(v)
#define IS_NIL(v)              kvm_val_is_nil(v)
#define IS_BOOL(v)             kvm_val_is_bool(v)
#define IS_POINTER(v)          kvm_val_is_heap_obj(v)

#define DOUBLE_VAL(d)          kvm_val_double(d)
#define INT48_VAL(i)           kvm_val_int48(i)
#define NIL_VAL                kvm_val_nil()
#define BOOL_VAL(b)            kvm_val_bool(b)
#define HEAP_OBJ_TO_VALUE(p)   kvm_val_heap_obj(p)

#define VALUE_TO_DOUBLE(v)     kvm_val_as_double(v)
#define VALUE_TO_INT48(v)      kvm_val_as_int48(v)
#define VALUE_TO_BOOL(v)       kvm_val_as_bool(v)
#define VALUE_TO_HEAP_OBJ(v)   ((struct KvmHeapObject*)kvm_val_as_heap_obj(v))

#endif /* KVM_VALUE_H */
