#ifndef KVM_ALLOCATOR_H
#define KVM_ALLOCATOR_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define KVM_NUM_SIZE_CLASSES 5

typedef struct KvmFreeNode {
    struct KvmFreeNode *next;
} KvmFreeNode;

typedef struct KvmAllocStats {
    size_t allocations;
    size_t frees;
    size_t live_bytes;
    size_t peak_bytes;
} KvmAllocStats;

typedef struct KvmAllocator {
    KvmFreeNode *free_lists[KVM_NUM_SIZE_CLASSES];
    KvmAllocStats stats;
} KvmAllocator;

void kvm_allocator_init(KvmAllocator *alloc);
void kvm_allocator_destroy(KvmAllocator *alloc);

void *kvm_alloc(KvmAllocator *alloc, size_t size);
void kvm_free(KvmAllocator *alloc, void *ptr, size_t size);
void *kvm_realloc(KvmAllocator *alloc, void *ptr, size_t old_size, size_t new_size);

KvmAllocStats kvm_allocator_get_stats(const KvmAllocator *alloc);

#endif /* KVM_ALLOCATOR_H */
