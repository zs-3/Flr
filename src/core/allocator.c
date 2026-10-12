#include "kvm/allocator.h"
#include <stdlib.h>
#include <string.h>

static inline int size_class_index(size_t size) {
    if (size <= 16) return 0;
    if (size <= 32) return 1;
    if (size <= 64) return 2;
    if (size <= 128) return 3;
    if (size <= 256) return 4;
    return -1;
}

static inline size_t class_size(int idx) {
    static const size_t sizes[KVM_NUM_SIZE_CLASSES] = {16, 32, 64, 128, 256};
    return (idx >= 0 && idx < KVM_NUM_SIZE_CLASSES) ? sizes[idx] : 0;
}

void kvm_allocator_init(KvmAllocator *alloc) {
    if (!alloc) return;
    memset(alloc, 0, sizeof(KvmAllocator));
}

void kvm_allocator_destroy(KvmAllocator *alloc) {
    if (!alloc) return;
    for (int i = 0; i < KVM_NUM_SIZE_CLASSES; i++) {
        KvmFreeNode *curr = alloc->free_lists[i];
        while (curr) {
            KvmFreeNode *next = curr->next;
            free(curr);
            curr = next;
        }
        alloc->free_lists[i] = NULL;
    }
}

void *kvm_alloc(KvmAllocator *alloc, size_t size) {
    if (!alloc || size == 0) return NULL;

    int sc = size_class_index(size);
    void *ptr = NULL;
    size_t alloc_bytes = size;

    if (sc >= 0) {
        alloc_bytes = class_size(sc);
        if (alloc->free_lists[sc]) {
            KvmFreeNode *node = alloc->free_lists[sc];
            alloc->free_lists[sc] = node->next;
            ptr = node;
        } else {
            ptr = malloc(alloc_bytes);
        }
    } else {
        ptr = malloc(size);
    }

    if (ptr) {
        alloc->stats.allocations++;
        alloc->stats.live_bytes += alloc_bytes;
        if (alloc->stats.live_bytes > alloc->stats.peak_bytes) {
            alloc->stats.peak_bytes = alloc->stats.live_bytes;
        }
    }

    return ptr;
}

void kvm_free(KvmAllocator *alloc, void *ptr, size_t size) {
    if (!alloc || !ptr || size == 0) return;

    int sc = size_class_index(size);
    size_t alloc_bytes = size;

    if (sc >= 0) {
        alloc_bytes = class_size(sc);
        KvmFreeNode *node = (KvmFreeNode *)ptr;
        node->next = alloc->free_lists[sc];
        alloc->free_lists[sc] = node;
    } else {
        free(ptr);
    }

    alloc->stats.frees++;
    if (alloc->stats.live_bytes >= alloc_bytes) {
        alloc->stats.live_bytes -= alloc_bytes;
    } else {
        alloc->stats.live_bytes = 0;
    }
}

void *kvm_realloc(KvmAllocator *alloc, void *ptr, size_t old_size, size_t new_size) {
    if (new_size == 0) {
        kvm_free(alloc, ptr, old_size);
        return NULL;
    }
    if (!ptr) {
        return kvm_alloc(alloc, new_size);
    }

    void *new_ptr = kvm_alloc(alloc, new_size);
    if (!new_ptr) return NULL;

    size_t copy_size = (old_size < new_size) ? old_size : new_size;
    memcpy(new_ptr, ptr, copy_size);
    kvm_free(alloc, ptr, old_size);

    return new_ptr;
}

KvmAllocStats kvm_allocator_get_stats(const KvmAllocator *alloc) {
    if (!alloc) {
        KvmAllocStats empty = {0, 0, 0, 0};
        return empty;
    }
    return alloc->stats;
}
