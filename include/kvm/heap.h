#ifndef KVM_HEAP_H
#define KVM_HEAP_H

#include "kvm/value.h"
#include "kvm/allocator.h"

typedef enum {
    KVM_KIND_STRING = 1,
    KVM_KIND_ARRAY,
    KVM_KIND_RECORD,
    KVM_KIND_BOX,
    KVM_KIND_RCBOX,
    KVM_KIND_NATIVE_HANDLE
} KvmObjectKind;

typedef struct KvmHeapHeader {
    uint8_t kind;
    uint8_t size_class;
    uint16_t flags;
    uint32_t generation;
    bool live;
} KvmHeapHeader;

typedef struct KvmHeapObject {
    KvmHeapHeader header;
} KvmHeapObject;

typedef struct KvmString {
    KvmHeapHeader header;
    size_t length;
    char data[];
} KvmString;

typedef struct KvmArray {
    KvmHeapHeader header;
    size_t capacity;
    size_t length;
    Value *items;
} KvmArray;

typedef struct KvmRecord {
    KvmHeapHeader header;
    uint32_t type_desc_id;
    size_t field_count;
    Value fields[];
} KvmRecord;

typedef struct KvmBox {
    KvmHeapHeader header;
    Value value;
} KvmBox;

typedef struct KvmRcBox {
    KvmHeapHeader header;
    int refcount;
    Value value;
} KvmRcBox;

typedef struct KvmNativeHandle {
    KvmHeapHeader header;
    void *handle;
    void (*dtor)(void *);
} KvmNativeHandle;

KvmString *kvm_string_create(KvmAllocator *alloc, const char *str, size_t len);
KvmArray *kvm_array_create(KvmAllocator *alloc, size_t initial_cap);
void kvm_array_set(KvmAllocator *alloc, KvmArray *arr, size_t idx, Value val);
KvmRecord *kvm_record_create(KvmAllocator *alloc, uint32_t type_desc_id, size_t field_count);
KvmBox *kvm_box_create(KvmAllocator *alloc, Value initial_val);
KvmRcBox *kvm_rcbox_create(KvmAllocator *alloc, Value initial_val);
KvmNativeHandle *kvm_native_handle_create(KvmAllocator *alloc, void *handle, void (*dtor)(void *));

void kvm_heap_obj_free(KvmAllocator *alloc, KvmHeapObject *obj);

#endif /* KVM_HEAP_H */
