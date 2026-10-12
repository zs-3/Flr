#include "kvm/heap.h"
#include <stdlib.h>
#include <string.h>

KvmString *kvm_string_create(KvmAllocator *alloc, const char *str, size_t len) {
    size_t total = sizeof(KvmString) + len + 1;
    KvmString *s = alloc ? (KvmString *)kvm_alloc(alloc, total) : (KvmString *)calloc(1, total);
    if (!s) return NULL;

    s->header.kind = KVM_KIND_STRING;
    s->header.size_class = 0xFF;
    s->header.flags = 0;
    s->header.generation = 1;
    s->header.live = true;

    s->length = len;
    if (str && len > 0) {
        memcpy(s->data, str, len);
    }
    s->data[len] = '\0';
    return s;
}

KvmArray *kvm_array_create(KvmAllocator *alloc, size_t initial_cap) {
    KvmArray *arr = alloc ? (KvmArray *)kvm_alloc(alloc, sizeof(KvmArray)) : (KvmArray *)calloc(1, sizeof(KvmArray));
    if (!arr) return NULL;

    arr->header.kind = KVM_KIND_ARRAY;
    arr->header.size_class = 0xFF;
    arr->header.flags = 0;
    arr->header.generation = 1;
    arr->header.live = true;

    arr->capacity = initial_cap;
    arr->length = 0;
    arr->items = NULL;

    if (initial_cap > 0) {
        arr->items = alloc ? (Value *)kvm_alloc(alloc, sizeof(Value) * initial_cap) : (Value *)calloc(initial_cap, sizeof(Value));
        if (!arr->items) {
            if (alloc) kvm_free(alloc, arr, sizeof(KvmArray));
            else free(arr);
            return NULL;
        }
        for (size_t i = 0; i < initial_cap; i++) {
            arr->items[i] = kvm_val_nil();
        }
    }
    return arr;
}

void kvm_array_set(KvmAllocator *alloc, KvmArray *arr, size_t idx, Value val) {
    if (!arr) return;
    if (idx >= arr->capacity) {
        size_t new_cap = (idx + 1) * 2;
        Value *new_items = alloc ? (Value *)kvm_alloc(alloc, sizeof(Value) * new_cap) : (Value *)calloc(new_cap, sizeof(Value));
        if (arr->items) {
            memcpy(new_items, arr->items, sizeof(Value) * arr->length);
            if (alloc) kvm_free(alloc, arr->items, sizeof(Value) * arr->capacity);
            else free(arr->items);
        }
        for (size_t i = arr->length; i < new_cap; i++) {
            new_items[i] = kvm_val_nil();
        }
        arr->items = new_items;
        arr->capacity = new_cap;
    }
    arr->items[idx] = val;
    if (idx + 1 > arr->length) {
        arr->length = idx + 1;
    }
}

KvmRecord *kvm_record_create(KvmAllocator *alloc, uint32_t type_desc_id, size_t field_count) {
    size_t total = sizeof(KvmRecord) + sizeof(Value) * field_count;
    KvmRecord *rec = alloc ? (KvmRecord *)kvm_alloc(alloc, total) : (KvmRecord *)calloc(1, total);
    if (!rec) return NULL;

    rec->header.kind = KVM_KIND_RECORD;
    rec->header.size_class = 0xFF;
    rec->header.flags = 0;
    rec->header.generation = 1;
    rec->header.live = true;

    rec->type_desc_id = type_desc_id;
    rec->field_count = field_count;
    for (size_t i = 0; i < field_count; i++) {
        rec->fields[i] = kvm_val_nil();
    }
    return rec;
}

KvmBox *kvm_box_create(KvmAllocator *alloc, Value initial_val) {
    KvmBox *box = alloc ? (KvmBox *)kvm_alloc(alloc, sizeof(KvmBox)) : (KvmBox *)calloc(1, sizeof(KvmBox));
    if (!box) return NULL;

    box->header.kind = KVM_KIND_BOX;
    box->header.size_class = 0xFF;
    box->header.flags = 0;
    box->header.generation = 1;
    box->header.live = true;

    box->value = initial_val;
    return box;
}

KvmRcBox *kvm_rcbox_create(KvmAllocator *alloc, Value initial_val) {
    KvmRcBox *rcbox = alloc ? (KvmRcBox *)kvm_alloc(alloc, sizeof(KvmRcBox)) : (KvmRcBox *)calloc(1, sizeof(KvmRcBox));
    if (!rcbox) return NULL;

    rcbox->header.kind = KVM_KIND_RCBOX;
    rcbox->header.size_class = 0xFF;
    rcbox->header.flags = 0;
    rcbox->header.generation = 1;
    rcbox->header.live = true;

    rcbox->refcount = 1;
    rcbox->value = initial_val;
    return rcbox;
}

KvmNativeHandle *kvm_native_handle_create(KvmAllocator *alloc, void *handle, void (*dtor)(void *)) {
    KvmNativeHandle *nh = alloc ? (KvmNativeHandle *)kvm_alloc(alloc, sizeof(KvmNativeHandle)) : (KvmNativeHandle *)calloc(1, sizeof(KvmNativeHandle));
    if (!nh) return NULL;

    nh->header.kind = KVM_KIND_NATIVE_HANDLE;
    nh->header.size_class = 0xFF;
    nh->header.flags = 0;
    nh->header.generation = 1;
    nh->header.live = true;

    nh->handle = handle;
    nh->dtor = dtor;
    return nh;
}
