#include "kvm/ownership.h"
#include <stdlib.h>

Value kvm_ownership_move(Value *src_reg) {
    if (!src_reg) return kvm_val_nil();
    Value val = *src_reg;
    *src_reg = kvm_val_nil();
    return val;
}

Value kvm_move(Value *src_reg) {
    return kvm_ownership_move(src_reg);
}

void kvm_ownership_drop(KvmAllocator *alloc, KvmHeapObject *obj) {
    if (!obj || !obj->header.live) return;

    obj->header.live = false;
    obj->header.generation++;

    switch ((KvmObjectKind)obj->header.kind) {
    case KVM_KIND_STRING: {
        KvmString *str = (KvmString *)obj;
        size_t total = sizeof(KvmString) + str->length + 1;
        if (alloc) kvm_free(alloc, str, total);
        else free(str);
        break;
    }
    case KVM_KIND_ARRAY: {
        KvmArray *arr = (KvmArray *)obj;
        if (arr->items) {
            for (size_t i = arr->length; i > 0; i--) {
                if (IS_POINTER(arr->items[i - 1])) {
                    kvm_ownership_drop(alloc, VALUE_TO_HEAP_OBJ(arr->items[i - 1]));
                }
            }
            if (arr->capacity > 0) {
                if (alloc) kvm_free(alloc, arr->items, sizeof(Value) * arr->capacity);
                else free(arr->items);
            }
        }
        if (alloc) kvm_free(alloc, arr, sizeof(KvmArray));
        else free(arr);
        break;
    }
    case KVM_KIND_RECORD: {
        KvmRecord *rec = (KvmRecord *)obj;
        for (size_t i = rec->field_count; i > 0; i--) {
            if (IS_POINTER(rec->fields[i - 1])) {
                kvm_ownership_drop(alloc, VALUE_TO_HEAP_OBJ(rec->fields[i - 1]));
            }
        }
        size_t total = sizeof(KvmRecord) + sizeof(Value) * rec->field_count;
        if (alloc) kvm_free(alloc, rec, total);
        else free(rec);
        break;
    }
    case KVM_KIND_BOX: {
        KvmBox *box = (KvmBox *)obj;
        if (IS_POINTER(box->value)) {
            kvm_ownership_drop(alloc, VALUE_TO_HEAP_OBJ(box->value));
        }
        if (alloc) kvm_free(alloc, box, sizeof(KvmBox));
        else free(box);
        break;
    }
    case KVM_KIND_RCBOX: {
        KvmRcBox *rcbox = (KvmRcBox *)obj;
        rcbox->refcount--;
        if (rcbox->refcount <= 0) {
            if (IS_POINTER(rcbox->value)) {
                kvm_ownership_drop(alloc, VALUE_TO_HEAP_OBJ(rcbox->value));
            }
            if (alloc) kvm_free(alloc, rcbox, sizeof(KvmRcBox));
            else free(rcbox);
        } else {
            obj->header.live = true;
        }
        break;
    }
    case KVM_KIND_NATIVE_HANDLE: {
        KvmNativeHandle *nh = (KvmNativeHandle *)obj;
        if (nh->dtor && nh->handle) {
            nh->dtor(nh->handle);
        }
        if (alloc) kvm_free(alloc, nh, sizeof(KvmNativeHandle));
        else free(nh);
        break;
    }
    }
}

void kvm_drop_value(KvmAllocator *alloc, Value *reg) {
    if (!reg) return;
    Value v = *reg;
    if (IS_POINTER(v)) {
        kvm_ownership_drop(alloc, VALUE_TO_HEAP_OBJ(v));
    }
    *reg = kvm_val_nil();
}

Value kvm_ownership_borrow(Value owner_val, bool is_mut) {
    if (!kvm_val_is_heap_obj(owner_val)) {
        return kvm_val_nil();
    }
    void *ptr = kvm_val_as_heap_obj(owner_val);
    return kvm_val_borrow(ptr, is_mut);
}

Value kvm_borrow(Value owner_val, bool is_mut) {
    return kvm_ownership_borrow(owner_val, is_mut);
}

void kvm_end_borrow(Value *borrow_reg) {
    if (!borrow_reg) return;
    *borrow_reg = kvm_val_nil();
}

Value kvm_copy_ref(Value ref_val) {
    if (!kvm_val_is_borrow(ref_val)) {
        return kvm_val_nil();
    }
    return ref_val;
}

KvmStatus kvm_check_borrow(Value ref_val) {
    if (!kvm_val_is_borrow(ref_val)) {
        return KVM_ERR_TYPE_ERROR;
    }
    KvmHeapObject *obj = (KvmHeapObject *)kvm_val_as_borrow(ref_val);
    if (!obj) {
        return KVM_ERR_STALE_BORROW;
    }
    if (!obj->header.live) {
        return KVM_ERR_STALE_BORROW;
    }
    return KVM_OK;
}

size_t kvm_frame_exit_sweep(KvmAllocator *alloc, Value *regs, size_t reg_count) {
    if (!regs) return 0;
    size_t swept = 0;
    for (size_t i = reg_count; i > 0; i--) {
        size_t idx = i - 1;
        if (kvm_val_is_heap_obj(regs[idx])) {
            kvm_ownership_drop(alloc, VALUE_TO_HEAP_OBJ(regs[idx]));
            regs[idx] = kvm_val_nil();
            swept++;
        } else {
            regs[idx] = kvm_val_nil();
        }
    }
    return swept;
}
