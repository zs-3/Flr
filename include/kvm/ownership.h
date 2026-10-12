#ifndef KVM_OWNERSHIP_H
#define KVM_OWNERSHIP_H

#include "kvm/value.h"
#include "kvm/heap.h"
#include "kvm/allocator.h"
#include "kvm/errors.h"

Value kvm_ownership_move(Value *src_reg);
void kvm_ownership_drop(KvmAllocator *alloc, KvmHeapObject *obj);

Value kvm_ownership_borrow(Value owner_val, bool is_mut);
void kvm_end_borrow(Value *borrow_reg);
Value kvm_copy_ref(Value ref_val);

KvmStatus kvm_check_borrow(Value ref_val);

size_t kvm_frame_exit_sweep(KvmAllocator *alloc, Value *regs, size_t reg_count);

#endif /* KVM_OWNERSHIP_H */
