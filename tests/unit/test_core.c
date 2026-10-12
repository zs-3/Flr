#include "kvm/value.h"
#include "kvm/allocator.h"
#include "kvm/heap.h"
#include "kvm/ownership.h"
#include <assert.h>
#include <stdio.h>
#include <math.h>

void test_value_encoding(void) {
    /* Double */
    Value v1 = kvm_val_double(3.14159);
    assert(kvm_val_is_double(v1));
    assert(fabs(kvm_val_as_double(v1) - 3.14159) < 1e-6);

    /* Nil */
    Value vn = kvm_val_nil();
    assert(kvm_val_is_nil(vn));

    /* Bool */
    Value vb1 = kvm_val_bool(true);
    Value vb2 = kvm_val_bool(false);
    assert(kvm_val_is_bool(vb1) && kvm_val_as_bool(vb1) == true);
    assert(kvm_val_is_bool(vb2) && kvm_val_as_bool(vb2) == false);

    /* Int48 */
    int64_t num1 = 123456789012LL;
    int64_t num2 = -123456789012LL;
    Value vi1 = kvm_val_int48(num1);
    Value vi2 = kvm_val_int48(num2);
    assert(kvm_val_is_int48(vi1) && kvm_val_as_int48(vi1) == num1);
    assert(kvm_val_is_int48(vi2) && kvm_val_as_int48(vi2) == num2);

    /* Int48 max / min limits */
    Value vmax = kvm_val_int48(KVM_INT48_MAX);
    Value vmin = kvm_val_int48(KVM_INT48_MIN);
    assert(kvm_val_as_int48(vmax) == KVM_INT48_MAX);
    assert(kvm_val_as_int48(vmin) == KVM_INT48_MIN);

    printf("  [PASS] test_value_encoding\n");
}

void test_allocator(void) {
    KvmAllocator alloc;
    kvm_allocator_init(&alloc);

    void *p16 = kvm_alloc(&alloc, 10);
    void *p32 = kvm_alloc(&alloc, 30);
    void *p64 = kvm_alloc(&alloc, 50);
    void *p128 = kvm_alloc(&alloc, 100);
    void *p256 = kvm_alloc(&alloc, 200);
    void *p1k = kvm_alloc(&alloc, 1024);

    KvmAllocStats stats = kvm_allocator_get_stats(&alloc);
    assert(stats.allocations == 6);
    assert(stats.live_bytes > 0);

    kvm_free(&alloc, p16, 10);
    kvm_free(&alloc, p32, 30);
    kvm_free(&alloc, p64, 50);
    kvm_free(&alloc, p128, 100);
    kvm_free(&alloc, p256, 200);
    kvm_free(&alloc, p1k, 1024);

    stats = kvm_allocator_get_stats(&alloc);
    assert(stats.frees == 6);
    assert(stats.live_bytes == 0);

    kvm_allocator_destroy(&alloc);
    printf("  [PASS] test_allocator\n");
}

static void my_native_dtor(void *ptr) {
    (void)ptr;
}

void test_ownership(void) {
    KvmAllocator alloc;
    kvm_allocator_init(&alloc);

    /* String */
    KvmString *str = kvm_string_create(&alloc, "hello kvm", 9);
    Value vstr = kvm_val_heap_obj(str);
    assert(kvm_val_is_heap_obj(vstr));

    /* Borrow & check */
    Value bref = kvm_ownership_borrow(vstr, false);
    assert(kvm_check_borrow(bref) == KVM_OK);

    /* Move */
    Value vstr_moved = kvm_ownership_move(&vstr);
    assert(kvm_val_is_nil(vstr));
    assert(kvm_val_is_heap_obj(vstr_moved));

    /* Drop */
    if (IS_POINTER(vstr_moved)) {
        kvm_ownership_drop(&alloc, VALUE_TO_HEAP_OBJ(vstr_moved));
        vstr_moved = NIL_VAL;
    }
    assert(kvm_val_is_nil(vstr_moved));

    /* Stale borrow check */
    assert(kvm_check_borrow(bref) == KVM_ERR_STALE_BORROW);

    /* Array */
    KvmArray *arr = kvm_array_create(&alloc, 4);
    Value varr = kvm_val_heap_obj(arr);
    arr->items[0] = kvm_val_heap_obj(kvm_string_create(&alloc, "item0", 5));
    arr->length = 1;
    if (IS_POINTER(varr)) {
        kvm_ownership_drop(&alloc, VALUE_TO_HEAP_OBJ(varr));
        varr = NIL_VAL;
    }

    /* Native handle */
    int dummy_res = 42;
    KvmNativeHandle *nh = kvm_native_handle_create(&alloc, &dummy_res, my_native_dtor);
    Value vnh = kvm_val_heap_obj(nh);
    if (IS_POINTER(vnh)) {
        kvm_ownership_drop(&alloc, VALUE_TO_HEAP_OBJ(vnh));
        vnh = NIL_VAL;
    }

    KvmAllocStats stats = kvm_allocator_get_stats(&alloc);
    assert(stats.live_bytes == 0);

    kvm_allocator_destroy(&alloc);
    printf("  [PASS] test_ownership\n");
}

void run_core_tests(void) {
    printf("Running Core Tests...\n");
    test_value_encoding();
    test_allocator();
    test_ownership();
}
