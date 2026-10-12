#include "kvm/vm.h"
#include "kvm/heap.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct KvmFrame {
    KvmFunction *fn;
    size_t pc;
    Value *regs;
    size_t reg_count;
} KvmFrame;

typedef struct KvmCallStack {
    KvmFrame *frames;
    size_t count;
    size_t capacity;
} KvmCallStack;

void kvm_callstack_init(KvmCallStack *cs) {
    cs->capacity = 16;
    cs->count = 0;
    cs->frames = calloc(cs->capacity, sizeof(KvmFrame));
}

void kvm_callstack_destroy(KvmCallStack *cs) {
    if (cs->frames) free(cs->frames);
    cs->frames = NULL;
    cs->count = 0;
    cs->capacity = 0;
}

KvmFrame *kvm_callstack_push(KvmCallStack *cs, KvmFunction *fn, Value *regs, size_t reg_count) {
    if (cs->count >= cs->capacity) {
        cs->capacity *= 2;
        cs->frames = realloc(cs->frames, cs->capacity * sizeof(KvmFrame));
    }
    KvmFrame *f = &cs->frames[cs->count++];
    f->fn = fn;
    f->pc = 0;
    f->regs = regs;
    f->reg_count = reg_count;
    return f;
}

void kvm_callstack_pop(KvmCallStack *cs) {
    if (cs->count > 0) {
        cs->count--;
    }
}
