#include "kvm/bytecode.h"
#include "kvm/heap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
} Buffer;

static void buf_init(Buffer *b) {
    b->data = NULL;
    b->size = 0;
    b->capacity = 0;
}

static void buf_write_bytes(Buffer *b, const void *src, size_t len) {
    if (b->size + len > b->capacity) {
        size_t new_cap = b->capacity == 0 ? 128 : b->capacity * 2;
        while (new_cap < b->size + len) new_cap *= 2;
        b->data = (uint8_t *)realloc(b->data, new_cap);
        b->capacity = new_cap;
    }
    memcpy(b->data + b->size, src, len);
    b->size += len;
}

static void buf_write_u8(Buffer *b, uint8_t v) {
    buf_write_bytes(b, &v, 1);
}

static void buf_write_u16(Buffer *b, uint16_t v) {
    uint8_t bytes[2];
    bytes[0] = (uint8_t)(v & 0xFF);
    bytes[1] = (uint8_t)((v >> 8) & 0xFF);
    buf_write_bytes(b, bytes, 2);
}

static void buf_write_u32(Buffer *b, uint32_t v) {
    uint8_t bytes[4];
    bytes[0] = (uint8_t)(v & 0xFF);
    bytes[1] = (uint8_t)((v >> 8) & 0xFF);
    bytes[2] = (uint8_t)((v >> 16) & 0xFF);
    bytes[3] = (uint8_t)((v >> 24) & 0xFF);
    buf_write_bytes(b, bytes, 4);
}

static void buf_write_u64(Buffer *b, uint64_t v) {
    uint8_t bytes[8];
    for (int i = 0; i < 8; i++) {
        bytes[i] = (uint8_t)((v >> (i * 8)) & 0xFF);
    }
    buf_write_bytes(b, bytes, 8);
}

static void buf_write_str(Buffer *b, const char *s) {
    if (!s) {
        buf_write_u32(b, 0);
        return;
    }
    uint32_t len = (uint32_t)strlen(s);
    buf_write_u32(b, len);
    buf_write_bytes(b, s, len);
}

static void buf_write_value(Buffer *b, Value v) {
    if (kvm_val_is_int48(v)) {
        buf_write_u8(b, 1);
        buf_write_u64(b, (uint64_t)kvm_val_as_int48(v));
    } else if (kvm_val_is_double(v)) {
        buf_write_u8(b, 2);
        uint64_t raw;
        double d = kvm_val_as_double(v);
        memcpy(&raw, &d, sizeof(double));
        buf_write_u64(b, raw);
    } else if (kvm_val_is_nil(v)) {
        buf_write_u8(b, 0);
    } else if (kvm_val_is_bool(v)) {
        buf_write_u8(b, 3);
        buf_write_u8(b, kvm_val_as_bool(v) ? 1 : 0);
    } else if (kvm_val_is_heap_obj(v)) {
        KvmHeapObject *obj = (KvmHeapObject *)kvm_val_as_heap_obj(v);
        if (obj && obj->header.kind == KVM_KIND_STRING) {
            KvmString *str = (KvmString *)obj;
            buf_write_u8(b, 4);
            buf_write_u32(b, (uint32_t)str->length);
            buf_write_bytes(b, str->data, str->length);
        } else {
            buf_write_u8(b, 0);
        }
    } else {
        buf_write_u8(b, 0);
    }
}

KvmStatus kvm_bytecode_write_bytes(const KvmBytecode *bc, uint8_t **out_buf, size_t *out_size) {
    if (!bc || !out_buf || !out_size) return KVM_ERR_INVALID_ARGUMENT;

    Buffer b;
    buf_init(&b);

    /* Header */
    buf_write_u32(&b, bc->magic);
    buf_write_u16(&b, bc->version);
    buf_write_u16(&b, bc->flags);
    buf_write_u32(&b, bc->entry_func_idx);

    buf_write_u32(&b, (uint32_t)bc->const_count);
    buf_write_u32(&b, (uint32_t)bc->func_count);
    buf_write_u32(&b, (uint32_t)bc->ffi_sig_count);
    buf_write_u32(&b, (uint32_t)bc->type_desc_count);

    /* Constant pool */
    for (size_t i = 0; i < bc->const_count; i++) {
        buf_write_value(&b, bc->const_pool[i]);
    }

    /* FFI Sigs */
    for (size_t i = 0; i < bc->ffi_sig_count; i++) {
        buf_write_str(&b, bc->ffi_sigs[i].symbol_name);
        buf_write_str(&b, bc->ffi_sigs[i].sig_str);
    }

    /* Type descs */
    for (size_t i = 0; i < bc->type_desc_count; i++) {
        buf_write_str(&b, bc->type_descs[i].name);
        buf_write_u32(&b, (uint32_t)bc->type_descs[i].field_count);
        for (size_t j = 0; j < bc->type_descs[i].field_count; j++) {
            buf_write_str(&b, bc->type_descs[i].field_names[j]);
        }
    }

    /* Functions */
    for (size_t i = 0; i < bc->func_count; i++) {
        KvmFunction *fn = bc->functions[i];
        buf_write_str(&b, fn->name);
        buf_write_u16(&b, fn->arity);
        buf_write_u16(&b, fn->reg_count);

        buf_write_u32(&b, (uint32_t)fn->const_count);
        for (size_t j = 0; j < fn->const_count; j++) {
            buf_write_value(&b, fn->const_pool[j]);
        }

        buf_write_u32(&b, (uint32_t)fn->code_count);
        for (size_t j = 0; j < fn->code_count; j++) {
            buf_write_u32(&b, fn->code[j]);
        }

        buf_write_u32(&b, (uint32_t)fn->line_table_count);
        for (size_t j = 0; j < fn->line_table_count; j++) {
            buf_write_u32(&b, fn->line_table[j]);
        }
    }

    *out_buf = b.data;
    *out_size = b.size;
    return KVM_OK;
}

KvmStatus kvm_bytecode_write_file(const KvmBytecode *bc, const char *filepath) {
    uint8_t *buf = NULL;
    size_t size = 0;
    KvmStatus status = kvm_bytecode_write_bytes(bc, &buf, &size);
    if (status != KVM_OK) return status;

    FILE *f = fopen(filepath, "wb");
    if (!f) {
        free(buf);
        return KVM_ERR_FILE_IO;
    }

    size_t written = fwrite(buf, 1, size, f);
    fclose(f);
    free(buf);

    if (written != size) return KVM_ERR_FILE_IO;
    return KVM_OK;
}
