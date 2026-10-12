#include "kvm/bytecode.h"
#include "kvm/heap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} Reader;

static bool read_bytes(Reader *r, void *dst, size_t len) {
    if (r->offset + len > r->size) return false;
    memcpy(dst, r->data + r->offset, len);
    r->offset += len;
    return true;
}

static bool read_u8(Reader *r, uint8_t *v) {
    return read_bytes(r, v, 1);
}

static bool read_u16(Reader *r, uint16_t *v) {
    uint8_t bytes[2];
    if (!read_bytes(r, bytes, 2)) return false;
    *v = (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
    return true;
}

static bool read_u32(Reader *r, uint32_t *v) {
    uint8_t bytes[4];
    if (!read_bytes(r, bytes, 4)) return false;
    *v = (uint32_t)bytes[0] |
         ((uint32_t)bytes[1] << 8) |
         ((uint32_t)bytes[2] << 16) |
         ((uint32_t)bytes[3] << 24);
    return true;
}

static bool read_u64(Reader *r, uint64_t *v) {
    uint8_t bytes[8];
    if (!read_bytes(r, bytes, 8)) return false;
    uint64_t res = 0;
    for (int i = 0; i < 8; i++) {
        res |= ((uint64_t)bytes[i] << (i * 8));
    }
    *v = res;
    return true;
}

static bool read_str(Reader *r, char **out_str) {
    uint32_t len = 0;
    if (!read_u32(r, &len)) return false;
    if (len > 1000000) return false; /* Sanity cap */
    if (r->offset + len > r->size) return false;

    char *s = (char *)malloc(len + 1);
    if (!s) return false;
    if (len > 0) {
        memcpy(s, r->data + r->offset, len);
        r->offset += len;
    }
    s[len] = '\0';
    *out_str = s;
    return true;
}

static bool read_value(Reader *r, KvmAllocator *alloc, Value *v) {
    uint8_t tag = 0;
    if (!read_u8(r, &tag)) return false;

    if (tag == 0) {
        *v = kvm_val_nil();
    } else if (tag == 1) { /* Int48 */
        uint64_t raw = 0;
        if (!read_u64(r, &raw)) return false;
        *v = kvm_val_int48((int64_t)raw);
    } else if (tag == 2) { /* Double */
        uint64_t raw = 0;
        if (!read_u64(r, &raw)) return false;
        double d;
        memcpy(&d, &raw, sizeof(double));
        *v = kvm_val_double(d);
    } else if (tag == 3) { /* Bool */
        uint8_t b = 0;
        if (!read_u8(r, &b)) return false;
        *v = kvm_val_bool(b != 0);
    } else if (tag == 4) { /* String */
        uint32_t len = 0;
        if (!read_u32(r, &len)) return false;
        if (len > 1000000) return false;
        if (r->offset + len > r->size) return false;

        const char *data_ptr = (const char *)(r->data + r->offset);
        r->offset += len;

        KvmString *str = kvm_string_create(alloc, data_ptr, len);
        if (!str) return false;
        *v = kvm_val_heap_obj(str);
    } else {
        return false;
    }
    return true;
}

KvmStatus kvm_bytecode_read_bytes(const uint8_t *buf, size_t size, KvmBytecode **out_bc) {
    if (!buf || size == 0 || !out_bc) return KVM_ERR_INVALID_ARGUMENT;

    Reader r;
    r.data = buf;
    r.size = size;
    r.offset = 0;

    KvmBytecode *bc = kvm_bytecode_create();
    if (!bc) return KVM_ERR_OUT_OF_MEMORY;

    if (!read_u32(&r, &bc->magic) || bc->magic != KVM_BYTECODE_MAGIC) {
        kvm_bytecode_destroy(NULL, bc);
        return KVM_ERR_CORRUPT_BYTECODE;
    }

    if (!read_u16(&r, &bc->version) || bc->version != KVM_BYTECODE_VERSION) {
        kvm_bytecode_destroy(NULL, bc);
        return KVM_ERR_CORRUPT_BYTECODE;
    }

    if (!read_u16(&r, &bc->flags)) {
        kvm_bytecode_destroy(NULL, bc);
        return KVM_ERR_CORRUPT_BYTECODE;
    }

    if (!read_u32(&r, &bc->entry_func_idx)) {
        kvm_bytecode_destroy(NULL, bc);
        return KVM_ERR_CORRUPT_BYTECODE;
    }

    uint32_t const_count = 0, func_count = 0, ffi_sig_count = 0, type_desc_count = 0;
    if (!read_u32(&r, &const_count) ||
        !read_u32(&r, &func_count) ||
        !read_u32(&r, &ffi_sig_count) ||
        !read_u32(&r, &type_desc_count)) {
        kvm_bytecode_destroy(NULL, bc);
        return KVM_ERR_CORRUPT_BYTECODE;
    }

    if (const_count > 100000 || func_count > 100000 || ffi_sig_count > 10000 || type_desc_count > 10000) {
        kvm_bytecode_destroy(NULL, bc);
        return KVM_ERR_CORRUPT_BYTECODE;
    }

    /* Global Const Pool */
    if (const_count > 0) {
        bc->const_pool = (Value *)calloc(const_count, sizeof(Value));
        if (!bc->const_pool) {
            kvm_bytecode_destroy(NULL, bc);
            return KVM_ERR_OUT_OF_MEMORY;
        }
        bc->const_count = const_count;
        for (size_t i = 0; i < const_count; i++) {
            if (!read_value(&r, NULL, &bc->const_pool[i])) {
                kvm_bytecode_destroy(NULL, bc);
                return KVM_ERR_CORRUPT_BYTECODE;
            }
        }
    }

    /* FFI Sigs */
    if (ffi_sig_count > 0) {
        bc->ffi_sigs = (KvmFfiSig *)calloc(ffi_sig_count, sizeof(KvmFfiSig));
        if (!bc->ffi_sigs) {
            kvm_bytecode_destroy(NULL, bc);
            return KVM_ERR_OUT_OF_MEMORY;
        }
        bc->ffi_sig_count = ffi_sig_count;
        for (size_t i = 0; i < ffi_sig_count; i++) {
            if (!read_str(&r, &bc->ffi_sigs[i].symbol_name) ||
                !read_str(&r, &bc->ffi_sigs[i].sig_str)) {
                kvm_bytecode_destroy(NULL, bc);
                return KVM_ERR_CORRUPT_BYTECODE;
            }
        }
    }

    /* Type Descs */
    if (type_desc_count > 0) {
        bc->type_descs = (KvmTypeDesc *)calloc(type_desc_count, sizeof(KvmTypeDesc));
        if (!bc->type_descs) {
            kvm_bytecode_destroy(NULL, bc);
            return KVM_ERR_OUT_OF_MEMORY;
        }
        bc->type_desc_count = type_desc_count;
        for (size_t i = 0; i < type_desc_count; i++) {
            if (!read_str(&r, &bc->type_descs[i].name)) {
                kvm_bytecode_destroy(NULL, bc);
                return KVM_ERR_CORRUPT_BYTECODE;
            }
            uint32_t fc = 0;
            if (!read_u32(&r, &fc) || fc > 10000) {
                kvm_bytecode_destroy(NULL, bc);
                return KVM_ERR_CORRUPT_BYTECODE;
            }
            bc->type_descs[i].field_count = fc;
            if (fc > 0) {
                bc->type_descs[i].field_names = (char **)calloc(fc, sizeof(char *));
                if (!bc->type_descs[i].field_names) {
                    kvm_bytecode_destroy(NULL, bc);
                    return KVM_ERR_OUT_OF_MEMORY;
                }
                for (size_t j = 0; j < fc; j++) {
                    if (!read_str(&r, &bc->type_descs[i].field_names[j])) {
                        kvm_bytecode_destroy(NULL, bc);
                        return KVM_ERR_CORRUPT_BYTECODE;
                    }
                }
            }
        }
    }

    /* Functions */
    if (func_count > 0) {
        bc->functions = (KvmFunction **)calloc(func_count, sizeof(KvmFunction *));
        if (!bc->functions) {
            kvm_bytecode_destroy(NULL, bc);
            return KVM_ERR_OUT_OF_MEMORY;
        }
        bc->func_count = func_count;

        for (size_t i = 0; i < func_count; i++) {
            char *fn_name = NULL;
            uint16_t arity = 0, reg_count = 0;
            if (!read_str(&r, &fn_name) || !read_u16(&r, &arity) || !read_u16(&r, &reg_count)) {
                if (fn_name) free(fn_name);
                kvm_bytecode_destroy(NULL, bc);
                return KVM_ERR_CORRUPT_BYTECODE;
            }

            KvmFunction *fn = kvm_function_create(fn_name, arity, reg_count);
            free(fn_name);
            if (!fn) {
                kvm_bytecode_destroy(NULL, bc);
                return KVM_ERR_OUT_OF_MEMORY;
            }
            bc->functions[i] = fn;

            uint32_t fn_const_count = 0;
            if (!read_u32(&r, &fn_const_count) || fn_const_count > 100000) {
                kvm_bytecode_destroy(NULL, bc);
                return KVM_ERR_CORRUPT_BYTECODE;
            }
            if (fn_const_count > 0) {
                fn->const_pool = (Value *)calloc(fn_const_count, sizeof(Value));
                if (!fn->const_pool) {
                    kvm_bytecode_destroy(NULL, bc);
                    return KVM_ERR_OUT_OF_MEMORY;
                }
                fn->const_count = fn_const_count;
                for (size_t j = 0; j < fn_const_count; j++) {
                    if (!read_value(&r, NULL, &fn->const_pool[j])) {
                        kvm_bytecode_destroy(NULL, bc);
                        return KVM_ERR_CORRUPT_BYTECODE;
                    }
                }
            }

            uint32_t code_count = 0;
            if (!read_u32(&r, &code_count) || code_count > 1000000) {
                kvm_bytecode_destroy(NULL, bc);
                return KVM_ERR_CORRUPT_BYTECODE;
            }
            if (code_count > 0) {
                fn->code = (KvmInstruction *)calloc(code_count, sizeof(KvmInstruction));
                if (!fn->code) {
                    kvm_bytecode_destroy(NULL, bc);
                    return KVM_ERR_OUT_OF_MEMORY;
                }
                fn->code_count = code_count;
                for (size_t j = 0; j < code_count; j++) {
                    if (!read_u32(&r, &fn->code[j])) {
                        kvm_bytecode_destroy(NULL, bc);
                        return KVM_ERR_CORRUPT_BYTECODE;
                    }
                    if (KVM_OPCODE(fn->code[j]) == OP_LOOPHINT) {
                        fn->loop_count++;
                    }
                }
                if (fn->loop_count > 0) {
                    fn->loop_counters = (uint32_t *)calloc(fn->loop_count, sizeof(uint32_t));
                }
            }

            uint32_t line_count = 0;
            if (!read_u32(&r, &line_count) || line_count > 1000000) {
                kvm_bytecode_destroy(NULL, bc);
                return KVM_ERR_CORRUPT_BYTECODE;
            }
            if (line_count > 0) {
                fn->line_table = (uint32_t *)calloc(line_count, sizeof(uint32_t));
                if (!fn->line_table) {
                    kvm_bytecode_destroy(NULL, bc);
                    return KVM_ERR_OUT_OF_MEMORY;
                }
                fn->line_table_count = line_count;
                for (size_t j = 0; j < line_count; j++) {
                    if (!read_u32(&r, &fn->line_table[j])) {
                        kvm_bytecode_destroy(NULL, bc);
                        return KVM_ERR_CORRUPT_BYTECODE;
                    }
                }
            }
        }
    }

    *out_bc = bc;
    return KVM_OK;
}

KvmStatus kvm_bytecode_read_file(const char *filepath, KvmBytecode **out_bc) {
    if (!filepath || !out_bc) return KVM_ERR_INVALID_ARGUMENT;

    FILE *f = fopen(filepath, "rb");
    if (!f) return KVM_ERR_FILE_IO;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0 || sz > 100000000) {
        fclose(f);
        return KVM_ERR_CORRUPT_BYTECODE;
    }

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return KVM_ERR_OUT_OF_MEMORY;
    }

    size_t read_bytes = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    if (read_bytes != (size_t)sz) {
        free(buf);
        return KVM_ERR_FILE_IO;
    }

    KvmStatus status = kvm_bytecode_read_bytes(buf, (size_t)sz, out_bc);
    free(buf);
    return status;
}
