#include "kvm/bytecode.h"
#include "kvm/heap.h"
#include <stdio.h>
#include <inttypes.h>

static void print_value(Value v, FILE *out) {
    if (kvm_val_is_nil(v)) {
        fprintf(out, "nil");
    } else if (kvm_val_is_bool(v)) {
        fprintf(out, "%s", kvm_val_as_bool(v) ? "true" : "false");
    } else if (kvm_val_is_int48(v)) {
        fprintf(out, "%" PRId64, kvm_val_as_int48(v));
    } else if (kvm_val_is_double(v)) {
        fprintf(out, "%g", kvm_val_as_double(v));
    } else if (kvm_val_is_heap_obj(v)) {
        KvmHeapObject *obj = (KvmHeapObject *)kvm_val_as_heap_obj(v);
        if (obj && obj->header.kind == KVM_KIND_STRING) {
            KvmString *s = (KvmString *)obj;
            fprintf(out, "\"%s\"", s->data);
        } else {
            fprintf(out, "<heap_obj:%p>", (void*)obj);
        }
    } else {
        fprintf(out, "<val:0x%" PRIx64 ">", v);
    }
}

void kvm_bytecode_disassemble(const KvmBytecode *bc, FILE *out) {
    if (!bc || !out) return;

    fprintf(out, "; === KVM Bytecode Disassembly ===\n");
    fprintf(out, "; Magic: 0x%08X Version: %u Flags: %u Entry: %u\n\n",
            bc->magic, bc->version, bc->flags, bc->entry_func_idx);

    if (bc->ffi_sig_count > 0) {
        fprintf(out, "; --- FFI Signatures ---\n");
        for (size_t i = 0; i < bc->ffi_sig_count; i++) {
            fprintf(out, ".ffi_sig [%zu] %s \"%s\"\n", i,
                    bc->ffi_sigs[i].symbol_name ? bc->ffi_sigs[i].symbol_name : "",
                    bc->ffi_sigs[i].sig_str ? bc->ffi_sigs[i].sig_str : "");
        }
        fprintf(out, "\n");
    }

    if (bc->type_desc_count > 0) {
        fprintf(out, "; --- Type Descriptors ---\n");
        for (size_t i = 0; i < bc->type_desc_count; i++) {
            fprintf(out, ".type_desc [%zu] %s (fields: %zu)\n", i,
                    bc->type_descs[i].name ? bc->type_descs[i].name : "",
                    bc->type_descs[i].field_count);
        }
        fprintf(out, "\n");
    }

    if (bc->const_count > 0) {
        fprintf(out, "; --- Global Constant Pool ---\n");
        for (size_t i = 0; i < bc->const_count; i++) {
            fprintf(out, ".const [%zu] = ", i);
            print_value(bc->const_pool[i], out);
            fprintf(out, "\n");
        }
        fprintf(out, "\n");
    }

    for (size_t f = 0; f < bc->func_count; f++) {
        KvmFunction *fn = bc->functions[f];
        if (!fn) continue;

        fprintf(out, ".function \"%s\" arity=%u regs=%u\n",
                fn->name ? fn->name : "<anon>", fn->arity, fn->reg_count);

        if (fn->const_count > 0) {
            for (size_t i = 0; i < fn->const_count; i++) {
                fprintf(out, "  .const [%zu] = ", i);
                print_value(fn->const_pool[i], out);
                fprintf(out, "\n");
            }
        }

        for (size_t pc = 0; pc < fn->code_count; pc++) {
            KvmInstruction inst = fn->code[pc];
            uint8_t op = KVM_OPCODE(inst);
            uint8_t ra = KVM_REG_A(inst);
            uint8_t rb = KVM_REG_B(inst);
            uint8_t rc = KVM_REG_C(inst);
            uint16_t imm16 = KVM_IMM16(inst);
            int16_t simm16 = KVM_SIMM16(inst);

            fprintf(out, "  [%04zu] %-12s ", pc, kvm_opcode_name((KvmOpcode)op));

            if (op == OP_LOADK) {
                fprintf(out, "r%u, const[%u]", ra, imm16);
            } else if (op == OP_LOADI) {
                fprintf(out, "r%u, %d", ra, simm16);
            } else if (op == OP_LOADNIL) {
                fprintf(out, "r%u", ra);
            } else if (op == OP_LOADBOOL) {
                fprintf(out, "r%u, %s", ra, rb ? "true" : "false");
            } else if (op == OP_MOVE) {
                fprintf(out, "r%u, r%u\t/* owner r%u -> r%u (r%u cleared) */", ra, rb, rb, ra, rb);
            } else if (op == OP_DROP) {
                fprintf(out, "r%u\t/* drop owner r%u */", ra, ra);
            } else if (op == OP_BORROW || op == OP_BORROWMUT) {
                fprintf(out, "r%u, r%u\t/* borrow %s owner r%u -> r%u */",
                        ra, rb, op == OP_BORROWMUT ? "exclusive" : "shared", rb, ra);
            } else if (op == OP_ENDBORROW) {
                fprintf(out, "r%u\t/* end borrow r%u */", ra, ra);
            } else if (op == OP_JMP) {
                fprintf(out, "%+d\t/* target pc %d */", simm16, (int)pc + 1 + simm16);
            } else if (op == OP_JMPIF || op == OP_JMPIFNOT) {
                fprintf(out, "r%u, %+d\t/* target pc %d */", ra, simm16, (int)pc + 1 + simm16);
            } else if (op == OP_JLT || op == OP_JLE || op == OP_JEQ ||
                       op == OP_JNLT || op == OP_JNLE || op == OP_JNEQ) {
                fprintf(out, "r%u, r%u, %+d\t/* target pc %d */", ra, rb, simm16, (int)pc + 1 + simm16);
            } else if (op == OP_CALL || op == OP_CALLNATIVE || op == OP_FFICALL || op == OP_TAILCALL) {
                fprintf(out, "r%u, func[%u], base_args=r%u", ra, rb, rc);
            } else if (op == OP_RETURN) {
                if (rb) {
                    fprintf(out, "r%u", ra);
                } else {
                    fprintf(out, "nil");
                }
            } else {
                fprintf(out, "r%u, r%u, r%u", ra, rb, rc);
            }
            fprintf(out, "\n");
        }
        fprintf(out, ".end\n\n");
    }
}
