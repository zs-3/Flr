#include "kvm/bytecode.h"
#include "kvm/heap.h"
#include <stdio.h>
#include <stdlib.h>

void kvm_bytecode_disassemble(const KvmBytecode *bc, FILE *out) {
    if (!bc || !out) return;

    fprintf(out, "; === KVM Bytecode Disassembly ===\n");
    fprintf(out, "; Magic: 0x%08X Version: %u Flags: %u Entry: %u\n\n",
            bc->magic, bc->version, bc->flags, bc->entry_func_idx);

    for (size_t f = 0; f < bc->func_count; f++) {
        KvmFunction *fn = bc->functions[f];
        if (!fn) continue;

        fprintf(out, ".function \"%s\" arity=%u regs=%u\n",
                fn->name ? fn->name : "<anon>", fn->arity, fn->reg_count);

        for (size_t c = 0; c < fn->const_count; c++) {
            Value k = fn->const_pool[c];
            if (IS_INT48(k)) {
                fprintf(out, "  .const_int %ld\n", (long)VALUE_TO_INT48(k));
            } else if (IS_DOUBLE(k)) {
                fprintf(out, "  .const_double %f\n", VALUE_TO_DOUBLE(k));
            } else if (IS_POINTER(k)) {
                KvmHeapObject *obj = VALUE_TO_HEAP_OBJ(k);
                if (obj->header.kind == KVM_KIND_STRING) {
                    fprintf(out, "  .const_str \"%s\"\n", ((KvmString *)obj)->data);
                } else {
                    fprintf(out, "  .const_ptr %p\n", (void *)obj);
                }
            }
        }

        for (size_t pc = 0; pc < fn->code_count; pc++) {
            KvmInstruction inst = fn->code[pc];
            KvmOpcode op = KVM_OPCODE(inst);
            uint8_t a = KVM_REG_A(inst);
            uint8_t b = KVM_REG_B(inst);
            uint8_t c = KVM_REG_C(inst);
            uint16_t imm = KVM_IMM16(inst);
            int16_t simm = KVM_SIMM16(inst);

            fprintf(out, "  [%04zu] %-12s ", pc, kvm_opcode_name(op));

            if (op == OP_LOADI || op == OP_LOADK) {
                fprintf(out, "r%u, %d", a, (int)simm);
            } else if (op == OP_JMP || op == OP_JMPIF || op == OP_JMPIFNOT) {
                if (op != OP_JMP) fprintf(out, "r%u, ", a);
                int target = (int)pc + 1 + simm;
                fprintf(out, "%+d\t/* target pc %d */", simm, target);
            } else if (op == OP_JLT || op == OP_JLE || op == OP_JEQ ||
                       op == OP_JNLT || op == OP_JNLE || op == OP_JNEQ) {
                uint8_t cmp_a = KVM_CMP_REG_A(inst);
                uint8_t cmp_b = KVM_CMP_REG_B(inst);
                int16_t cmp_simm = KVM_CMP_SIMM16(inst);
                int target = (int)pc + 1 + cmp_simm;
                fprintf(out, "r%u, r%u, %+d\t/* target pc %d */", cmp_a, cmp_b, cmp_simm, target);
            } else if (op == OP_CALL || op == OP_TAILCALL) {
                fprintf(out, "r%u, func[r%u], base_args=r%u", a, b, b + 1);
            } else if (op == OP_RETURN) {
                if (b > 0) fprintf(out, "r%u", a);
            } else if (op == OP_DROP || op == OP_LOADNIL || op == OP_ENDBORROW) {
                fprintf(out, "r%u", a);
            } else {
                fprintf(out, "r%u, r%u, r%u (imm=%u)", a, b, c, imm);
            }

            /* Ownership annotations */
            if (op == OP_MOVE) {
                fprintf(out, "\t; [OWNERSHIP] transfer r%u -> r%u, clear r%u", b, a, b);
            } else if (op == OP_DROP) {
                fprintf(out, "\t; [OWNERSHIP] drop r%u, clear to nil", a);
            } else if (op == OP_BORROW) {
                fprintf(out, "\t; [OWNERSHIP] shared borrow r%u of r%u", a, b);
            } else if (op == OP_BORROWMUT) {
                fprintf(out, "\t; [OWNERSHIP] exclusive borrow r%u of r%u", a, b);
            }

            fprintf(out, "\n");
        }

        fprintf(out, ".end\n\n");
    }
}
