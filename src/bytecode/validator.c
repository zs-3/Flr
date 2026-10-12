#include "kvm/bytecode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REG_UNINIT  0
#define REG_DEFINED 1
#define REG_MOVED   2

typedef struct {
    uint8_t *reg_states; /* [reg_count] */
    int *borrow_owner;   /* [reg_count] -> owner reg or -1 */
    int *borrow_type;    /* [reg_count] -> 0=none, 1=shared, 2=mut */
} BlockState;

static bool states_equal(const BlockState *a, const BlockState *b, size_t reg_count) {
    if (memcmp(a->reg_states, b->reg_states, reg_count) != 0) return false;
    if (memcmp(a->borrow_owner, b->borrow_owner, reg_count * sizeof(int)) != 0) return false;
    if (memcmp(a->borrow_type, b->borrow_type, reg_count * sizeof(int)) != 0) return false;
    return true;
}

static void merge_states(BlockState *dst, const BlockState *src, size_t reg_count) {
    for (size_t i = 0; i < reg_count; i++) {
        if (src->reg_states[i] == REG_UNINIT || dst->reg_states[i] == REG_UNINIT) {
            dst->reg_states[i] = REG_UNINIT;
        } else if (src->reg_states[i] == REG_MOVED || dst->reg_states[i] == REG_MOVED) {
            dst->reg_states[i] = REG_MOVED;
        } else {
            dst->reg_states[i] = REG_DEFINED;
        }

        if (src->borrow_type[i] != dst->borrow_type[i]) {
            dst->borrow_type[i] = 0;
            dst->borrow_owner[i] = -1;
        }
    }
}

static void copy_state(BlockState *dst, const BlockState *src, size_t reg_count) {
    memcpy(dst->reg_states, src->reg_states, reg_count);
    memcpy(dst->borrow_owner, src->borrow_owner, reg_count * sizeof(int));
    memcpy(dst->borrow_type, src->borrow_type, reg_count * sizeof(int));
}

static void report_error(char *err_msg, size_t cap, const char *fn_name, size_t pc, const char *reason) {
    if (err_msg && cap > 0) {
        snprintf(err_msg, cap, "Verifier error in '%s' at PC %zu: %s", fn_name ? fn_name : "<unknown>", pc, reason);
    }
}

KvmStatus kvm_bytecode_validate(const KvmBytecode *bc, char *err_msg, size_t err_msg_cap) {
    if (!bc) {
        if (err_msg) snprintf(err_msg, err_msg_cap, "Null bytecode structure");
        return KVM_ERR_VERIFIER_FAILURE;
    }

    if (bc->entry_func_idx >= bc->func_count) {
        if (err_msg) snprintf(err_msg, err_msg_cap, "Entry function index out of range");
        return KVM_ERR_VERIFIER_FAILURE;
    }

    for (size_t f = 0; f < bc->func_count; f++) {
        KvmFunction *fn = bc->functions[f];
        if (!fn) continue;

        bool has_return_or_trap = false;
        bool has_loophint = false;

        /* Basic structural checks */
        for (size_t pc = 0; pc < fn->code_count; pc++) {
            KvmInstruction inst = fn->code[pc];
            uint8_t op = KVM_OPCODE(inst);
            uint8_t ra = KVM_REG_A(inst);
            uint8_t rb = KVM_REG_B(inst);
            uint8_t rc = KVM_REG_C(inst);

            if (op == 0 || op >= OP_MAX_OPCODE) {
                report_error(err_msg, err_msg_cap, fn->name, pc, "Unknown opcode");
                return KVM_ERR_VERIFIER_FAILURE;
            }

            /* Register bounds check according to opcode operand format */
            if (op == OP_JMP || op == OP_LOOPHINT || op == OP_TRAP) {
                /* No register operands */
            } else if (op == OP_LOADK || op == OP_LOADI || op == OP_LOADNIL || op == OP_JMPIF || op == OP_JMPIFNOT || op == OP_DROP || op == OP_ENDBORROW) {
                if (ra >= fn->reg_count) {
                    report_error(err_msg, err_msg_cap, fn->name, pc, "Register index out of range");
                    return KVM_ERR_VERIFIER_FAILURE;
                }
            } else if (op == OP_JLT || op == OP_JLE || op == OP_JEQ || op == OP_JNLT || op == OP_JNLE || op == OP_JNEQ || op == OP_MOVE || op == OP_BORROW || op == OP_BORROWMUT || op == OP_COPYREF || op == OP_LOADBOOL) {
                if (ra >= fn->reg_count || rb >= fn->reg_count) {
                    report_error(err_msg, err_msg_cap, fn->name, pc, "Register index out of range");
                    return KVM_ERR_VERIFIER_FAILURE;
                }
            } else {
                if (ra >= fn->reg_count || rb >= fn->reg_count || rc >= fn->reg_count) {
                    report_error(err_msg, err_msg_cap, fn->name, pc, "Register index out of range");
                    return KVM_ERR_VERIFIER_FAILURE;
                }
            }

            if (op == OP_LOADK && KVM_IMM16(inst) >= fn->const_count) {
                report_error(err_msg, err_msg_cap, fn->name, pc, "Constant pool index out of range");
                return KVM_ERR_VERIFIER_FAILURE;
            }

            if (op == OP_FFICALL && KVM_REG_B(inst) >= bc->ffi_sig_count) {
                report_error(err_msg, err_msg_cap, fn->name, pc, "FFI signature index out of range");
                return KVM_ERR_VERIFIER_FAILURE;
            }

            if (op == OP_RETURN || op == OP_TRAP) {
                has_return_or_trap = true;
            }
            if (op == OP_LOOPHINT) {
                has_loophint = true;
            }

            /* Jump target bounds check */
            if (op == OP_JMP || op == OP_JMPIF || op == OP_JMPIFNOT) {
                int16_t offset = KVM_SIMM16(inst);
                int target = (int)pc + 1 + offset;
                if (target < 0 || target >= (int)fn->code_count) {
                    report_error(err_msg, err_msg_cap, fn->name, pc, "Jump target out of range");
                    return KVM_ERR_VERIFIER_FAILURE;
                }
            } else if (op == OP_JLT || op == OP_JLE || op == OP_JEQ ||
                       op == OP_JNLT || op == OP_JNLE || op == OP_JNEQ) {
                int8_t offset = (int8_t)rc;
                int target = (int)pc + 1 + offset;
                if (target < 0 || target >= (int)fn->code_count) {
                    report_error(err_msg, err_msg_cap, fn->name, pc, "Jump target out of range");
                    return KVM_ERR_VERIFIER_FAILURE;
                }
            }
        }

        if (!has_return_or_trap && !has_loophint) {
            report_error(err_msg, err_msg_cap, fn->name, fn->code_count, "Function has no reachable RETURN or TRAP");
            return KVM_ERR_VERIFIER_FAILURE;
        }

        /* Worklist Dataflow Analysis */
        size_t n_inst = fn->code_count;
        size_t n_regs = fn->reg_count;
        if (n_inst == 0) continue;

        BlockState *states = (BlockState *)calloc(n_inst, sizeof(BlockState));
        bool *visited = (bool *)calloc(n_inst, sizeof(bool));
        bool *in_worklist = (bool *)calloc(n_inst, sizeof(bool));
        size_t wl_cap = n_inst * 2 + 16;
        int *worklist = (int *)malloc(wl_cap * sizeof(int));
        int wl_head = 0, wl_tail = 0;

        for (size_t i = 0; i < n_inst; i++) {
            states[i].reg_states = (uint8_t *)calloc(n_regs, sizeof(uint8_t));
            states[i].borrow_owner = (int *)malloc(n_regs * sizeof(int));
            states[i].borrow_type = (int *)calloc(n_regs, sizeof(int));
            for (size_t r = 0; r < n_regs; r++) {
                states[i].borrow_owner[r] = -1;
            }
        }

        if (fn->arity > fn->reg_count) {
            report_error(err_msg, err_msg_cap, fn->name, 0, "Function arity exceeds register count");
            for (size_t i = 0; i < n_inst; i++) {
                free(states[i].reg_states); free(states[i].borrow_owner); free(states[i].borrow_type);
            }
            free(states); free(visited); free(in_worklist); free(worklist);
            return KVM_ERR_VERIFIER_FAILURE;
        }

        /* Entry function parameters (arity registers r0..rN-1) are pre-defined */
        for (size_t r = 0; r < fn->arity && r < fn->reg_count; r++) {
            states[0].reg_states[r] = REG_DEFINED;
        }

        worklist[wl_tail++] = 0;
        in_worklist[0] = true;
        visited[0] = true;

        while (wl_head < wl_tail) {
            int pc = worklist[wl_head++];
            in_worklist[pc] = false;

            BlockState cur;
            cur.reg_states = (uint8_t *)malloc(n_regs * sizeof(uint8_t));
            cur.borrow_owner = (int *)malloc(n_regs * sizeof(int));
            cur.borrow_type = (int *)malloc(n_regs * sizeof(int));

            memcpy(cur.reg_states, states[pc].reg_states, n_regs);
            memcpy(cur.borrow_owner, states[pc].borrow_owner, n_regs * sizeof(int));
            memcpy(cur.borrow_type, states[pc].borrow_type, n_regs * sizeof(int));

            KvmInstruction inst = fn->code[pc];
            uint8_t op = KVM_OPCODE(inst);
            uint8_t ra = KVM_REG_A(inst);
            uint8_t rb = KVM_REG_B(inst);
            uint8_t rc = KVM_REG_C(inst);

            if (op == OP_MOVE) {
                if (cur.reg_states[rb] != REG_DEFINED) {
                    report_error(err_msg, err_msg_cap, fn->name, pc, "Use of undefined or moved register in MOVE source");
                    free(cur.reg_states); free(cur.borrow_owner); free(cur.borrow_type);
                    for (size_t i = 0; i < n_inst; i++) {
                        free(states[i].reg_states); free(states[i].borrow_owner); free(states[i].borrow_type);
                    }
                    free(states); free(visited); free(in_worklist); free(worklist);
                    return KVM_ERR_VERIFIER_FAILURE;
                }
                for (size_t r = 0; r < n_regs; r++) {
                    if (cur.borrow_owner[r] == (int)rb && cur.borrow_type[r] > 0) {
                        report_error(err_msg, err_msg_cap, fn->name, pc, "Cannot MOVE register while borrowed");
                        free(cur.reg_states); free(cur.borrow_owner); free(cur.borrow_type);
                        for (size_t i = 0; i < n_inst; i++) {
                            free(states[i].reg_states); free(states[i].borrow_owner); free(states[i].borrow_type);
                        }
                        free(states); free(visited); free(in_worklist); free(worklist);
                        return KVM_ERR_VERIFIER_FAILURE;
                    }
                }
                cur.reg_states[ra] = REG_DEFINED;
                cur.reg_states[rb] = REG_MOVED;
            } else if (op == OP_DROP) {
                if (cur.reg_states[ra] != REG_DEFINED) {
                    report_error(err_msg, err_msg_cap, fn->name, pc, "DROP of undefined or already dropped register");
                    free(cur.reg_states); free(cur.borrow_owner); free(cur.borrow_type);
                    for (size_t i = 0; i < n_inst; i++) {
                        free(states[i].reg_states); free(states[i].borrow_owner); free(states[i].borrow_type);
                    }
                    free(states); free(visited); free(in_worklist); free(worklist);
                    return KVM_ERR_VERIFIER_FAILURE;
                }
                for (size_t r = 0; r < n_regs; r++) {
                    if (cur.borrow_owner[r] == (int)ra && cur.borrow_type[r] > 0) {
                        report_error(err_msg, err_msg_cap, fn->name, pc, "Borrow outlives owner before DROP");
                        free(cur.reg_states); free(cur.borrow_owner); free(cur.borrow_type);
                        for (size_t i = 0; i < n_inst; i++) {
                            free(states[i].reg_states); free(states[i].borrow_owner); free(states[i].borrow_type);
                        }
                        free(states); free(visited); free(in_worklist); free(worklist);
                        return KVM_ERR_VERIFIER_FAILURE;
                    }
                }
                cur.reg_states[ra] = REG_MOVED;
            } else if (op == OP_BORROWMUT) {
                if (cur.reg_states[rb] != REG_DEFINED) {
                    report_error(err_msg, err_msg_cap, fn->name, pc, "BORROWMUT of undefined register");
                    free(cur.reg_states); free(cur.borrow_owner); free(cur.borrow_type);
                    for (size_t i = 0; i < n_inst; i++) {
                        free(states[i].reg_states); free(states[i].borrow_owner); free(states[i].borrow_type);
                    }
                    free(states); free(visited); free(in_worklist); free(worklist);
                    return KVM_ERR_VERIFIER_FAILURE;
                }
                for (size_t r = 0; r < n_regs; r++) {
                    if (cur.borrow_owner[r] == (int)rb && cur.borrow_type[r] > 0) {
                        report_error(err_msg, err_msg_cap, fn->name, pc, "Two live exclusive borrows of the same owner at once");
                        free(cur.reg_states); free(cur.borrow_owner); free(cur.borrow_type);
                        for (size_t i = 0; i < n_inst; i++) {
                            free(states[i].reg_states); free(states[i].borrow_owner); free(states[i].borrow_type);
                        }
                        free(states); free(visited); free(in_worklist); free(worklist);
                        return KVM_ERR_VERIFIER_FAILURE;
                    }
                }
                cur.reg_states[ra] = REG_DEFINED;
                cur.borrow_owner[ra] = rb;
                cur.borrow_type[ra] = 2;
            } else if (op == OP_BORROW) {
                if (cur.reg_states[rb] != REG_DEFINED) {
                    report_error(err_msg, err_msg_cap, fn->name, pc, "BORROW of undefined register");
                    free(cur.reg_states); free(cur.borrow_owner); free(cur.borrow_type);
                    for (size_t i = 0; i < n_inst; i++) {
                        free(states[i].reg_states); free(states[i].borrow_owner); free(states[i].borrow_type);
                    }
                    free(states); free(visited); free(in_worklist); free(worklist);
                    return KVM_ERR_VERIFIER_FAILURE;
                }
                cur.reg_states[ra] = REG_DEFINED;
                cur.borrow_owner[ra] = rb;
                cur.borrow_type[ra] = 1;
            } else if (op == OP_ENDBORROW) {
                cur.borrow_owner[ra] = -1;
                cur.borrow_type[ra] = 0;
            } else {
                if (op == OP_LOADK || op == OP_LOADI || op == OP_LOADNIL || op == OP_LOADBOOL ||
                    op == OP_ADD || op == OP_SUB || op == OP_MUL || op == OP_DIV || op == OP_MOD || op == OP_NEG ||
                    op == OP_IADD || op == OP_ISUB || op == OP_IMUL || op == OP_IDIV || op == OP_IMOD || op == OP_INEG ||
                    op == OP_FADD || op == OP_FSUB || op == OP_FMUL || op == OP_FDIV || op == OP_FNEG ||
                    op == OP_EQ || op == OP_LT || op == OP_LE || op == OP_NOT ||
                    op == OP_NEWOBJ || op == OP_NEWARRAY || op == OP_GETFIELD || op == OP_GETINDEX ||
                    op == OP_CALL || op == OP_CALLNATIVE || op == OP_FFICALL || op == OP_COPYREF) {
                    cur.reg_states[ra] = REG_DEFINED;
                }
            }

            (void)rc;
            int succs[2];
            int num_succs = 0;

            if (op == OP_RETURN || op == OP_TRAP) {
                num_succs = 0;
            } else if (op == OP_JMP) {
                int target = pc + 1 + KVM_SIMM16(inst);
                succs[num_succs++] = target;
            } else if (op == OP_JMPIF || op == OP_JMPIFNOT ||
                       op == OP_JLT || op == OP_JLE || op == OP_JEQ ||
                       op == OP_JNLT || op == OP_JNLE || op == OP_JNEQ) {
                succs[num_succs++] = pc + 1;
                succs[num_succs++] = pc + 1 + KVM_SIMM16(inst);
            } else {
                succs[num_succs++] = pc + 1;
            }

            for (int s = 0; s < num_succs; s++) {
                int target = succs[s];
                if (target >= 0 && target < (int)n_inst) {
                    if (!visited[target]) {
                        visited[target] = true;
                        copy_state(&states[target], &cur, n_regs);
                        if (!in_worklist[target]) {
                            if ((size_t)wl_tail >= wl_cap) {
                                wl_cap *= 2;
                                worklist = (int *)realloc(worklist, wl_cap * sizeof(int));
                            }
                            worklist[wl_tail++] = target;
                            in_worklist[target] = true;
                        }
                    } else {
                        BlockState old_s = states[target];
                        merge_states(&states[target], &cur, n_regs);
                        if (!states_equal(&states[target], &old_s, n_regs) || !in_worklist[target]) {
                            if (!in_worklist[target]) {
                                if ((size_t)wl_tail >= wl_cap) {
                                    wl_cap *= 2;
                                    worklist = (int *)realloc(worklist, wl_cap * sizeof(int));
                                }
                                worklist[wl_tail++] = target;
                                in_worklist[target] = true;
                            }
                        }
                    }
                }
            }

            free(cur.reg_states);
            free(cur.borrow_owner);
            free(cur.borrow_type);
        }

        for (size_t i = 0; i < n_inst; i++) {
            free(states[i].reg_states);
            free(states[i].borrow_owner);
            free(states[i].borrow_type);
        }
        free(states);
        free(visited);
        free(in_worklist);
        free(worklist);
    }

    return KVM_OK;
}
