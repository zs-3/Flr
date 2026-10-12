#include "kvm/bytecode.h"
#include "kvm/heap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    char name[64];
    int pc;
} Label;

typedef struct {
    char name[64];
    int instruction_index;
    int line;
    int col;
} LabelRef;

static void report_asm_err(char *err_msg, size_t err_cap, int line, int col, const char *msg) {
    if (err_msg && err_cap > 0) {
        snprintf(err_msg, err_cap, "Assembler error at line %d, col %d: %s", line, col, msg);
    }
}

static const char *skip_space_and_comments(const char *p, int *line, int *col) {
    while (*p) {
        if (*p == ';') {
            while (*p && *p != '\n') { p++; (*col)++; }
        } else if (isspace((unsigned char)*p)) {
            if (*p == '\n') { (*line)++; *col = 1; }
            else { (*col)++; }
            p++;
        } else {
            break;
        }
    }
    return p;
}

static bool parse_reg(const char **pp, uint8_t *reg, int *col) {
    const char *p = *pp;
    if (*p != 'r' && *p != 'R') return false;
    p++; (*col)++;
    if (!isdigit((unsigned char)*p)) return false;
    int num = 0;
    while (isdigit((unsigned char)*p)) {
        num = num * 10 + (*p - '0');
        p++; (*col)++;
    }
    if (num < 0 || num > 255) return false;
    *reg = (uint8_t)num;
    *pp = p;
    return true;
}

static bool parse_int(const char **pp, int *val, int *col) {
    const char *p = *pp;
    int sign = 1;
    if (*p == '-') { sign = -1; p++; (*col)++; }
    else if (*p == '+') { p++; (*col)++; }
    if (!isdigit((unsigned char)*p)) return false;
    int num = 0;
    while (isdigit((unsigned char)*p)) {
        num = num * 10 + (*p - '0');
        p++; (*col)++;
    }
    *val = num * sign;
    *pp = p;
    return true;
}

static bool parse_string_lit(const char **pp, char *dst, size_t max_cap, int *col) {
    const char *p = *pp;
    if (*p != '"') return false;
    p++; (*col)++;
    size_t len = 0;
    while (*p && *p != '"') {
        if (*p == '\\' && *(p + 1)) {
            p++; (*col)++;
            if (*p == 'n') dst[len++] = '\n';
            else if (*p == 't') dst[len++] = '\t';
            else if (*p == '"') dst[len++] = '"';
            else if (*p == '\\') dst[len++] = '\\';
            else dst[len++] = *p;
        } else {
            dst[len++] = *p;
        }
        if (len >= max_cap - 1) return false;
        p++; (*col)++;
    }
    if (*p != '"') return false;
    p++; (*col)++;
    dst[len] = '\0';
    *pp = p;
    return true;
}

KvmStatus kvm_bytecode_assemble(const char *source, KvmBytecode **out_bc, char *err_msg, size_t err_cap) {
    if (!source || !out_bc) return KVM_ERR_INVALID_ARGUMENT;

    KvmBytecode *bc = kvm_bytecode_create();
    if (!bc) return KVM_ERR_OUT_OF_MEMORY;

    int line = 1, col = 1;
    const char *p = source;

    KvmFunction *cur_fn = NULL;
    Label labels[128];
    int num_labels = 0;
    LabelRef label_refs[128];
    int num_refs = 0;

    while (*p) {
        p = skip_space_and_comments(p, &line, &col);
        if (!*p) break;

        /* Check for directive or opcode or label */
        if (*p == '.') {
            char dir[64];
            int i = 0;
            while (*p && !isspace((unsigned char)*p) && i < 63) {
                dir[i++] = *p++; col++;
            }
            dir[i] = '\0';

            if (strcmp(dir, ".ffi_sig") == 0) {
                p = skip_space_and_comments(p, &line, &col);
                char sym[64], sig[64];
                if (!parse_string_lit(&p, sym, sizeof(sym), &col)) {
                    report_asm_err(err_msg, err_cap, line, col, "Expected symbol string in .ffi_sig");
                    kvm_bytecode_destroy(NULL, bc); return KVM_ERR_CORRUPT_BYTECODE;
                }
                p = skip_space_and_comments(p, &line, &col);
                if (!parse_string_lit(&p, sig, sizeof(sig), &col)) {
                    report_asm_err(err_msg, err_cap, line, col, "Expected signature string in .ffi_sig");
                    kvm_bytecode_destroy(NULL, bc); return KVM_ERR_CORRUPT_BYTECODE;
                }
                bc->ffi_sig_count++;
                bc->ffi_sigs = (KvmFfiSig *)realloc(bc->ffi_sigs, sizeof(KvmFfiSig) * bc->ffi_sig_count);
                bc->ffi_sigs[bc->ffi_sig_count - 1].symbol_name = strdup(sym);
                bc->ffi_sigs[bc->ffi_sig_count - 1].sig_str = strdup(sig);
            } else if (strcmp(dir, ".type_desc") == 0) {
                p = skip_space_and_comments(p, &line, &col);
                char tname[64];
                if (!parse_string_lit(&p, tname, sizeof(tname), &col)) {
                    report_asm_err(err_msg, err_cap, line, col, "Expected type name in .type_desc");
                    kvm_bytecode_destroy(NULL, bc); return KVM_ERR_CORRUPT_BYTECODE;
                }
                bc->type_desc_count++;
                bc->type_descs = (KvmTypeDesc *)realloc(bc->type_descs, sizeof(KvmTypeDesc) * bc->type_desc_count);
                KvmTypeDesc *td = &bc->type_descs[bc->type_desc_count - 1];
                td->name = strdup(tname);
                td->field_count = 0;
                td->field_names = NULL;

                while (true) {
                    const char *saved = p;
                    int sline = line, scol = col;
                    p = skip_space_and_comments(p, &line, &col);
                    if (*p != '"') { p = saved; line = sline; col = scol; break; }
                    char fname[64];
                    if (!parse_string_lit(&p, fname, sizeof(fname), &col)) break;
                    td->field_count++;
                    td->field_names = (char **)realloc(td->field_names, sizeof(char *) * td->field_count);
                    td->field_names[td->field_count - 1] = strdup(fname);
                }
            } else if (strcmp(dir, ".function") == 0) {
                p = skip_space_and_comments(p, &line, &col);
                char fname[64];
                if (!parse_string_lit(&p, fname, sizeof(fname), &col)) {
                    report_asm_err(err_msg, err_cap, line, col, "Expected function name in .function");
                    kvm_bytecode_destroy(NULL, bc); return KVM_ERR_CORRUPT_BYTECODE;
                }
                int arity = 0, regs = 8;
                /* Parse arity=N regs=M if present */
                p = skip_space_and_comments(p, &line, &col);
                if (strncmp(p, "arity=", 6) == 0) {
                    p += 6; col += 6;
                    parse_int(&p, &arity, &col);
                }
                p = skip_space_and_comments(p, &line, &col);
                if (strncmp(p, "regs=", 5) == 0) {
                    p += 5; col += 5;
                    parse_int(&p, &regs, &col);
                }

                cur_fn = kvm_function_create(fname, (uint16_t)arity, (uint16_t)regs);
                bc->func_count++;
                bc->functions = (KvmFunction **)realloc(bc->functions, sizeof(KvmFunction *) * bc->func_count);
                bc->functions[bc->func_count - 1] = cur_fn;

                num_labels = 0;
                num_refs = 0;
            } else if (strcmp(dir, ".const_int") == 0) {
                if (!cur_fn) { report_asm_err(err_msg, err_cap, line, col, ".const_int outside function"); kvm_bytecode_destroy(NULL, bc); return KVM_ERR_CORRUPT_BYTECODE; }
                p = skip_space_and_comments(p, &line, &col);
                int num = 0;
                parse_int(&p, &num, &col);
                cur_fn->const_count++;
                cur_fn->const_pool = (Value *)realloc(cur_fn->const_pool, sizeof(Value) * cur_fn->const_count);
                cur_fn->const_pool[cur_fn->const_count - 1] = kvm_val_int48(num);
            } else if (strcmp(dir, ".const_str") == 0) {
                if (!cur_fn) { report_asm_err(err_msg, err_cap, line, col, ".const_str outside function"); kvm_bytecode_destroy(NULL, bc); return KVM_ERR_CORRUPT_BYTECODE; }
                p = skip_space_and_comments(p, &line, &col);
                char str_val[256];
                parse_string_lit(&p, str_val, sizeof(str_val), &col);
                cur_fn->const_count++;
                cur_fn->const_pool = (Value *)realloc(cur_fn->const_pool, sizeof(Value) * cur_fn->const_count);
                KvmString *ks = kvm_string_create(NULL, str_val, strlen(str_val));
                cur_fn->const_pool[cur_fn->const_count - 1] = kvm_val_heap_obj(ks);
            } else if (strcmp(dir, ".end") == 0) {
                if (cur_fn) {
                    /* Resolve label references */
                    for (int r = 0; r < num_refs; r++) {
                        int target_pc = -1;
                        for (int l = 0; l < num_labels; l++) {
                            if (strcmp(label_refs[r].name, labels[l].name) == 0) {
                                target_pc = labels[l].pc;
                                break;
                            }
                        }
                        if (target_pc < 0) {
                            report_asm_err(err_msg, err_cap, label_refs[r].line, label_refs[r].col, "Undefined label reference");
                            kvm_bytecode_destroy(NULL, bc); return KVM_ERR_CORRUPT_BYTECODE;
                        }
                        int inst_idx = label_refs[r].instruction_index;
                        int offset = target_pc - (inst_idx + 1);
                        KvmInstruction old_inst = cur_fn->code[inst_idx];
                        uint8_t op = KVM_OPCODE(old_inst);
                        uint8_t ra = KVM_REG_A(old_inst);
                        uint8_t rb = KVM_REG_B(old_inst);
                        cur_fn->code[inst_idx] = (op == OP_JMP || op == OP_JMPIF || op == OP_JMPIFNOT) ?
                            KVM_ENCODE_ABSI(op, ra, offset) : KVM_ENCODE_ABC(op, ra, rb, (uint8_t)offset);
                    }
                    cur_fn = NULL;
                }
            }
            continue;
        }

        /* Label definition: @name: */
        if (*p == '@') {
            p++; col++;
            char lname[64]; int li = 0;
            while (*p && (isalnum((unsigned char)*p) || *p == '_') && li < 63) {
                lname[li++] = *p++; col++;
            }
            lname[li] = '\0';
            p = skip_space_and_comments(p, &line, &col);
            if (*p == ':') { p++; col++; }
            if (cur_fn) {
                strcpy(labels[num_labels].name, lname);
                labels[num_labels].pc = (int)cur_fn->code_count;
                num_labels++;
            }
            continue;
        }

        /* Parse Opcode Token */
        char op_token[64]; int opi = 0;
        while (*p && (isalnum((unsigned char)*p) || *p == '_') && opi < 63) {
            op_token[opi++] = *p++; col++;
        }
        op_token[opi] = '\0';

        KvmOpcode opcode = OP_MAX_OPCODE;
        for (int o = 1; o < OP_MAX_OPCODE; o++) {
            if (strcmp(op_token, kvm_opcode_name((KvmOpcode)o)) == 0) {
                opcode = (KvmOpcode)o;
                break;
            }
        }

        if (opcode == OP_MAX_OPCODE) {
            report_asm_err(err_msg, err_cap, line, col, "Unknown instruction opcode");
            kvm_bytecode_destroy(NULL, bc); return KVM_ERR_CORRUPT_BYTECODE;
        }

        if (!cur_fn) {
            report_asm_err(err_msg, err_cap, line, col, "Instruction outside function definition");
            kvm_bytecode_destroy(NULL, bc); return KVM_ERR_CORRUPT_BYTECODE;
        }

        /* Operand parsing */
        uint8_t ra = 0, rb = 0, rc = 0;
        int imm = 0;
        bool has_label_operand = false;
        char ref_label_name[64] = "";

        /* Parse operands based on opcode format */
        p = skip_space_and_comments(p, &line, &col);

        if (opcode == OP_LOADI || opcode == OP_LOADK) {
            parse_reg(&p, &ra, &col);
            p = skip_space_and_comments(p, &line, &col);
            if (*p == ',') { p++; col++; }
            p = skip_space_and_comments(p, &line, &col);
            parse_int(&p, &imm, &col);
        } else if (opcode == OP_JMP) {
            if (*p == '@') {
                p++; col++;
                int li = 0;
                while (*p && (isalnum((unsigned char)*p) || *p == '_') && li < 63) {
                    ref_label_name[li++] = *p++; col++;
                }
                ref_label_name[li] = '\0';
                has_label_operand = true;
            } else {
                parse_int(&p, &imm, &col);
            }
        } else if (opcode == OP_JMPIF || opcode == OP_JMPIFNOT) {
            parse_reg(&p, &ra, &col);
            p = skip_space_and_comments(p, &line, &col);
            if (*p == ',') { p++; col++; }
            p = skip_space_and_comments(p, &line, &col);
            if (*p == '@') {
                p++; col++;
                int li = 0;
                while (*p && (isalnum((unsigned char)*p) || *p == '_') && li < 63) {
                    ref_label_name[li++] = *p++; col++;
                }
                ref_label_name[li] = '\0';
                has_label_operand = true;
            } else {
                parse_int(&p, &imm, &col);
            }
        } else if (opcode == OP_JLT || opcode == OP_JLE || opcode == OP_JEQ ||
                   opcode == OP_JNLT || opcode == OP_JNLE || opcode == OP_JNEQ) {
            parse_reg(&p, &ra, &col);
            p = skip_space_and_comments(p, &line, &col);
            if (*p == ',') { p++; col++; }
            p = skip_space_and_comments(p, &line, &col);
            parse_reg(&p, &rb, &col);
            p = skip_space_and_comments(p, &line, &col);
            if (*p == ',') { p++; col++; }
            p = skip_space_and_comments(p, &line, &col);
            if (*p == '@') {
                p++; col++;
                int li = 0;
                while (*p && (isalnum((unsigned char)*p) || *p == '_') && li < 63) {
                    ref_label_name[li++] = *p++; col++;
                }
                ref_label_name[li] = '\0';
                has_label_operand = true;
            } else {
                parse_int(&p, &imm, &col);
            }
        } else if (opcode == OP_RETURN) {
            if (*p == 'r' || *p == 'R') {
                parse_reg(&p, &ra, &col);
                rb = 1;
            } else {
                ra = 0; rb = 0;
            }
        } else if (opcode == OP_DROP || opcode == OP_LOADNIL || opcode == OP_ENDBORROW) {
            parse_reg(&p, &ra, &col);
        } else {
            /* Generic 2 or 3 reg operands */
            parse_reg(&p, &ra, &col);
            p = skip_space_and_comments(p, &line, &col);
            if (*p == ',') { p++; col++; }
            p = skip_space_and_comments(p, &line, &col);
            if (*p == 'r' || *p == 'R') {
                parse_reg(&p, &rb, &col);
                p = skip_space_and_comments(p, &line, &col);
                if (*p == ',') { p++; col++; }
                p = skip_space_and_comments(p, &line, &col);
                if (*p == 'r' || *p == 'R') {
                    parse_reg(&p, &rc, &col);
                } else if (isdigit((unsigned char)*p) || *p == '-') {
                    parse_int(&p, &imm, &col);
                    rc = (uint8_t)imm;
                }
            } else if (isdigit((unsigned char)*p) || *p == '-') {
                parse_int(&p, &imm, &col);
                rb = (uint8_t)imm;
            }
        }

        KvmInstruction inst;
        if (has_label_operand) {
            label_refs[num_refs].instruction_index = (int)cur_fn->code_count;
            label_refs[num_refs].line = line;
            label_refs[num_refs].col = col;
            strcpy(label_refs[num_refs].name, ref_label_name);
            num_refs++;
            inst = KVM_ENCODE_ABSI(opcode, ra, 0);
        } else if (opcode == OP_LOADI || opcode == OP_LOADK || opcode == OP_JMP || opcode == OP_JMPIF || opcode == OP_JMPIFNOT) {
            inst = KVM_ENCODE_ABSI(opcode, ra, imm);
        } else {
            inst = KVM_ENCODE_ABC(opcode, ra, rb, rc);
        }

        cur_fn->code_count++;
        cur_fn->code = (KvmInstruction *)realloc(cur_fn->code, sizeof(KvmInstruction) * cur_fn->code_count);
        cur_fn->code[cur_fn->code_count - 1] = inst;

        if (opcode == OP_LOOPHINT) {
            cur_fn->loop_count++;
        }
    }

    /* Initialize loop counters array for functions */
    for (size_t f = 0; f < bc->func_count; f++) {
        if (bc->functions[f]->loop_count > 0) {
            bc->functions[f]->loop_counters = (uint32_t *)calloc(bc->functions[f]->loop_count, sizeof(uint32_t));
        }
    }

    *out_bc = bc;
    return KVM_OK;
}
