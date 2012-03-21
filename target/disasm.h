#ifndef __DISASM_H__
#define __DISASM_H__

#include "common.h"

typedef enum {
    INST_NONE    = 0,
    INST_RET,
    INST_CALL,
    INST_SYSCALL,
    INST_SYSRET,
    INST_INT,
    INST_JMP,
    INST_JCC,
    INST_CMOV,
} inst_type_t;

typedef enum {
    INST_CF_NONE    = 0,
    INST_CF_RET     = 1 << INST_RET,
    INST_CF_CALL    = 1 << INST_CALL,
    INST_CF_SYSCALL = 1 << INST_SYSCALL,
    INST_CF_SYSRET  = 1 << INST_SYSRET,
    INST_CF_INT     = 1 << INST_INT,
    INST_CF_JMP     = 1 << INST_JMP,
    INST_CF_JCC     = 1 << INST_JCC,
    INST_CF_CMOV    = 1 << INST_CMOV,
} inst_cf_flags_t;

#define INST_TO_CF_FLAG(inst) (1 << (inst))

/* These are exactly equivalent to the distorm ones for now! */
typedef enum {
    RG_RAX,RG_RCX,RG_RDX,RG_RBX,RG_RSP,RG_RBP,RG_RSI,RG_RDI, 
    RG_R8,RG_R9,RG_R10,RG_R11,RG_R12,RG_R13,RG_R14,RG_R15,
    RG_EAX,RG_ECX,RG_EDX,RG_EBX,RG_ESP,RG_EBP,RG_ESI,RG_EDI, 
    RG_R8D,RG_R9D,RG_R10D,RG_R11D,RG_R12D,RG_R13D,RG_R14D,RG_R15D,
    RG_AX,RG_CX,RG_DX,RG_BX,RG_SP,RG_BP,RG_SI,RG_DI, 
    RG_R8W,RG_R9W,RG_R10W,RG_R11W,RG_R12W,RG_R13W,RG_R14W,RG_R15W,
    RG_AL,RG_CL,RG_DL,RG_BL,RG_AH,RG_CH,RG_DH,RG_BH, 
    RG_R8B,RG_R9B,RG_R10B,RG_R11B,RG_R12B,RG_R13B,RG_R14B,RG_R15B,
    RG_SPL,RG_BPL,RG_SIL,RG_DIL,
    RG_ES,RG_CS,RG_SS,RG_DS,RG_FS,RG_GS,
    RG_RIP,
    RG_ST0,RG_ST1,RG_ST2,RG_ST3,RG_ST4,RG_ST5,RG_ST6,RG_ST7,
    RG_MM0,RG_MM1,RG_MM2,RG_MM3,RG_MM4,RG_MM5,RG_MM6,RG_MM7,
    RG_XMM0,RG_XMM1,RG_XMM2,RG_XMM3,RG_XMM4,RG_XMM5,RG_XMM6,RG_XMM7, 
    RG_XMM8,RG_XMM9,RG_XMM10,RG_XMM11,RG_XMM12,RG_XMM13,RG_XMM14,RG_XMM15,
    RG_YMM0,RG_YMM1,RG_YMM2,RG_YMM3,RG_YMM4,RG_YMM5,RG_YMM6,RG_YMM7, 
    RG_YMM8,RG_YMM9,RG_YMM10,RG_YMM11,RG_YMM12,RG_YMM13,RG_YMM14,RG_YMM15,
    RG_CR0,RG_UNUSED0,RG_CR2,RG_CR3,RG_CR4,
    RG_UNUSED1,RG_UNUSED2,RG_UNUSED3,RG_CR8,
    RG_DR0,RG_DR1,RG_DR2,RG_DR3,RG_UNUSED4,RG_UNUSED5,RG_DR6,RG_DR7
} reg_type_t;

struct inst_cf_data {
    inst_type_t type;
    int target_is_indirect:1,
        target_is_offset:1,
        target_is_reg:1;
    OFFSET offset;
    union {
	reg_type_t target_reg;
	OFFSET target_offset;
	ADDR target_addr;
    };
};

#endif /* __DISASM_H__ */
