#ifndef STACK_CALL_H
#define STACK_CALL_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_SIZEOF_INSTRUCTION 16

typedef enum t_call {
    __cdecl_call,
    __fastcall_call,
    __msfcall_call,
    __stdcall_call,
    __thiscall_call
} t_call;

typedef enum t_data_arg {
    // para tipos de dato puntero:
    arg_ptr,

    // para tipos de datos de 8, 16, 32 o 64bits, con o sin signo:
    arg_int8,
    arg_int16,
    arg_int32,
    arg_int64,
    mov_inst,
    #define MOV(arg_size, name) mov_inst << 24 | arg_size << 16 | name << 8
    call_func
    #define CALL(addr_func) call_func << 24, addr_func
} t_data_arg;



typedef enum BITS_REG_8bits {
    reg_al_bits,
    reg_cl_bits,
    reg_dl_bits,
    reg_bl_bits,
    reg_ah_bits,
    reg_ch_bits,
    reg_dh_bits,
    reg_bh_bits,
} BITS_REG_8bits;

typedef enum BITS_REG_16bits {
    reg_ax_bits = reg_bh_bits + 1,
    reg_cx_bits,
    reg_dx_bits,
    reg_bx_bits,
    reg_sp_bits,
    reg_bp_bits,
    reg_si_bits,
    reg_di_bits,
} BITS_REG_16bits;

typedef enum BITS_REG_32bits {
    reg_eax_bits = reg_bh_bits + 1,
    reg_ecx_bits,
    reg_edx_bits,
    reg_ebx_bits,
    reg_esp_bits,
    reg_ebp_bits,
    reg_esi_bits,
    reg_edi_bits,
} BITS_REG_32bits;

#define REX_WB 0x49
#define REX_W  0x48
/**
 * prefijos 0100 WR0B:
 * 0x49 == REX.WB
 * 0x48 == REX.W:
 *          Indica el uso de un prefijo REX que afecta el tamaño del 
 *          operando o la semántica de la instrucción. El orden del 
 *          prefijo REX y otros prefijos de instrucción 
 *          opcionales/obligatorios se describe en el Capítulo 2. 
 *          Tenga en cuenta que los prefijos REX que promueven el 
 *          funcionamiento de las instrucciones heredadas a 64 bits 
 *          no se enumeran explícitamente en la columna de código de 
 *          operación.
 * 
 * Field Name   Bit Position    Definition
 *  -               7:4            0100
 *  W               3               0 = Operand size determined by CS.D
 *                                  1 = 64 Bit Operand Size
 *  R               2               Extension of the ModR/M reg field
 *  X               1               Extension of the SIB index field
 *  B               0               Extension of the ModR/M r/m field, SIB 
 *                                      base field, or Opcode reg field
 * 
 * 
 */
typedef struct PREFIX_REX {
    uint8_t const_field:4; // 0100 
    uint8_t bit_w:1;    /* 0 = Operand size determined by CS.D
                         * 1 = 64 Bit Operand Size
                         */
    uint8_t bit_r:1;    // Extension of the ModR/M reg field
    uint8_t bit_x:1;    // Extension of the SIB index field
    uint8_t bit_b:1;    /* Extension of the ModR/M r/m field, 
                         * SIB base field, or Opcode reg field
                         */
} PREFIX_REX;

typedef enum BITS_REG_64bits {
    reg_rax_bits = 8, // 0x0
    reg_rcx_bits,
    reg_rdx_bits,
    reg_rbx_bits,
    reg_rsp_bits,
    reg_rbp_bits,
    reg_rsi_bits,
    reg_rdi_bits,
    reg_r08_bits = reg_rax_bits,
    reg_r09_bits,
    reg_r10_bits,
    reg_r11_bits,
    reg_r12_bits,
    reg_r13_bits,
    reg_r14_bits,
    reg_r15_bits, // 0xf
} BITS_REG_64bits;

typedef struct instruction_emmit_asm {
    uint8_t *instruction;
    uint8_t sizeof_instruction;
    union prefix
    {
        PREFIX_REX field;
        uint8_t byte;
    } prefix;
    
    
} instruction_emmit_asm;

static inline void emmit_mov_reg8_inmed8(
    instruction_emmit_asm *emmit_asm, 
    BITS_REG_8bits reg, 
    uint8_t va
) {
    emmit_asm->sizeof_instruction = 2;
    emmit_asm->instruction[0] = 0xb0 | reg;
    emmit_asm->instruction[1] = va;
}

static inline void emmit_mov_reg16_inmed16_for_64bits(
    instruction_emmit_asm *emmit_asm, 
    BITS_REG_16bits reg, 
    uint16_t va
) {
    emmit_asm->sizeof_instruction = 4;
    // prefijo de cambio de modo a 16bits:
    emmit_asm->instruction[0] = 0x66;
    emmit_asm->instruction[1] = 0xb0 | reg;
    *(uint16_t*)(emmit_asm->instruction + 2) = va;
}

static inline void emmit_mov_reg32_inmed32(
    instruction_emmit_asm *emmit_asm, 
    BITS_REG_32bits reg, 
    uint32_t va
) {
    emmit_asm->sizeof_instruction = 5;
    emmit_asm->instruction[0] = 0xb0 | reg;
    *(uint32_t*)(emmit_asm->instruction + 1) = va;
}

static inline void emmit_mov_reg64_inmed64(
    instruction_emmit_asm *emmit_asm, 
    BITS_REG_64bits reg, 
    uint64_t va
) {
    emmit_asm->sizeof_instruction = 10;
    emmit_asm->instruction[0] = emmit_asm->prefix.byte;
    emmit_asm->instruction[1] = 0xb0 | reg;
    *(uint64_t*)(emmit_asm->instruction + 2) = va;
}

static inline void emmit_mov_reg64_inmed32(
    instruction_emmit_asm *emmit_asm, 
    BITS_REG_64bits reg, 
    uint32_t va
) {
    emmit_asm->sizeof_instruction = 7;
    emmit_asm->instruction[0] = emmit_asm->prefix.byte;
    emmit_asm->instruction[1] = 0xc7;
    emmit_asm->instruction[2] = 0xc0 | ((reg >= reg_r08_bits) ? reg - reg_r08_bits : reg);
    *(uint32_t*)(emmit_asm->instruction + 3) = va;
}

#define JMP_RAX 0xd0ff

/*
 * 55          push rbp
 * 48 89 E5    mov  rbp, rsp
 * 48 89 EC    mov rsp, rbp
 * 5D          pop rbp
 * C3          ret 
 */
#define PUSH_RBP 0x55
#define POP_RBP 0x5D
#define RET 0xc3

void print_instruction_emmit_asm(instruction_emmit_asm *instruction_info);

#endif