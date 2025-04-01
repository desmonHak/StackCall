#ifndef STACK_CALL_C
#define STACK_CALL_C

#include "StackCall.h"

/**
 * @brief array de emision de codigo
 * 
 * 2.2.1.5 Operandos inmediatos
 * En el modo de 64 bits, el tamaño típico de los operandos inmediatos se 
 * mantiene en 32 bits. Cuando el tamaño del operando es de 64 bits, el 
 * procesador extiende el signo de todos los operandos inmediatos a 64 bits 
 * antes de su uso.
 * La compatibilidad con operandos inmediatos de 64 bits se logra ampliando 
 * la semántica de las instrucciones de movimiento existentes 
 * (MOV reg, imm16/32). Estas instrucciones (códigos de operación B8H - BFH) 
 * mueven 16 o 32 bits de datos inmediatos (según el tamaño efectivo del 
 * operando) a un GPR. Cuando el tamaño efectivo del operando es de 64 bits, 
 * estas instrucciones pueden utilizarse para cargar un operando inmediato 
 * en un GPR. Se necesita un prefijo REX para sobrescribir el tamaño 
 * predeterminado de operando de 32 bits a un tamaño de operando de 64 bits.
 * Por ejemplo:
 *      48 B8 8877665544332211 MOV RAX,1122334455667788H
 */

 const char __fastcall_call_emmit_asm[] = {
    // immediate to register (alternate encoding) :
    // 0100 000B : 1011 w reg : imm

    /** 0x49, 0xb8 - 0xbf  -> movabs r8/r15, val64bits: */
    0x49, 0xb9, 0x67, 0x45, 0x23, 0x91, 0x78, 0x56, 0x34, 0x12, // mov r9, 0x1234567891234567
    0x49, 0xb8, 0x67, 0x45, 0x23, 0x91, 0x78, 0x56, 0x34, 0x12, // mov r8, 0x1234567891234567

    /** 0x48, 0xb8 - 0xbf  -> movabs rax/rcx/rdx/rbx/rsp/rbp/rsi/rdi, val64bits: */
    0x48, 0xb9, 0x67, 0x45, 0x23, 0x91, 0x78, 0x56, 0x34, 0x12, // mov rcx, 0x1234567891234567
    0x48, 0xba, 0x67, 0x45, 0x23, 0x91, 0x78, 0x56, 0x34, 0x12, // mov rdx, 0x1234567891234567

    /** 0x48, 0xc7, 0xc0 - 0xc7  -> mov rax/rcx/rdx/rbx/rsp/rbp/rsi/rdi, val32bits: */
    0x48, 0xc7, 0xc1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1
    0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00, // mov rdx, 1

    /** 0x49, 0xc7, 0xc0 - 0xc7  -> mov r8/r15, val32bits: */
    0x49, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov r8, 1
    0x49, 0xc7, 0xc1, 0x01, 0x00, 0x00, 0x00, // mov r9, 1

    /*
     * mov reg32/8, inmed32
     * immediate to register 1100 011w : 11 000 reg : immediate data
     * immediate to register (alternate encoding) 1011 w reg : immediate data 
     * 
     * (0xb8) 1011 1000 -> W = 1, REG = 000
     * b8 0c 00 00 00  -> mov eax, 0xC
     * 
     * --------------- CAMPO REG: ------------------
     * Cuando el modo de operacion es de 16bits, es 
     * necesario usar el prefijo 0x66 para eso
     * reg      when w = 0      when w = 1 
     * 000          AL              AX
     * 001          CL              CX
     * 010          DL              DX
     * 011          BL              BX
     * 100          AH              SP
     * 101          CH              BP
     * 110          DH              SI
     * 111          BH              DI
     * 
     * Cuando el modo de operacion es de 32bits(por defecto en 32 y 64bits)
     * reg      when w = 0      when w = 1 
     * 000          AL              EAX
     * 001          CL              ECX
     * 010          DL              EDX
     * 011          BL              EBX
     * 100          AH              ESP
     * 101          CH              EBP
     * 110          DH              ESI
     * 111          BH              EDI
     * 
     */

};

void print_instruction_emmit_asm(instruction_emmit_asm *instruction_info) {
    //printf("sizeof instruction: %d\n", instruction_info->sizeof_instruction);
    for (uint8_t i = 0; i < instruction_info->sizeof_instruction; i++ ) {
        printf("%02x ", instruction_info->instruction[i]);
    }
    printf("\n");
}

uint8_t resolve_reg(uint8_t arg_size, char name) {
    switch (arg_size)
    {
    case arg_int8:  return name -1;
    case arg_int16: return name -1 + 8;
    case arg_int32: return name -1 + 8;   
    case arg_int64: return name -1;
    default:
        puts("Error");
        return 0;
    }
}

void create_shellcode(
    size_t* pseucode_asm, 
    size_t sizeof_pseucode_asm, 
    void*code, 
    size_t sizeof_code
) {
    
    size_t counter = 0;


    uint8_t SAVE_STACK_POINTER[] = {
        PUSH_RBP,
        0x48, 0x89, 0xE5
    };
    //memcpy(code + counter, SAVE_STACK_POINTER, sizeof(SAVE_STACK_POINTER));
    //counter += sizeof(SAVE_STACK_POINTER);

    for (size_t i = 0; i < sizeof_pseucode_asm; i++) {
 
        uint8_t code_instruction[MAX_SIZEOF_INSTRUCTION] = { 0 };
        instruction_emmit_asm instruction_info = { 
            .prefix.field.const_field = 0100,
            .instruction = code_instruction
        };
        uint8_t instruction = ( pseucode_asm[i] >> 24 ) & 0xff;

        uint8_t arg_size;
        uint8_t name;
        switch (instruction)
        {
        case mov_inst:
            // arg_size << 16 | name << 8
            arg_size = ( pseucode_asm[i] >> 16 ) & 0xff;
            name = resolve_reg(arg_size, ( pseucode_asm[i] >> 8 ) & 0xff);
            i++;
            size_t  val = pseucode_asm[i];
            switch (arg_size)
            {
            case arg_int8:
                    emmit_mov_reg8_inmed8(&instruction_info, name, val);
                break;
                case arg_int16:
                    emmit_mov_reg16_inmed16_for_64bits(&instruction_info, name, val);
                    break;
                case arg_int32:
                    emmit_mov_reg32_inmed32(&instruction_info, name, val);
                    break;
                case arg_int64:
                    if ( name >= 8 ) { // registros r Numero
                        instruction_info.prefix.byte = REX_WB;
                        name++;
                    } else { // rax, rbx, ....
                        instruction_info.prefix.byte = REX_W;
                        name += 8;
                    }
                    emmit_mov_reg64_inmed32(&instruction_info, name, val);
                    break;
            default:
                break;
            }
            memcpy(code + counter, instruction_info.instruction, instruction_info.sizeof_instruction);
            counter += instruction_info.sizeof_instruction;
            print_instruction_emmit_asm(&instruction_info);

            break;
        case call_func:
            i++;
        
            size_t  addr = pseucode_asm[i];
            instruction_info.prefix.byte = REX_W;
            emmit_mov_reg64_inmed64(&instruction_info, reg_rax_bits, addr);
            memcpy(code + counter, instruction_info.instruction, instruction_info.sizeof_instruction);
                    counter += instruction_info.sizeof_instruction;
            print_instruction_emmit_asm(&instruction_info);


            uint8_t cde_final[] = {
                0xff, 0xe0, // call rax
                //0x48, 0x89, 0xEC,
                //POP_RBP,
                RET
            };
            memcpy(code + counter, cde_final, sizeof(cde_final));
            counter += sizeof(cde_final);
            /**((uint16_t*)(code + counter)) = JMP_RAX;
            counter+=2;


            *((uint8_t*)(code + counter)) = POP_RBP;
            counter+=1;

            *((uint8_t*)(code + counter)) = RET;
            counter+=1;*/
            printf("%x\n Call addr %p\n", JMP_RAX, addr);
            break;
        default:
            puts("Error");
            break;
        }
    }
    for (; counter < sizeof_code; counter++) {
        ((uint8_t*)code)[counter] = 0x90;
    }
}

#endif