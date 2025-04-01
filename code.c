#include <stdio.h>
#include <windows.h>

#include "./StackCall.h"


void PrintLastErrorInfo() {
    LPVOID lpMsgBuf;
    DWORD dwLastError = GetLastError();

    DWORD dwFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS;

    DWORD dwLanguageId = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);

    DWORD dwResult = FormatMessage(dwFlags, NULL, dwLastError, dwLanguageId,
                                   (LPTSTR)&lpMsgBuf, 0, NULL);

    if (dwResult != 0) {
        printf("Error code: %lu\n", dwLastError);
        printf("Error message: %s\n", (LPCTSTR)lpMsgBuf);
        
        // Libera el búfer de mensajes
        LocalFree(lpMsgBuf);
    } else {
        fprintf(stderr, "Error al obtener informacion sobre el ultimo error.\n");
    }
}

int suma(int n1, int n2) {
    return n1 + n2;
}

int main() {



    uint8_t code_instruction[MAX_SIZEOF_INSTRUCTION] = { 0 };
    instruction_emmit_asm instruction_info = { 
        .prefix.field.const_field = 0100,
        .instruction = code_instruction
    };
    emmit_mov_reg8_inmed8(&instruction_info, reg_al_bits, 0xff);
    print_instruction_emmit_asm(&instruction_info);

    emmit_mov_reg8_inmed8(&instruction_info, reg_bh_bits, 0xff);
    print_instruction_emmit_asm(&instruction_info);

    emmit_mov_reg16_inmed16_for_64bits(&instruction_info, reg_ax_bits, 0x1234);
    print_instruction_emmit_asm(&instruction_info);

    emmit_mov_reg16_inmed16_for_64bits(&instruction_info, reg_di_bits, 0x1234);
    print_instruction_emmit_asm(&instruction_info);

    emmit_mov_reg32_inmed32(&instruction_info, reg_eax_bits, 0x1234abcd);
    print_instruction_emmit_asm(&instruction_info);

    emmit_mov_reg32_inmed32(&instruction_info, reg_edi_bits, 0x1234abcd);
    print_instruction_emmit_asm(&instruction_info);

    instruction_info.prefix.byte = REX_W;
    emmit_mov_reg64_inmed32(&instruction_info, reg_rax_bits, 0x1234abcd);
    print_instruction_emmit_asm(&instruction_info);

    instruction_info.prefix.byte = REX_W;
    emmit_mov_reg64_inmed32(&instruction_info, reg_rdi_bits, 0x1234abcd);
    print_instruction_emmit_asm(&instruction_info);

    instruction_info.prefix.byte = REX_WB;
    emmit_mov_reg64_inmed32(&instruction_info, reg_r15_bits, 0x1234abcd);
    print_instruction_emmit_asm(&instruction_info);

    instruction_info.prefix.byte = REX_W;
    emmit_mov_reg64_inmed64(&instruction_info, reg_rax_bits, 0x1234abcd1234abcd);
    print_instruction_emmit_asm(&instruction_info);

    instruction_info.prefix.byte = REX_W;
    emmit_mov_reg64_inmed64(&instruction_info, reg_rdi_bits, 0x1234abcd1234abcd);
    print_instruction_emmit_asm(&instruction_info);

    instruction_info.prefix.byte = REX_WB;
    emmit_mov_reg64_inmed64(&instruction_info, reg_r15_bits, 0x1234abcd1234abcd);
    print_instruction_emmit_asm(&instruction_info);

    printf("%p\n", suma);

    static size_t pseucode_asm[] = {
        MOV(arg_int64, 2), 0x12,
        MOV(arg_int64, 3), 0x12,
        CALL(suma)
    };

    static uint8_t code[0x80] =   { 0 };

    create_shellcode(
        pseucode_asm, 
        sizeof(pseucode_asm)/sizeof(size_t), 
        code, sizeof(code)
    );

    for (uint8_t i = 0; i < sizeof(code); i++ ) {
        printf("%02x ", code[i]);
    }

    PVOID exec = VirtualAlloc(0, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (exec == NULL) puts("VirtualAlloc error");
    printf("\nptr VirtualAlloc: 0x%p\n", exec);

    memcpy(exec, code, sizeof code); // copiar el shellcode a la nueva memoria reservada
	int n = ((int(*)())exec)(); // ejecuta el shellcode
    printf("Suma %x\n", n);
    PrintLastErrorInfo();

    if(!VirtualFree(exec, 0, MEM_RELEASE)){// liberar memoria
        // si el valor es 0 == false, a ocurrio un error
        PrintLastErrorInfo();
        return EXIT_FAILURE;
    } 
    puts("Succes");


    return 0;
}