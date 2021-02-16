[BITS 32]
imul ecx
imul dword [ecx]
imul dword [byte ecx + 4]
imul dword [dword ecx + 4]
imul esi, dword [ecx]
imul esi, dword [0x44556677]
imul dword [0x11223344]
imul edx, [0x55667788], 0x11223344
imul edx, [edi], 0x11223344
imul edx, dword [byte edi + 0x04], 0x11223344
imul edx, dword [dword edi + 0x55667788], 0x11223344
imul edx, eax, 0x11223344